package domains

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	osuser "os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/openpropanel/openpropanel/internal/deploy"
	"github.com/openpropanel/openpropanel/internal/store"
)

// tenantIDs resolves a project owner's Linux system user to uid/gid. Repo-backed
// projects REQUIRE a dedicated (non-root) tenant user, because git runs as that
// user — never root — so a tenant-owned checkout cannot use git hooks or
// core.sshCommand to execute as root.
func (s *Service) tenantIDs(ownerID int64) (uint32, uint32, error) {
	owner, err := s.store.UserByID(ownerID)
	if err != nil {
		return 0, 0, errors.New("project owner not found")
	}
	if owner.SystemUser == "" {
		return 0, 0, errors.New("this account has no system user — assign one under Users before deploying from GitHub (git must not run as root)")
	}
	u, err := osuser.Lookup(owner.SystemUser)
	if err != nil {
		return 0, 0, fmt.Errorf("system user %q not found: %w", owner.SystemUser, err)
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	if uid == 0 || gid == 0 {
		return 0, 0, errors.New("refusing to run git as root (uid/gid 0)")
	}
	return uint32(uid), uint32(gid), nil
}

// LinkRepo attaches a GitHub repository to a project (its main site): it
// validates the URL, auto-selects the auth mode (public HTTPS, else a per-repo
// deploy key), generates the key, and records the repo. The returned repo has
// PublicKey/KeyFingerprint set when a key was generated (to paste into GitHub).
func (s *Service) LinkRepo(ctx context.Context, projectSiteID int64, rawURL, branch string) (*store.Repo, error) {
	site, err := s.store.SiteByID(projectSiteID)
	if err != nil {
		return nil, err
	}
	if site.Type != store.SiteMain {
		return nil, errors.New("link the repository to the project's main domain")
	}
	if site.Source != store.SourceManaged {
		return nil, errImportedReadOnly
	}
	if _, err := s.store.RepoByProject(projectSiteID); err == nil {
		return nil, errors.New("this project already has a repository linked")
	}
	if _, _, err := s.tenantIDs(site.UserID); err != nil {
		return nil, err // must have a tenant user before we clone anything
	}

	owner, name, err := deploy.ParseGitHubURL(rawURL)
	if err != nil {
		return nil, err
	}
	branch = strings.TrimSpace(branch)
	if branch == "" {
		branch = "main"
	}
	if !deploy.ValidBranch(branch) {
		return nil, errors.New("invalid branch name")
	}

	authMode := deploy.AuthDeployKey
	if s.deploy.IsPublic(ctx, owner, name) {
		authMode = deploy.AuthPublic
	}

	repo := &store.Repo{
		ProjectSiteID: projectSiteID,
		Provider:      "github",
		Owner:         owner,
		Name:          name,
		URL:           deploy.HTTPSURL(owner, name),
		AuthMode:      authMode,
		Branch:        branch,
		CheckoutDir:   filepath.Join(s.cfg.WebRoot, site.Domain, "repo"),
		LastStatus:    "linked",
	}
	created, err := s.store.CreateRepo(repo)
	if err != nil {
		return nil, err
	}
	if authMode != deploy.AuthPublic {
		pub, fp, kerr := s.deploy.GenerateKey(created.ID)
		if kerr != nil {
			_ = s.store.DeleteRepo(created.ID)
			return nil, fmt.Errorf("generate deploy key: %w", kerr)
		}
		created.PublicKey, created.KeyFingerprint = pub, fp
		_ = s.store.SetRepoKey(created.ID, pub, fp)
	}
	return created, nil
}

// VerifyRepo tests connectivity/authorisation (git ls-remote) as the tenant.
func (s *Service) VerifyRepo(ctx context.Context, repoID int64) error {
	repo, err := s.store.RepoByID(repoID)
	if err != nil {
		return err
	}
	uid, gid, err := s.projectTenant(repo.ProjectSiteID)
	if err != nil {
		return err
	}
	return s.deploy.Verify(ctx, repo, uid, gid)
}

// CloneRepo performs the initial checkout into the project's repo directory.
func (s *Service) CloneRepo(ctx context.Context, repoID int64) error {
	s.deployMu.Lock()
	defer s.deployMu.Unlock()
	repo, err := s.store.RepoByID(repoID)
	if err != nil {
		return err
	}
	uid, gid, err := s.projectTenant(repo.ProjectSiteID)
	if err != nil {
		return err
	}
	if err := s.deploy.Clone(ctx, repo, uid, gid); err != nil {
		_ = s.store.UpdateRepoDeploy(repoID, "", "error", err.Error(), time.Now())
		return err
	}
	_ = s.store.UpdateRepoDeploy(repoID, "", "ok", "", time.Now())
	return nil
}

// DeployProject fetches + hard-resets the project's checkout to the tip of its
// branch (as the tenant) and reloads the web server — refreshing every mapped
// domain at once.
func (s *Service) DeployProject(ctx context.Context, projectSiteID int64) error {
	s.deployMu.Lock()
	defer s.deployMu.Unlock()
	repo, err := s.store.RepoByProject(projectSiteID)
	if err != nil {
		return errors.New("no repository is linked to this project")
	}
	uid, gid, err := s.projectTenant(projectSiteID)
	if err != nil {
		return err
	}
	commit, derr := s.deploy.Deploy(ctx, repo, uid, gid)
	if derr != nil {
		_ = s.store.UpdateRepoDeploy(repo.ID, repo.LastCommit, "error", derr.Error(), time.Now())
		return derr
	}
	_ = s.store.UpdateRepoDeploy(repo.ID, commit, "ok", "", time.Now())
	return s.web().Reload(ctx)
}

// MapSite points a site's document root at a subfolder of its project's repo
// checkout and sets the serving mode (php|static|spa), then re-renders its vhost.
func (s *Service) MapSite(ctx context.Context, siteID int64, subdir, mode string) error {
	site, err := s.store.SiteByID(siteID)
	if err != nil {
		return err
	}
	if site.Source != store.SourceManaged {
		return errImportedReadOnly
	}
	repo, err := s.store.RepoByProject(s.projectIDFor(site))
	if err != nil {
		return errors.New("this project has no repository — link one first")
	}
	docRoot, rel, err := repoSubPath(repo.CheckoutDir, subdir)
	if err != nil {
		return err
	}
	switch mode {
	case "":
		mode = store.WebModePHP
	case store.WebModePHP, store.WebModeStatic, store.WebModeSPA:
	default:
		return errors.New("invalid serving mode")
	}
	if err := s.store.SetSiteMapping(siteID, sql.NullInt64{Int64: repo.ID, Valid: true}, rel, docRoot, mode); err != nil {
		return err
	}
	site.DocRoot, site.WebMode = docRoot, mode
	site.RepoID = sql.NullInt64{Int64: repo.ID, Valid: true}
	if err := s.renderVHost(site); err != nil {
		return err
	}
	return s.web().Apply(ctx)
}

// RepoTree lists the immediate subdirectories of rel inside a project's repo
// checkout (for the folder picker), hiding VCS/build noise.
func (s *Service) RepoTree(repoID int64, rel string) ([]string, error) {
	repo, err := s.store.RepoByID(repoID)
	if err != nil {
		return nil, err
	}
	dir, _, err := repoSubPath(repo.CheckoutDir, rel)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	skip := map[string]bool{".git": true, "node_modules": true, "vendor": true}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() && !skip[e.Name()] && !strings.HasPrefix(e.Name(), ".") {
			dirs = append(dirs, e.Name())
		}
	}
	return dirs, nil
}

// UnlinkRepo removes a project's repository link + deploy key (files on disk are
// left in place).
func (s *Service) UnlinkRepo(ctx context.Context, projectSiteID int64) error {
	repo, err := s.store.RepoByProject(projectSiteID)
	if err != nil {
		return nil
	}
	s.deploy.RemoveKey(repo.ID)
	return s.store.DeleteRepo(repo.ID)
}

func (s *Service) projectIDFor(site *store.Site) int64 {
	if site.Type == store.SiteSubdomain && site.ParentID.Valid {
		return site.ParentID.Int64
	}
	return site.ID
}

func (s *Service) projectTenant(projectSiteID int64) (uint32, uint32, error) {
	site, err := s.store.SiteByID(projectSiteID)
	if err != nil {
		return 0, 0, err
	}
	return s.tenantIDs(site.UserID)
}

// repoSubPath joins a subdir onto a checkout, returning the absolute doc root and
// the cleaned relative path, guaranteeing the result stays inside the checkout.
func repoSubPath(checkout, subdir string) (abs, rel string, err error) {
	rel = strings.TrimPrefix(filepath.Clean("/"+strings.TrimSpace(subdir)), "/")
	// The subdir is tenant-supplied and its join becomes a doc root that is
	// interpolated verbatim into the vhost the panel reloads as root; reject any
	// config metacharacter (newline, ';', '"', '{', ...) before it gets there.
	if !safeVHostPath(rel) {
		return "", "", errors.New("folder name contains characters that are not allowed")
	}
	abs = filepath.Join(checkout, filepath.FromSlash(rel))
	if !pathWithin(checkout, abs) {
		return "", "", errors.New("folder must be inside the repository")
	}
	return abs, rel, nil
}

func pathWithin(base, p string) bool {
	base = filepath.Clean(base)
	p = filepath.Clean(p)
	return p == base || strings.HasPrefix(p, base+string(os.PathSeparator))
}
