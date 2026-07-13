package domains

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	osuser "os/user"
	"path/filepath"
	"slices"
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
		return 0, 0, errors.New("this account has no system user — it is provisioned automatically when a domain is added or a repo is linked; retry, and check the panel log if this persists")
	}
	// Dev hosts have no real tenant accounts and deploy.* short-circuits before
	// any git runs, so a synthetic unprivileged uid keeps the flow testable.
	if s.cfg.Dev {
		return 1000, 1000, nil
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
// JIT-provisions the owner's system user if missing, validates the URL,
// auto-selects the auth mode (public HTTPS, else a per-repo deploy key),
// generates the key + webhook secret, and records the repo. The returned note
// is non-fatal operator advice (inconclusive public check, partial tenant
// upgrade) to surface alongside the success message.
func (s *Service) LinkRepo(ctx context.Context, projectSiteID int64, rawURL, branch string) (*store.Repo, string, error) {
	site, err := s.store.SiteByID(projectSiteID)
	if err != nil {
		return nil, "", err
	}
	if site.Type != store.SiteMain {
		return nil, "", errors.New("link the repository to the project's main domain")
	}
	if site.Source != store.SourceManaged {
		return nil, "", errImportedReadOnly
	}
	if _, err := s.store.RepoByProject(projectSiteID); err == nil {
		return nil, "", errors.New("this project already has a repository linked")
	}
	owner, err := s.store.UserByID(site.UserID)
	if err != nil {
		return nil, "", errors.New("project owner not found")
	}
	// Deploy needs a tenant user (git must not run as root) — provision it now
	// rather than telling the user to go assign one.
	note, err := s.ensureTenant(ctx, owner)
	if err != nil {
		return nil, "", fmt.Errorf("could not provision a system user for this account (git must not run as root): %w", err)
	}
	if _, _, err := s.tenantIDs(site.UserID); err != nil {
		return nil, "", err
	}

	ghOwner, ghName, err := deploy.ParseGitHubURL(rawURL)
	if err != nil {
		return nil, "", err
	}
	branch = strings.TrimSpace(branch)
	if branch == "" {
		branch = "main"
	}
	if !deploy.ValidBranch(branch) {
		return nil, "", errors.New("invalid branch name")
	}

	authMode := deploy.AuthDeployKey
	public, sure := s.deploy.IsPublic(ctx, ghOwner, ghName)
	if public {
		authMode = deploy.AuthPublic
	} else if !sure {
		note = joinNotes(note, "couldn't confirm the repository is public (GitHub API unreachable or rate-limited) — treating it as private")
	}

	secret, serr := deploy.NewWebhookSecret()
	if serr != nil {
		secret = "" // activation backstop will retry; never block linking on this
	}
	repo := &store.Repo{
		ProjectSiteID: projectSiteID,
		Provider:      "github",
		Owner:         ghOwner,
		Name:          ghName,
		URL:           deploy.HTTPSURL(ghOwner, ghName),
		AuthMode:      authMode,
		Branch:        branch,
		CheckoutDir:   filepath.Join(s.cfg.WebRoot, site.Domain, "repo"),
		LastStatus:    "linked",
		WebhookSecret: secret,
	}
	created, err := s.store.CreateRepo(repo)
	if err != nil {
		return nil, "", err
	}
	if authMode != deploy.AuthPublic {
		pub, fp, kerr := s.deploy.GenerateKey(created.ID)
		if kerr != nil {
			_ = s.store.DeleteRepo(created.ID)
			return nil, "", fmt.Errorf("generate deploy key: %w", kerr)
		}
		created.PublicKey, created.KeyFingerprint = pub, fp
		_ = s.store.SetRepoKey(created.ID, pub, fp)
	}
	return created, note, nil
}

// ---------------------------------------------------------------------------
// Background jobs: activation (verify → clone → detect → map) and deploys run
// detached from the request so slow clones survive tab closes and the 60s
// default command timeout, with the UI polling repo status instead of hanging.
// ---------------------------------------------------------------------------

// repoJobTimeout bounds one background clone/deploy run.
const repoJobTimeout = 10 * time.Minute

// runRepoJob starts fn for a project in the background, or — when a job for
// that project is already running — queues fn as the single follow-up run. The
// follow-up executes the LATEST requested fn once the current run ends: a push
// (or click) landing mid-deploy is never lost, N of them coalesce into one
// run, and a different request kind (e.g. a branch change requiring a full
// re-activate) supersedes a queued re-deploy rather than being discarded.
// repoID is used only to record a panic as a retryable error on the card.
func (s *Service) runRepoJob(projectID, repoID int64, fn func(ctx context.Context)) {
	s.jobMu.Lock()
	if s.jobs == nil {
		s.jobs = map[int64]*repoJob{}
	}
	j := s.jobs[projectID]
	if j == nil {
		j = &repoJob{}
		s.jobs[projectID] = j
	}
	if j.running {
		j.next = fn
		s.jobMu.Unlock()
		return
	}
	j.running = true
	s.jobMu.Unlock()

	go func() {
		run := fn
		for {
			func() {
				ctx, cancel := context.WithTimeout(context.Background(), repoJobTimeout)
				defer cancel()
				defer func() {
					if r := recover(); r != nil {
						// A panicked job must still land in a retryable state,
						// not leave the card spinning on a busy status forever.
						log.Printf("project %d background job panic: %v", projectID, r)
						s.recordRepoFailure(repoID, "", fmt.Errorf("internal error during deploy — try again"))
					}
				}()
				run(ctx)
			}()
			s.jobMu.Lock()
			if j.next != nil {
				run, j.next = j.next, nil
				s.jobMu.Unlock()
				continue
			}
			j.running = false
			delete(s.jobs, projectID)
			s.jobMu.Unlock()
			return
		}
	}()
}

// StartActivate begins background activation for a repo: verify connectivity
// and branch, fresh clone, auto-detect the app, map the main site, and record
// status. Coalesces with any in-flight job for the project.
func (s *Service) StartActivate(repoID int64) {
	repo, err := s.store.RepoByID(repoID)
	if err != nil {
		return
	}
	// Mark busy now so the redirect straight after shows live progress; the job
	// re-marks it when it actually starts (a coalesced run may execute after
	// the current job's terminal write). Keep LastCommit — the site still
	// serves that checkout until the new one lands.
	_ = s.store.UpdateRepoDeploy(repoID, repo.LastCommit, "cloning", "", time.Now())
	s.runRepoJob(repo.ProjectSiteID, repoID, func(ctx context.Context) { s.activateOnce(ctx, repoID) })
}

// StartDeploy begins a background fetch+reset deploy for a project's linked
// repo. Returns an error only when no repo is linked.
func (s *Service) StartDeploy(projectSiteID int64) error {
	repo, err := s.store.RepoByProject(projectSiteID)
	if err != nil {
		return errors.New("no repository is linked to this project")
	}
	_ = s.store.UpdateRepoDeploy(repo.ID, repo.LastCommit, "deploying", "", time.Now())
	s.runRepoJob(projectSiteID, repo.ID, func(ctx context.Context) { s.deployOnce(ctx, repo.ID, projectSiteID) })
	return nil
}

// recordRepoFailure classifies err, stores a user-safe message on the repo row
// (the card is rendered to non-admin owners) and logs the raw detail. An empty
// lastCommit preserves the currently stored commit — the site keeps serving
// its existing checkout through a failed activation, and the record of what is
// live must not be wiped.
func (s *Service) recordRepoFailure(repoID int64, lastCommit string, err error) {
	err = deploy.Classify(err)
	msg := "deploy failed — check the server log (journalctl -u openpropanel) for details"
	var ue *deploy.UserError
	if errors.As(err, &ue) {
		msg = ue.Msg
	}
	if lastCommit == "" {
		if repo, rerr := s.store.RepoByID(repoID); rerr == nil {
			lastCommit = repo.LastCommit
		}
	}
	log.Printf("repo %d: %v", repoID, err)
	_ = s.store.UpdateRepoDeploy(repoID, lastCommit, "error", msg, time.Now())
}

// activateOnce is the synchronous activation pipeline (runs inside a repo job).
func (s *Service) activateOnce(ctx context.Context, repoID int64) {
	repo, err := s.store.RepoByID(repoID)
	if err != nil {
		return // unlinked while queued
	}
	// Re-mark busy from inside the run: a coalesced execution starts after the
	// previous run's terminal write, and the card polls only while busy.
	_ = s.store.UpdateRepoDeploy(repoID, repo.LastCommit, "cloning", "", time.Now())
	site, err := s.store.SiteByID(repo.ProjectSiteID)
	if err != nil {
		s.recordRepoFailure(repoID, "", err)
		return
	}
	owner, err := s.store.UserByID(site.UserID)
	if err != nil {
		s.recordRepoFailure(repoID, "", errors.New("project owner not found"))
		return
	}
	// Backstop for repos linked before JIT provisioning existed.
	if _, err := s.ensureTenant(ctx, owner); err != nil {
		s.recordRepoFailure(repoID, "", err)
		return
	}
	uid, gid, err := s.tenantIDs(site.UserID)
	if err != nil {
		s.recordRepoFailure(repoID, "", err)
		return
	}

	branches, err := s.deploy.Verify(ctx, repo, uid, gid)
	if err != nil {
		s.recordRepoFailure(repoID, "", err)
		return
	}
	if !slices.Contains(branches, repo.Branch) {
		s.recordRepoFailure(repoID, "", deploy.BranchNotFound(repo.Branch, branches))
		return
	}
	commit, err := s.deploy.Clone(ctx, repo, uid, gid)
	if err != nil {
		s.recordRepoFailure(repoID, "", err)
		return
	}
	// Wire the checkout so the tenant's own `git pull` authenticates (private
	// repos get the deploy key; public repos need nothing).
	if aerr := s.deploy.InstallRepoAuth(ctx, repo, uid, gid); aerr != nil {
		log.Printf("repo %d: enable terminal git pull: %v", repoID, aerr)
	}

	// Auto-detect how to serve the checkout and point the main domain at it —
	// but only when this repo hasn't been mapped yet (site.RepoID != repo.ID
	// also covers a dangling id left by an older unlink), so an operator's
	// explicit folder/mode choice is never overwritten by a re-activate. The
	// site row is RE-READ here: the clone above can take minutes, and a manual
	// mapping made during it must win over the pre-clone snapshot.
	if fresh, ferr := s.store.SiteByID(repo.ProjectSiteID); ferr == nil {
		site = fresh
	}
	subdir, mode, detectNote, mapOK := deploy.DetectApp(repo.CheckoutDir)
	if mapOK && (!site.RepoID.Valid || site.RepoID.Int64 != repo.ID) {
		if merr := s.MapSite(ctx, site.ID, subdir, mode); merr != nil {
			log.Printf("repo %d: auto-map %s -> %q (%s): %v", repoID, site.Domain, subdir, mode, merr)
			detectNote = joinNotes(detectNote, "auto-detected /"+subdir+" ("+mode+") but could not apply it — set the folder manually below")
		}
	}
	_ = s.store.SetRepoDetectNote(repoID, detectNote)
	if repo.WebhookSecret == "" {
		if sec, serr := deploy.NewWebhookSecret(); serr == nil {
			_ = s.store.SetRepoWebhookSecret(repoID, sec)
		}
	}
	_ = s.store.UpdateRepoDeploy(repoID, commit, "ok", "", time.Now())
}

// deployOnce fetches + hard-resets the checkout to the branch tip (as the
// tenant) and reloads the web server, refreshing every mapped domain at once.
func (s *Service) deployOnce(ctx context.Context, repoID, projectSiteID int64) {
	repo, err := s.store.RepoByID(repoID)
	if err != nil {
		return // unlinked while queued
	}
	// Re-mark busy from inside the run (see activateOnce).
	_ = s.store.UpdateRepoDeploy(repoID, repo.LastCommit, "deploying", "", time.Now())
	uid, gid, err := s.projectTenant(projectSiteID)
	if err != nil {
		s.recordRepoFailure(repoID, repo.LastCommit, err)
		return
	}
	commit, derr := s.deploy.Deploy(ctx, repo, uid, gid)
	if derr != nil {
		s.recordRepoFailure(repoID, repo.LastCommit, derr)
		return
	}
	if aerr := s.deploy.InstallRepoAuth(ctx, repo, uid, gid); aerr != nil {
		log.Printf("repo %d: enable terminal git pull: %v", repoID, aerr)
	}
	if err := s.web().Reload(ctx); err != nil {
		s.recordRepoFailure(repoID, commit, fmt.Errorf("deployed %s but the web server reload failed: %w", commit, err))
		return
	}
	// Backstop for repos linked before webhooks existed: Redeploy is the only
	// action an "ok" repo offers, so the secret must appear via this path too.
	if repo.WebhookSecret == "" {
		if sec, serr := deploy.NewWebhookSecret(); serr == nil {
			_ = s.store.SetRepoWebhookSecret(repoID, sec)
		}
	}
	_ = s.store.UpdateRepoDeploy(repoID, commit, "ok", "", time.Now())
}

// ChangeRepoBranch switches the branch a repo deploys from and re-activates.
// The deploy key is untouched, so fixing a branch typo never requires
// re-adding the key on GitHub.
func (s *Service) ChangeRepoBranch(repoID int64, branch string) error {
	branch = strings.TrimSpace(branch)
	if !deploy.ValidBranch(branch) {
		return errors.New("invalid branch name")
	}
	if err := s.store.SetRepoBranch(repoID, branch); err != nil {
		return err
	}
	s.StartActivate(repoID)
	return nil
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
	// Mapping always yields a file-serving mode; drop any reverse-proxy app so
	// its port is freed and its unit removed.
	s.removeAppFor(ctx, site)
	if err := s.renderVHost(site); err != nil {
		return err
	}
	return s.web().Apply(ctx)
}

// RepoHead returns the checked-out HEAD commit's details for a project's repo,
// or nil if there is no repo or it can't be read. Best-effort — it runs git as
// the tenant and never blocks the page on failure.
func (s *Service) RepoHead(ctx context.Context, projectSiteID int64) *deploy.CommitInfo {
	repo, err := s.store.RepoByProject(projectSiteID)
	if err != nil {
		return nil
	}
	site, err := s.store.SiteByID(projectSiteID)
	if err != nil {
		return nil
	}
	uid, gid, err := s.tenantIDs(site.UserID)
	if err != nil {
		return nil
	}
	info, err := s.deploy.HeadInfo(ctx, repo, uid, gid)
	if err != nil {
		return nil
	}
	return info
}

// ReconcileRepoAuth wires every existing repo's checkout for terminal `git pull`
// at startup, so an upgrade enables it without a manual Redeploy. Best-effort and
// per-repo so one failure can't block the rest.
func (s *Service) ReconcileRepoAuth(ctx context.Context) {
	repos, err := s.store.ListRepos()
	if err != nil {
		return
	}
	for _, repo := range repos {
		uid, gid, err := s.projectTenant(repo.ProjectSiteID)
		if err != nil {
			continue
		}
		if !isGitCheckoutDir(repo.CheckoutDir) {
			continue // not cloned yet; the next deploy will wire it
		}
		_ = s.deploy.InstallRepoAuth(ctx, repo, uid, gid)
	}
}

// isGitCheckoutDir reports whether dir looks like a git working tree.
func isGitCheckoutDir(dir string) bool {
	fi, err := os.Stat(filepath.Join(dir, ".git"))
	return err == nil && (fi.IsDir() || fi.Mode().IsRegular())
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

// UnlinkRepo removes a project's repository link + deploy key (files on disk
// are left in place). Site mappings into the checkout are detached (doc root
// and mode stay, so the site keeps serving) — a later relink must start
// unmapped or its auto-map guard misfires on the dangling repo id.
func (s *Service) UnlinkRepo(ctx context.Context, projectSiteID int64) error {
	repo, err := s.store.RepoByProject(projectSiteID)
	if err != nil {
		return nil
	}
	s.deploy.RemoveKey(repo.ID)
	s.deploy.RemoveRepoAuth(repo) // durable deploy-key copy beside the checkout
	if err := s.store.ClearRepoMapping(repo.ID); err != nil {
		return err
	}
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

// joinNotes concatenates non-empty operator notes with a separator.
func joinNotes(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	return a + " · " + b
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
