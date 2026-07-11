package web

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"

	"github.com/openpropanel/openpropanel/internal/auth"
	"github.com/openpropanel/openpropanel/internal/deploy"
	"github.com/openpropanel/openpropanel/internal/store"
)

// authorizeRepo loads the repo named by {id} and checks the caller may manage
// its project (owner or admin).
func (s *Server) authorizeRepo(w http.ResponseWriter, r *http.Request) (*store.Repo, bool) {
	u := auth.UserFrom(r.Context())
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return nil, false
	}
	repo, err := s.store.RepoByID(id)
	if err != nil {
		http.Error(w, "repository not found", http.StatusNotFound)
		return nil, false
	}
	site, err := s.store.SiteByID(repo.ProjectSiteID)
	if err != nil {
		http.Error(w, "project not found", http.StatusNotFound)
		return nil, false
	}
	if u.Role != store.RoleAdmin && site.UserID != u.ID {
		http.Error(w, "forbidden", http.StatusForbidden)
		return nil, false
	}
	return repo, true
}

// projectRedirect PRG-redirects back to the Projects page anchored at a
// project's card, so the user lands where they acted — not at the page top
// with the relevant card collapsed off-screen. ERRORS are deliberately NOT
// anchored: the flash banner renders once at the top of the page, and
// anchoring would scroll it out of view, making a failed action look like a
// silent no-op.
func projectRedirect(w http.ResponseWriter, r *http.Request, projectID int64, kind, msg string) {
	path := "/sites"
	if msg != "" {
		path += "?" + kind + "=" + url.QueryEscape(msg)
	}
	if kind != "err" {
		path += "#project-" + strconv.FormatInt(projectID, 10)
	}
	http.Redirect(w, r, path, http.StatusSeeOther)
}

// postLinkRepo links a GitHub repo to a project ({id} is the project's site).
// Public repos go straight into background activation — verify, clone, detect,
// map, live — with zero further clicks.
func (s *Server) postLinkRepo(w http.ResponseWriter, r *http.Request) {
	site, ok := s.authorizeSite(w, r)
	if !ok {
		return
	}
	repo, note, err := s.domains.LinkRepo(r.Context(), site.ID, r.FormValue("repo_url"), r.FormValue("branch"))
	if err != nil {
		projectRedirect(w, r, site.ID, "err", s.opErr(r, err))
		return
	}
	if repo.AuthMode == deploy.AuthPublic {
		s.domains.StartActivate(repo.ID)
		projectRedirect(w, r, site.ID, "msg", joinFlash("Deploying "+repo.Owner+"/"+repo.Name+"@"+repo.Branch+" — the card below updates as it progresses.", note))
		return
	}
	projectRedirect(w, r, site.ID, "msg", joinFlash("Repository linked — one step left: add the deploy key below on GitHub, then click Deploy.", note))
}

func joinFlash(msg, note string) string {
	if note == "" {
		return msg
	}
	return msg + " (" + note + ")"
}

func (s *Server) postUnlinkRepo(w http.ResponseWriter, r *http.Request) {
	site, ok := s.authorizeSite(w, r)
	if !ok {
		return
	}
	if err := s.domains.UnlinkRepo(r.Context(), site.ID); err != nil {
		projectRedirect(w, r, site.ID, "err", s.opErr(r, err))
		return
	}
	projectRedirect(w, r, site.ID, "msg", "Repository unlinked — files on disk were kept")
}

// postActivateRepo starts background activation: verify + clone + auto-detect
// + map. Used by the private-repo "Deploy" button (after the key is added on
// GitHub) and safe to re-click — runs coalesce.
func (s *Server) postActivateRepo(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.authorizeRepo(w, r)
	if !ok {
		return
	}
	s.domains.StartActivate(repo.ID)
	projectRedirect(w, r, repo.ProjectSiteID, "msg", "Deploying "+repo.Owner+"/"+repo.Name+"@"+repo.Branch+" — the card below updates as it progresses.")
}

// postRepoBranch changes the deploy branch and re-activates. The deploy key is
// untouched, so a branch typo never costs a key re-add on GitHub.
func (s *Server) postRepoBranch(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.authorizeRepo(w, r)
	if !ok {
		return
	}
	if err := s.domains.ChangeRepoBranch(repo.ID, r.FormValue("branch")); err != nil {
		projectRedirect(w, r, repo.ProjectSiteID, "err", s.opErr(r, err))
		return
	}
	projectRedirect(w, r, repo.ProjectSiteID, "msg", "Branch changed — redeploying from "+r.FormValue("branch"))
}

func (s *Server) postDeployProject(w http.ResponseWriter, r *http.Request) {
	site, ok := s.authorizeSite(w, r)
	if !ok {
		return
	}
	if err := s.domains.StartDeploy(site.ID); err != nil {
		projectRedirect(w, r, site.ID, "err", s.opErr(r, err))
		return
	}
	projectRedirect(w, r, site.ID, "msg", "Deploying the latest commit for "+site.Domain+" — the card below updates as it progresses.")
}

// getRepoCard renders one repo card fragment (HTMX polls it while a background
// clone/deploy is running, so the user sees live progress without reloading).
func (s *Server) getRepoCard(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.authorizeRepo(w, r)
	if !ok {
		return
	}
	s.render.fragment(w, "sites", "repoBox", map[string]any{
		"Repo": repo,
		"Pid":  repo.ProjectSiteID,
		"Host": r.Host,
	})
}

// postMapSite points a site's doc root at a repo subfolder + sets serving mode.
func (s *Server) postMapSite(w http.ResponseWriter, r *http.Request) {
	site, ok := s.authorizeSite(w, r)
	if !ok {
		return
	}
	// Anchor back to the project card (the parent's, for a subdomain row).
	pid := site.ID
	if site.Type == store.SiteSubdomain && site.ParentID.Valid {
		pid = site.ParentID.Int64
	}
	if err := s.domains.MapSite(r.Context(), site.ID, r.FormValue("subdir"), r.FormValue("mode")); err != nil {
		projectRedirect(w, r, pid, "err", s.opErr(r, err))
		return
	}
	folder := r.FormValue("subdir")
	if folder == "" {
		folder = "the repository root"
	}
	projectRedirect(w, r, pid, "msg", site.Domain+" now serves from "+folder)
}

// getRepoTree lists subfolders of a repo checkout for the folder picker (JSON).
func (s *Server) getRepoTree(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.authorizeRepo(w, r)
	if !ok {
		return
	}
	dirs, err := s.domains.RepoTree(repo.ID, r.URL.Query().Get("path"))
	if err != nil {
		http.Error(w, s.opErr(r, err), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"path": r.URL.Query().Get("path"), "dirs": dirs})
}
