package web

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/openpropanel/openpropanel/internal/auth"
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

// postLinkRepo links a GitHub repo to a project ({id} is the project's site).
func (s *Server) postLinkRepo(w http.ResponseWriter, r *http.Request) {
	site, ok := s.authorizeSite(w, r)
	if !ok {
		return
	}
	if _, err := s.domains.LinkRepo(r.Context(), site.ID, r.FormValue("repo_url"), r.FormValue("branch")); err != nil {
		redirect(w, r, "/sites", "err", s.opErr(r, err))
		return
	}
	redirect(w, r, "/sites", "msg", "Repository linked — add the deploy key (if shown) to GitHub, then Clone.")
}

func (s *Server) postUnlinkRepo(w http.ResponseWriter, r *http.Request) {
	site, ok := s.authorizeSite(w, r)
	if !ok {
		return
	}
	if err := s.domains.UnlinkRepo(r.Context(), site.ID); err != nil {
		redirect(w, r, "/sites", "err", s.opErr(r, err))
		return
	}
	redirect(w, r, "/sites", "msg", "Repository unlinked")
}

func (s *Server) postVerifyRepo(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.authorizeRepo(w, r)
	if !ok {
		return
	}
	if err := s.domains.VerifyRepo(r.Context(), repo.ID); err != nil {
		redirect(w, r, "/sites", "err", "Connection test failed: "+s.opErr(r, err))
		return
	}
	redirect(w, r, "/sites", "msg", "Connected to "+repo.Owner+"/"+repo.Name+" successfully")
}

func (s *Server) postCloneRepo(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.authorizeRepo(w, r)
	if !ok {
		return
	}
	if err := s.domains.CloneRepo(r.Context(), repo.ID); err != nil {
		redirect(w, r, "/sites", "err", "Clone failed: "+s.opErr(r, err))
		return
	}
	redirect(w, r, "/sites", "msg", "Cloned "+repo.Owner+"/"+repo.Name+" — now map each domain to a folder")
}

func (s *Server) postDeployProject(w http.ResponseWriter, r *http.Request) {
	site, ok := s.authorizeSite(w, r)
	if !ok {
		return
	}
	if err := s.domains.DeployProject(r.Context(), site.ID); err != nil {
		redirect(w, r, "/sites", "err", "Deploy failed: "+s.opErr(r, err))
		return
	}
	redirect(w, r, "/sites", "msg", "Deployed the latest commit for "+site.Domain)
}

// postMapSite points a site's doc root at a repo subfolder + sets serving mode.
func (s *Server) postMapSite(w http.ResponseWriter, r *http.Request) {
	site, ok := s.authorizeSite(w, r)
	if !ok {
		return
	}
	if err := s.domains.MapSite(r.Context(), site.ID, r.FormValue("subdir"), r.FormValue("mode")); err != nil {
		redirect(w, r, "/sites", "err", s.opErr(r, err))
		return
	}
	redirect(w, r, "/sites", "msg", site.Domain+" now serves from "+r.FormValue("subdir"))
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
