package web

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/openpropanel/openpropanel/internal/auth"
	"github.com/openpropanel/openpropanel/internal/deploy"
	"github.com/openpropanel/openpropanel/internal/php"
	"github.com/openpropanel/openpropanel/internal/store"
)

// modeOption is one serving-mode choice for the UI.
type modeOption struct{ Value, Label string }

func serveModes() []modeOption {
	return []modeOption{
		{store.WebModePHP, "PHP"},
		{store.WebModeStatic, "Static"},
		{store.WebModeSPA, "SPA"},
	}
}

type domainsVM struct {
	Rows        []siteRow
	PHPVersions []php.Version
	Modes       []modeOption
	IsAdmin     bool
	Users       []*store.User
	CurrentUID  int64
}

type domainVM struct {
	Site          *store.Site
	Project       *store.Site // the project's main site (== Site for a main)
	IsProjectMain bool
	Repo          *store.Repo   // the project's linked repo, or nil
	Subs          []*store.Site // when IsProjectMain
	OwnerName     string
	PHPVersions   []php.Version
	Modes         []modeOption
	Host          string
	IsAdmin       bool
	ActiveTab     string // overview | deployment | ssl
	Detail        string // this domain's own detail URL, for form "return" fields

	App        *store.App // reverse-proxy app config, or nil
	AppActive  bool       // managed app unit is running
	AppEnabled bool       // managed app unit is enabled at boot
	Runtimes   []string   // runtime labels for the app form

	SystemUser string             // the site's tenant OS user (for the terminal hint)
	Head       *deploy.CommitInfo // last-deployed commit, or nil
}

// projectsFor loads the caller's sites and groups them into project rows
// (a main site + its subdomains + its linked repo). Shared by the list and the
// detail page.
func (s *Server) projectsFor(viewer *store.User) ([]siteRow, map[int64]string, error) {
	isAdmin := viewer.Role == store.RoleAdmin
	var sites []*store.Site
	var err error
	if isAdmin {
		sites, err = s.store.ListSites()
	} else {
		sites, err = s.store.ListSitesByUser(viewer.ID)
	}
	if err != nil {
		return nil, nil, err
	}
	names := map[int64]string{}
	if isAdmin {
		if users, e := s.store.ListUsers(); e == nil {
			for _, usr := range users {
				names[usr.ID] = usr.Username
			}
		}
	} else {
		names[viewer.ID] = viewer.Username
	}
	subsByParent := map[int64][]*store.Site{}
	var mains []*store.Site
	for _, st := range sites {
		if st.Type == store.SiteSubdomain && st.ParentID.Valid {
			subsByParent[st.ParentID.Int64] = append(subsByParent[st.ParentID.Int64], st)
		} else if st.Type == store.SiteMain {
			mains = append(mains, st)
		}
	}
	rows := make([]siteRow, 0, len(mains))
	for _, m := range mains {
		row := siteRow{Site: m, OwnerName: names[m.UserID], Subs: subsByParent[m.ID]}
		if repo, e := s.store.RepoByProject(m.ID); e == nil {
			row.Repo = repo
		}
		rows = append(rows, row)
	}
	return rows, names, nil
}

// getDomains renders the clean domains list (projects with their domain rows).
func (s *Server) getDomains(w http.ResponseWriter, r *http.Request) {
	viewer := auth.UserFrom(r.Context())
	rows, _, err := s.projectsFor(viewer)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	vm := domainsVM{
		Rows: rows, PHPVersions: s.php.DetectVersions(), Modes: serveModes(),
		IsAdmin: viewer.Role == store.RoleAdmin, CurrentUID: viewer.ID,
	}
	if vm.IsAdmin {
		vm.Users, _ = s.store.ListUsers()
	}
	s.render.page(w, http.StatusOK, "domains", pageData{
		User: viewer, Active: "domains",
		Flash: r.URL.Query().Get("msg"), Error: r.URL.Query().Get("err"),
		Data: vm,
	})
}

// getDomain renders the per-domain detail page (Overview / Deployment / SSL).
func (s *Server) getDomain(w http.ResponseWriter, r *http.Request) {
	site, ok := s.authorizeSite(w, r)
	if !ok {
		return
	}
	viewer := auth.UserFrom(r.Context())

	// The project = this site if it's a main, else its parent main.
	project := site
	if site.Type == store.SiteSubdomain && site.ParentID.Valid {
		if p, err := s.store.SiteByID(site.ParentID.Int64); err == nil {
			project = p
		}
	}
	var repo *store.Repo
	if rp, err := s.store.RepoByProject(project.ID); err == nil {
		repo = rp
	}
	var subs []*store.Site
	isMain := site.Type == store.SiteMain
	if isMain {
		subs, _ = s.store.ListSubdomains(site.ID)
	}
	ownerName := viewer.Username
	var systemUser string
	if owner, err := s.store.UserByID(site.UserID); err == nil {
		systemUser = owner.SystemUser
		if viewer.Role == store.RoleAdmin {
			ownerName = owner.Username
		}
	}
	tab := r.URL.Query().Get("tab")
	if tab != "deployment" && tab != "ssl" {
		tab = "overview"
	}
	// The last-deployed commit (best-effort, tenant git) for the Deployment tab.
	var head *deploy.CommitInfo
	if tab == "deployment" && isMain && repo != nil {
		head = s.domains.RepoHead(r.Context(), project.ID)
	}
	// Reverse-proxy app (if any) + its live unit status.
	app := s.domains.AppFor(site.ID)
	var appActive, appEnabled bool
	if app != nil {
		appActive, appEnabled = s.domains.AppStatus(r.Context(), site.ID)
	}
	s.render.page(w, http.StatusOK, "domain", pageData{
		User: viewer, Active: "domains",
		Flash: r.URL.Query().Get("msg"), Error: r.URL.Query().Get("err"),
		Data: domainVM{
			Site: site, Project: project, IsProjectMain: isMain, Repo: repo, Subs: subs,
			OwnerName: ownerName, PHPVersions: s.php.DetectVersions(), Modes: serveModes(),
			Host: r.Host, IsAdmin: viewer.Role == store.RoleAdmin, ActiveTab: tab,
			Detail:   "/domains/" + strconv.FormatInt(site.ID, 10),
			App:      app, AppActive: appActive, AppEnabled: appEnabled, Runtimes: appRuntimes(),
			SystemUser: systemUser, Head: head,
		},
	})
}

// postServe changes a non-repo domain's folder + serving mode.
func (s *Server) postServe(w http.ResponseWriter, r *http.Request) {
	site, ok := s.authorizeSite(w, r)
	if !ok {
		return
	}
	viewer := auth.UserFrom(r.Context())
	allowShared := viewer.Role == store.RoleAdmin
	if err := s.domains.SetServe(r.Context(), site.ID, r.FormValue("doc_root"), r.FormValue("mode"), allowShared); err != nil {
		s.backRedirect(w, r, "err", s.opErr(r, err))
		return
	}
	s.backRedirect(w, r, "msg", site.Domain+" updated")
}

// backTo returns the same-origin page to return to after a mutation: the form's
// "return" field when it points at the domains UI, else the domains list.
func backTo(r *http.Request) string {
	if v := r.FormValue("return"); strings.HasPrefix(v, "/domains") && !strings.Contains(v, "//") {
		return v
	}
	return "/domains"
}

// backRedirect completes a mutation with a flash, returning to backTo(r).
func (s *Server) backRedirect(w http.ResponseWriter, r *http.Request, kind, msg string) {
	if isAjax(r) {
		if kind == "err" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": msg})
		} else {
			writeJSON(w, http.StatusOK, map[string]any{"msg": msg})
		}
		return
	}
	redirect(w, r, backTo(r), kind, msg)
}
