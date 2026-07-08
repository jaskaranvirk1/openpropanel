package web

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/openpropanel/openpropanel/internal/auth"
	"github.com/openpropanel/openpropanel/internal/php"
	"github.com/openpropanel/openpropanel/internal/store"
	"github.com/openpropanel/openpropanel/internal/system"
)

// usernameRe validates panel/system account names: 3-32 chars of lowercase
// letters, digits, underscore or hyphen, starting with a letter or digit.
var usernameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{2,31}$`)

// ---------------------------------------------------------------------------
// view models
// ---------------------------------------------------------------------------

type dashboardVM struct {
	Stats    system.Stats
	Services []system.ServiceInfo
	IsAdmin  bool
}

type siteRow struct {
	Site      *store.Site
	OwnerName string
	Subs      []*store.Site
}

type sitesVM struct {
	Rows        []siteRow
	PHPVersions []php.Version
	IsAdmin     bool
	Users       []*store.User
}

type usersVM struct {
	Users      []*store.User
	SitesCount map[int64]int
}

type settingsVM struct {
	ACMEEmail     string
	ListenAddr    string
	WebRoot       string
	WebServer     string // "apache" | "nginx"
	Dev           bool
	TLSEnabled    bool
	PanelHostname string
	CertKind      string // "self-signed" | "Let's Encrypt" | "custom"
}

// ---------------------------------------------------------------------------
// auth handlers
// ---------------------------------------------------------------------------

func (s *Server) getLogin(w http.ResponseWriter, r *http.Request) {
	s.render.page(w, http.StatusOK, "login", pageData{Error: r.URL.Query().Get("err")})
}

func (s *Server) postLogin(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	if _, err := s.auth.Login(w, username, password); err != nil {
		redirect(w, r, "/login", "err", "Invalid username or password")
		return
	}
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (s *Server) postLogout(w http.ResponseWriter, r *http.Request) {
	s.auth.Logout(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ---------------------------------------------------------------------------
// dashboard
// ---------------------------------------------------------------------------

func (s *Server) dashboardData(ctx context.Context, isAdmin bool) dashboardVM {
	return dashboardVM{
		Stats: system.Collect(),
		Services: system.InspectServices(ctx,
			s.cfg.ActiveWebService(), s.cfg.PHPFPMService, "mariadb", "firewalld"),
		IsAdmin: isAdmin,
	}
}

func (s *Server) getDashboard(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFrom(r.Context())
	s.render.page(w, http.StatusOK, "dashboard", pageData{
		User:   u,
		Active: "dashboard",
		Flash:  r.URL.Query().Get("msg"),
		Error:  r.URL.Query().Get("err"),
		Data:   s.dashboardData(r.Context(), u.Role == store.RoleAdmin),
	})
}

func (s *Server) getStats(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFrom(r.Context())
	s.render.fragment(w, "dashboard", "dashboard-live", s.dashboardData(r.Context(), u.Role == store.RoleAdmin))
}

func (s *Server) postService(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFrom(r.Context())
	if u == nil || u.Role != store.RoleAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	unit := r.PathValue("unit")
	action := r.PathValue("action")

	allowedUnits := map[string]bool{
		s.cfg.ApacheService: true, s.cfg.NginxService: true, s.cfg.PHPFPMService: true,
		"mariadb": true, "firewalld": true,
	}
	allowedActions := map[string]bool{"start": true, "stop": true, "restart": true, "reload": true}
	if !allowedUnits[unit] || !allowedActions[action] {
		redirect(w, r, "/dashboard", "err", "Unsupported service action")
		return
	}
	if err := system.ServiceAction(r.Context(), action, unit); err != nil {
		redirect(w, r, "/dashboard", "err", action+" "+unit+" failed: "+err.Error())
		return
	}
	redirect(w, r, "/dashboard", "msg", unit+" "+action+"ed")
}

// ---------------------------------------------------------------------------
// sites
// ---------------------------------------------------------------------------

func (s *Server) getSites(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFrom(r.Context())
	isAdmin := u.Role == store.RoleAdmin

	var sites []*store.Site
	var err error
	if isAdmin {
		sites, err = s.store.ListSites()
	} else {
		sites, err = s.store.ListSitesByUser(u.ID)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Resolve owner names once.
	names := map[int64]string{}
	if isAdmin {
		if users, err := s.store.ListUsers(); err == nil {
			for _, usr := range users {
				names[usr.ID] = usr.Username
			}
		}
	} else {
		names[u.ID] = u.Username
	}

	// Group subdomains under their parent main site.
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
		rows = append(rows, siteRow{Site: m, OwnerName: names[m.UserID], Subs: subsByParent[m.ID]})
	}

	vm := sitesVM{Rows: rows, PHPVersions: s.php.DetectVersions(), IsAdmin: isAdmin}
	if isAdmin {
		vm.Users, _ = s.store.ListUsers()
	}
	s.render.page(w, http.StatusOK, "sites", pageData{
		User: u, Active: "sites",
		Flash: r.URL.Query().Get("msg"), Error: r.URL.Query().Get("err"),
		Data: vm,
	})
}

func (s *Server) postCreateSite(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFrom(r.Context())
	owner := u.ID
	if u.Role == store.RoleAdmin {
		if v := r.FormValue("owner_id"); v != "" {
			if id, err := strconv.ParseInt(v, 10, 64); err == nil {
				owner = id
			}
		}
	}
	domain := r.FormValue("domain")
	phpVersion := r.FormValue("php_version")
	if _, err := s.domains.CreateSite(r.Context(), owner, domain, phpVersion); err != nil {
		redirect(w, r, "/sites", "err", err.Error())
		return
	}
	redirect(w, r, "/sites", "msg", "Domain "+domain+" created")
}

func (s *Server) postDeleteSite(w http.ResponseWriter, r *http.Request) {
	site, ok := s.authorizeSite(w, r)
	if !ok {
		return
	}
	if err := s.domains.DeleteSite(r.Context(), site.ID); err != nil {
		redirect(w, r, "/sites", "err", err.Error())
		return
	}
	redirect(w, r, "/sites", "msg", site.Domain+" deleted")
}

func (s *Server) postChangePHP(w http.ResponseWriter, r *http.Request) {
	site, ok := s.authorizeSite(w, r)
	if !ok {
		return
	}
	version := r.FormValue("php_version")
	if err := s.domains.ChangePHP(r.Context(), site.ID, version); err != nil {
		redirect(w, r, "/sites", "err", err.Error())
		return
	}
	redirect(w, r, "/sites", "msg", site.Domain+" switched to PHP "+version)
}

func (s *Server) postToggleSSL(w http.ResponseWriter, r *http.Request) {
	site, ok := s.authorizeSite(w, r)
	if !ok {
		return
	}
	enable := r.FormValue("enable") == "1"
	var err error
	if enable {
		err = s.domains.EnableSSL(r.Context(), site.ID)
	} else {
		err = s.domains.DisableSSL(r.Context(), site.ID)
	}
	if err != nil {
		redirect(w, r, "/sites", "err", err.Error())
		return
	}
	msg := "SSL enabled for " + site.Domain
	if !enable {
		msg = "SSL disabled for " + site.Domain
	}
	redirect(w, r, "/sites", "msg", msg)
}

func (s *Server) postAddSubdomain(w http.ResponseWriter, r *http.Request) {
	site, ok := s.authorizeSite(w, r)
	if !ok {
		return
	}
	label := r.FormValue("label")
	if _, err := s.domains.AddSubdomain(r.Context(), site.ID, label); err != nil {
		redirect(w, r, "/sites", "err", err.Error())
		return
	}
	redirect(w, r, "/sites", "msg", "Subdomain "+label+"."+site.Domain+" created")
}

// postScanSites re-scans the host for pre-existing vhosts and imports new ones.
func (s *Server) postScanSites(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFrom(r.Context())
	if u == nil || u.Role != store.RoleAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	n, err := s.domains.ImportExisting(r.Context())
	if err != nil {
		redirect(w, r, "/sites", "err", "Scan failed: "+err.Error())
		return
	}
	msg := "No new sites found"
	if n > 0 {
		msg = "Imported " + strconv.Itoa(n) + " existing site(s)"
	}
	redirect(w, r, "/sites", "msg", msg)
}

// postAdoptSite converts an imported site to fully managed.
func (s *Server) postAdoptSite(w http.ResponseWriter, r *http.Request) {
	site, ok := s.authorizeSite(w, r)
	if !ok {
		return
	}
	if err := s.domains.AdoptSite(r.Context(), site.ID, r.FormValue("php_version")); err != nil {
		redirect(w, r, "/sites", "err", err.Error())
		return
	}
	redirect(w, r, "/sites", "msg", site.Domain+" adopted — now fully managed")
}

// authorizeSite loads the site named by {id} and checks the current user may
// manage it (owner or admin). It writes the error response itself on failure.
func (s *Server) authorizeSite(w http.ResponseWriter, r *http.Request) (*store.Site, bool) {
	u := auth.UserFrom(r.Context())
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return nil, false
	}
	site, err := s.store.SiteByID(id)
	if err != nil {
		http.Error(w, "site not found", http.StatusNotFound)
		return nil, false
	}
	if u.Role != store.RoleAdmin && site.UserID != u.ID {
		http.Error(w, "forbidden", http.StatusForbidden)
		return nil, false
	}
	return site, true
}

// ---------------------------------------------------------------------------
// users (admin)
// ---------------------------------------------------------------------------

func (s *Server) getUsers(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFrom(r.Context())
	users, err := s.store.ListUsers()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	counts := map[int64]int{}
	for _, usr := range users {
		if sites, err := s.store.ListSitesByUser(usr.ID); err == nil {
			counts[usr.ID] = len(sites)
		}
	}
	s.render.page(w, http.StatusOK, "users", pageData{
		User: u, Active: "users",
		Flash: r.URL.Query().Get("msg"), Error: r.URL.Query().Get("err"),
		Data: usersVM{Users: users, SitesCount: counts},
	})
}

func (s *Server) postCreateUser(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(strings.ToLower(r.FormValue("username")))
	email := strings.TrimSpace(r.FormValue("email"))
	password := r.FormValue("password")
	role := r.FormValue("role")
	systemUser := strings.TrimSpace(r.FormValue("system_user"))

	if !usernameRe.MatchString(username) {
		redirect(w, r, "/users", "err", "Username must be 3-32 chars: letters, digits, underscore, hyphen")
		return
	}
	if len(password) < 8 {
		redirect(w, r, "/users", "err", "Password must be at least 8 characters")
		return
	}
	// system_user is written verbatim into a root-generated php-fpm pool file,
	// so it MUST be strictly validated to prevent config injection. Reject
	// anything that is not a plain, unprivileged account name.
	if systemUser != "" && (!usernameRe.MatchString(systemUser) || systemUser == "root") {
		redirect(w, r, "/users", "err", "System user must be a valid, non-root account name (a-z, 0-9, _-)")
		return
	}
	if role != store.RoleAdmin {
		role = store.RoleUser
	}
	if _, err := s.store.UserByUsername(username); err == nil {
		redirect(w, r, "/users", "err", "Username already exists")
		return
	}
	// Provision the Linux system user up front so the account is never stored
	// referencing a user that php-fpm/chown will later fail on.
	if systemUser != "" {
		if err := s.sysuser.Ensure(r.Context(), systemUser); err != nil {
			redirect(w, r, "/users", "err", "System user: "+err.Error())
			return
		}
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		redirect(w, r, "/users", "err", "Could not hash password")
		return
	}
	_, err = s.store.CreateUser(&store.User{
		Username: username, Email: email, PasswordHash: hash,
		Role: role, SystemUser: systemUser,
	})
	if err != nil {
		redirect(w, r, "/users", "err", err.Error())
		return
	}
	redirect(w, r, "/users", "msg", "User "+username+" created")
}

func (s *Server) postDeleteUser(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFrom(r.Context())
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if id == u.ID {
		redirect(w, r, "/users", "err", "You cannot delete your own account")
		return
	}
	// DeleteAccount tears down the user's live sites (vhosts + php-fpm pools)
	// before removing the account, so nothing is left orphaned on disk.
	if err := s.domains.DeleteAccount(r.Context(), id); err != nil {
		redirect(w, r, "/users", "err", err.Error())
		return
	}
	redirect(w, r, "/users", "msg", "User deleted")
}

// ---------------------------------------------------------------------------
// settings (admin)
// ---------------------------------------------------------------------------

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFrom(r.Context())
	certKind := "self-signed"
	if s.cfg.TLSCert != "" {
		if strings.Contains(s.cfg.TLSCert, "letsencrypt") {
			certKind = "Let's Encrypt"
		} else {
			certKind = "custom"
		}
	}
	s.render.page(w, http.StatusOK, "settings", pageData{
		User: u, Active: "settings",
		Flash: r.URL.Query().Get("msg"), Error: r.URL.Query().Get("err"),
		Data: settingsVM{
			ACMEEmail: s.cfg.ACMEEmail, ListenAddr: s.cfg.ListenAddr,
			WebRoot: s.cfg.WebRoot, WebServer: s.cfg.WebServer, Dev: s.cfg.Dev,
			TLSEnabled: s.cfg.TLSEnabled, PanelHostname: s.cfg.PanelHostname, CertKind: certKind,
		},
	})
}

// postPanelCert issues a Let's Encrypt certificate for the panel's own hostname
// and switches the panel to serve it (picked up live via the cert reloader).
func (s *Server) postPanelCert(w http.ResponseWriter, r *http.Request) {
	host := strings.TrimSpace(r.FormValue("panel_hostname"))
	if s.cfg.ACMEEmail == "" {
		redirect(w, r, "/settings", "err", "Set an ACME email above first, then request the certificate")
		return
	}
	certFile, keyFile, normHost, err := s.domains.IssuePanelCert(r.Context(), host)
	if err != nil {
		redirect(w, r, "/settings", "err", "Certificate request failed: "+err.Error())
		return
	}
	s.cfg.TLSCert, s.cfg.TLSKey, s.cfg.PanelHostname = certFile, keyFile, normHost
	if err := s.cfg.Save(s.cfgPath); err != nil {
		redirect(w, r, "/settings", "err", "Issued the certificate but could not save config: "+err.Error())
		return
	}
	redirect(w, r, "/settings", "msg", "Certificate issued for "+normHost+". Reload the panel at https://"+normHost+s.cfg.ListenAddr)
}

// postWebServer switches the active web server (apache <-> nginx): it
// regenerates every site's config for the target, swaps the systemd services,
// reloads, and persists the choice.
func (s *Server) postWebServer(w http.ResponseWriter, r *http.Request) {
	target := strings.TrimSpace(r.FormValue("web_server"))
	if target != "apache" && target != "nginx" {
		redirect(w, r, "/settings", "err", "Choose apache or nginx")
		return
	}
	if target == s.cfg.WebServer {
		redirect(w, r, "/settings", "msg", "Already using "+target)
		return
	}
	// SwitchWebServer persists the config itself once services agree.
	if err := s.domains.SwitchWebServer(r.Context(), target); err != nil {
		redirect(w, r, "/settings", "err", "Switch failed: "+err.Error())
		return
	}
	redirect(w, r, "/settings", "msg", "Web server switched to "+target)
}

func (s *Server) postSettings(w http.ResponseWriter, r *http.Request) {
	s.cfg.ACMEEmail = strings.TrimSpace(r.FormValue("acme_email"))
	if err := s.cfg.Save(s.cfgPath); err != nil {
		redirect(w, r, "/settings", "err", "Could not save settings: "+err.Error())
		return
	}
	redirect(w, r, "/settings", "msg", "Settings saved")
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func redirect(w http.ResponseWriter, r *http.Request, path, kind, msg string) {
	if msg != "" {
		path += "?" + kind + "=" + url.QueryEscape(msg)
	}
	http.Redirect(w, r, path, http.StatusSeeOther)
}
