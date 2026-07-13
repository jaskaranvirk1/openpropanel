package web

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/openpropanel/openpropanel/internal/auth"
	"github.com/openpropanel/openpropanel/internal/deploy"
	"github.com/openpropanel/openpropanel/internal/store"
	"github.com/openpropanel/openpropanel/internal/system"
)

// usernameRe validates panel/system account names: 3-32 chars of lowercase
// letters, digits, underscore or hyphen, starting with a letter or digit.
var usernameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{2,31}$`)

// opErr sanitizes an error from a system operation for display. It always logs
// the full detail server-side; non-admin users get a generic message so raw
// command output (absolute paths, httpd -t / certbot / mysql text, other
// tenants' data) never leaks to them. Admins may see the detail to debug.
// deploy.UserError is the exception: its message is written to be user-safe
// (no command output), so every role gets the actionable guidance.
func (s *Server) opErr(r *http.Request, err error) string {
	log.Printf("operation error [%s %s]: %v", r.Method, r.URL.Path, err)
	var ue *deploy.UserError
	if errors.As(err, &ue) {
		return ue.Msg
	}
	if u := auth.UserFrom(r.Context()); u != nil && u.Role == store.RoleAdmin {
		return err.Error()
	}
	return "The operation failed. Please review your input and try again."
}

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
	Repo      *store.Repo // linked GitHub repo for this project, or nil
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
	ip := clientIP(r)
	if ok, wait := s.login.allow(ip); !ok {
		redirect(w, r, "/login", "err",
			"Too many failed attempts. Try again in "+wait.String()+".")
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")

	// Bound concurrent bcrypt work so a login flood can't monopolise the CPU.
	release := s.login.acquire()
	user, err := s.auth.Login(w, username, password)
	release()

	if err != nil {
		s.login.fail(ip)
		redirect(w, r, "/login", "err", "Invalid username or password")
		return
	}
	s.login.success(ip)
	// Once an admin has logged in, the plaintext first-run credential file has
	// served its purpose — remove it.
	if user.Role == store.RoleAdmin {
		_ = os.Remove(filepath.Join(s.cfg.DataDir, "initial-admin-password.txt"))
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

// dashboardData samples host stats + services, cached for a few seconds and
// serialized so rapid polling (every 5s per client, times N clients) coalesces
// into a single sample instead of spawning ~8 subprocesses per request.
func (s *Server) dashboardData(ctx context.Context, isAdmin bool) dashboardVM {
	s.statsMu.Lock()
	defer s.statsMu.Unlock()
	if !s.statsAt.IsZero() && time.Since(s.statsAt) < 3*time.Second {
		vm := s.statsCache
		vm.IsAdmin = isAdmin
		return vm
	}
	vm := dashboardVM{
		Stats: system.Collect(),
		Services: system.InspectServices(ctx,
			s.cfg.ActiveWebService(), s.cfg.PHPFPMService, "mariadb", "firewalld"),
	}
	s.statsCache = vm
	s.statsAt = time.Now()
	vm.IsAdmin = isAdmin
	return vm
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
	docRoot := r.FormValue("doc_root")
	// Only an admin may aim a custom doc root outside this site's own tree.
	allowSharedRoot := u.Role == store.RoleAdmin
	site, err := s.domains.CreateSite(r.Context(), owner, domain, phpVersion, docRoot, allowSharedRoot)
	if err != nil {
		redirect(w, r, "/domains", "err", s.opErr(r, err))
		return
	}
	// One-form happy path: an optional GitHub URL creates, links and (for a
	// public repo) deploys in this single POST. A link failure never undoes the
	// created domain — it flashes with the card anchored so the user can retry.
	if repoURL := strings.TrimSpace(r.FormValue("repo_url")); repoURL != "" {
		repo, note, lerr := s.domains.LinkRepo(r.Context(), site.ID, repoURL, r.FormValue("repo_branch"))
		if lerr != nil {
			projectRedirect(w, r, site.ID, "err", "Domain "+domain+" created, but linking the repository failed: "+s.opErr(r, lerr))
			return
		}
		if repo.AuthMode == deploy.AuthPublic {
			s.domains.StartActivate(repo.ID)
			projectRedirect(w, r, site.ID, "msg", joinFlash("Domain "+domain+" created — deploying "+repo.Owner+"/"+repo.Name+"@"+repo.Branch+" now.", note))
			return
		}
		projectRedirect(w, r, site.ID, "msg", joinFlash("Domain "+domain+" created — one step left: add the deploy key on GitHub, then click Deploy.", note))
		return
	}
	projectRedirect(w, r, site.ID, "msg", "Domain "+domain+" created")
}

func (s *Server) postDeleteSite(w http.ResponseWriter, r *http.Request) {
	site, ok := s.authorizeSite(w, r)
	if !ok {
		return
	}
	if err := s.domains.DeleteSite(r.Context(), site.ID); err != nil {
		redirect(w, r, "/domains", "err", s.opErr(r, err))
		return
	}
	redirect(w, r, "/domains", "msg", site.Domain+" deleted")
}

func (s *Server) postChangePHP(w http.ResponseWriter, r *http.Request) {
	site, ok := s.authorizeSite(w, r)
	if !ok {
		return
	}
	version := r.FormValue("php_version")
	if err := s.domains.ChangePHP(r.Context(), site.ID, version); err != nil {
		s.backRedirect(w, r, "err", s.opErr(r, err))
		return
	}
	s.backRedirect(w, r, "msg", site.Domain+" switched to PHP "+version)
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
		s.backRedirect(w, r, "err", s.opErr(r, err))
		return
	}
	msg := "SSL enabled for " + site.Domain
	if !enable {
		msg = "SSL disabled for " + site.Domain
	}
	s.backRedirect(w, r, "msg", msg)
}

func (s *Server) postAddSubdomain(w http.ResponseWriter, r *http.Request) {
	site, ok := s.authorizeSite(w, r)
	if !ok {
		return
	}
	u := auth.UserFrom(r.Context())
	label := r.FormValue("label")
	docRoot := r.FormValue("doc_root")
	allowSharedRoot := u != nil && u.Role == store.RoleAdmin
	if _, err := s.domains.AddSubdomain(r.Context(), site.ID, label, docRoot, allowSharedRoot); err != nil {
		s.backRedirect(w, r, "err", s.opErr(r, err))
		return
	}
	s.backRedirect(w, r, "msg", "Subdomain "+label+"."+site.Domain+" created")
}

// postScanSites re-scans the host for pre-existing vhosts and imports new ones.
func (s *Server) postScanSites(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFrom(r.Context())
	if u == nil || u.Role != store.RoleAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	// An explicit re-scan re-discovers everything, including sites previously
	// forgotten from the panel.
	_ = s.store.ClearDismissals()
	n, err := s.domains.ImportExisting(r.Context())
	if err != nil {
		redirect(w, r, "/domains", "err", "Scan failed: "+err.Error())
		return
	}
	msg := "No new sites found"
	if n > 0 {
		msg = "Imported " + strconv.Itoa(n) + " existing site(s)"
	}
	redirect(w, r, "/domains", "msg", msg)
}

// postAdoptSite converts an imported site to fully managed.
func (s *Server) postAdoptSite(w http.ResponseWriter, r *http.Request) {
	site, ok := s.authorizeSite(w, r)
	if !ok {
		return
	}
	if err := s.domains.AdoptSite(r.Context(), site.ID, r.FormValue("php_version")); err != nil {
		s.backRedirect(w, r, "err", s.opErr(r, err))
		return
	}
	s.backRedirect(w, r, "msg", site.Domain+" adopted — now fully managed")
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
	tlsCert, _ := s.cfg.TLSOverride()
	certKind := "self-signed"
	if tlsCert != "" {
		if strings.Contains(tlsCert, "letsencrypt") {
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
			WebRoot: s.cfg.WebRoot, WebServer: s.cfg.WebServerName(), Dev: s.cfg.Dev,
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
	s.cfg.SetTLSOverride(certFile, keyFile, normHost)
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
	if target == s.cfg.WebServerName() {
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

// postRegenerate rebuilds every managed site's php-fpm pool + web config and
// reloads — the repair action for a partially-failed tenant upgrade (and a
// general "make the configs match the database again" button).
func (s *Server) postRegenerate(w http.ResponseWriter, r *http.Request) {
	if err := s.domains.RegenerateAll(r.Context()); err != nil {
		redirect(w, r, "/settings", "err", "Regenerate failed: "+s.opErr(r, err))
		return
	}
	redirect(w, r, "/settings", "msg", "All site configurations regenerated and reloaded")
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
		sep := "?"
		if strings.Contains(path, "?") { // path already carries a query (e.g. ?tab=ssl)
			sep = "&"
		}
		path += sep + kind + "=" + url.QueryEscape(msg)
	}
	http.Redirect(w, r, path, http.StatusSeeOther)
}
