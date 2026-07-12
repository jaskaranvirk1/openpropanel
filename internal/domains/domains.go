// Package domains is the orchestration layer that turns a high-level request
// ("add example.com for this user with PHP 8.3") into the concrete sequence of
// filesystem, PHP-FPM, Apache and SSL operations — with best-effort rollback if
// a step fails partway through.
package domains

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	osuser "os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/openpropanel/openpropanel/internal/config"
	"github.com/openpropanel/openpropanel/internal/deploy"
	"github.com/openpropanel/openpropanel/internal/mariadb"
	"github.com/openpropanel/openpropanel/internal/php"
	"github.com/openpropanel/openpropanel/internal/ssl"
	"github.com/openpropanel/openpropanel/internal/store"
	"github.com/openpropanel/openpropanel/internal/sysuser"
	"github.com/openpropanel/openpropanel/internal/system"
	"github.com/openpropanel/openpropanel/internal/vhostscan"
	"github.com/openpropanel/openpropanel/internal/webserver"
)

// Service coordinates the sub-systems needed to manage a site end-to-end. It
// holds both web-server backends and selects the active one per request, so an
// admin can switch between Apache and Nginx at runtime.
type Service struct {
	cfg       *config.Config
	cfgPath   string
	store     *store.Store
	apacheWeb webserver.Manager
	nginxWeb  webserver.Manager
	php       *php.Manager
	ssl       *ssl.Manager
	sysuser   *sysuser.Manager
	mariadb   *mariadb.Manager
	deploy    *deploy.Manager

	switchMu  sync.Mutex // serializes web-server switches
	accountMu sync.Mutex // serializes account deletion (last-admin guard)
	tenantMu  sync.Mutex // serializes JIT system-user provisioning (ensureTenant)

	jobMu sync.Mutex         // guards jobs
	jobs  map[int64]*repoJob // background clone/deploy jobs, keyed by PROJECT site ID
}

// repoJob tracks one project's in-flight background work. Jobs are keyed by
// project (not repo) because the contended resource is the project's checkout
// directory — an unlink+relink mints a new repo ID but reuses the same dir, and
// two concurrent git jobs there would corrupt it. next coalesces requests that
// arrive while a job is running into exactly one follow-up executing the MOST
// RECENT request (so a branch change arriving mid-deploy runs a full activate,
// not a re-deploy that cannot fetch the new branch).
type repoJob struct {
	running bool
	next    func(ctx context.Context)
}

// New wires the orchestrator.
func New(cfg *config.Config, cfgPath string, s *store.Store, apacheWeb, nginxWeb webserver.Manager, p *php.Manager, sl *ssl.Manager, su *sysuser.Manager, mdb *mariadb.Manager, dep *deploy.Manager) *Service {
	return &Service{cfg: cfg, cfgPath: cfgPath, store: s, apacheWeb: apacheWeb, nginxWeb: nginxWeb, php: p, ssl: sl, sysuser: su, mariadb: mdb, deploy: dep}
}

// web returns the active web-server manager based on the current config.
func (s *Service) web() webserver.Manager { return s.managerFor(s.cfg.WebServerName()) }

// managerFor returns the manager for a named web server.
func (s *Service) managerFor(target string) webserver.Manager {
	if target == "nginx" {
		return s.nginxWeb
	}
	return s.apacheWeb
}

// domainRe validates hostnames: lowercase labels of [a-z0-9-] separated by
// dots, no leading/trailing hyphen per label, at least two labels. This is the
// primary guard against path- and config-injection via the domain field.
var domainRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// labelRe validates a single subdomain label (no dots).
var labelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// errImportedReadOnly is returned when a config-mutating action is attempted on
// an imported (never-adopted) site. Such sites are read-only until adopted, so
// the panel never overwrites a config it did not create.
var errImportedReadOnly = errors.New("this site was imported from an existing config — adopt it first to manage it here")

// validImportDomain rejects discovered names that are not real, safe hostnames
// (bare IPs, wildcards, etc.) before they are recorded or used in file paths.
func validImportDomain(d string) bool {
	return domainRe.MatchString(d) && net.ParseIP(d) == nil
}

func distinctDomains(sites []vhostscan.Site) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range sites {
		if !seen[s.Domain] {
			seen[s.Domain] = true
			out = append(out, s.Domain)
		}
	}
	return out
}

// NormalizeDomain lower-cases and trims a domain and validates it.
func NormalizeDomain(d string) (string, error) {
	d = strings.TrimSpace(strings.ToLower(d))
	d = strings.TrimPrefix(d, "www.")
	if len(d) > 253 || !domainRe.MatchString(d) {
		return "", fmt.Errorf("invalid domain %q", d)
	}
	return d, nil
}

func (s *Service) docRootFor(domain string) string {
	return filepath.Join(s.cfg.WebRoot, domain, "public_html")
}

// CreateSite provisions a brand-new main domain for an owner. docRootArg is an
// optional custom document root; empty uses the default /var/www/<domain>/public_html.
// allowSharedRoot must be true only when the caller is an admin — it widens the
// custom doc root's allowed area from this site's own tree to the whole web root.
func (s *Service) CreateSite(ctx context.Context, ownerID int64, rawDomain, phpLabel, docRootArg string, allowSharedRoot bool) (*store.Site, error) {
	domain, err := NormalizeDomain(rawDomain)
	if err != nil {
		return nil, err
	}
	if _, err := s.store.SiteByDomain(domain); err == nil {
		return nil, fmt.Errorf("domain %q already exists", domain)
	}
	owner, err := s.store.UserByID(ownerID)
	if err != nil {
		return nil, errors.New("owner account not found")
	}
	// JIT-provision the owner's Linux system user so the new site's files and
	// pool are tenant-isolated from day one. Best-effort: a provisioning
	// failure degrades to today's behaviour (pool runs as the web-server user)
	// rather than blocking the domain.
	if warn, terr := s.ensureTenant(ctx, owner); terr != nil {
		log.Printf("create site %s: system-user provisioning failed (continuing without): %v", domain, terr)
	} else if warn != "" {
		log.Printf("create site %s: %s", domain, warn)
	}
	version, err := s.resolveVersion(phpLabel)
	if err != nil {
		return nil, err
	}

	docRoot := s.docRootFor(domain)
	external := false // operator supplied a custom path we must not seed over or delete
	if strings.TrimSpace(docRootArg) != "" {
		p, verr := s.validateDocRoot(docRootArg, owner, domain, allowSharedRoot)
		if verr != nil {
			return nil, verr
		}
		docRoot, external = p, true
	}
	if err := s.provisionDocRoot(docRoot, domain, owner.SystemUser, external); err != nil {
		return nil, err
	}

	site := &store.Site{
		UserID:     ownerID,
		Domain:     domain,
		Type:       store.SiteMain,
		DocRoot:    docRoot,
		PHPVersion: version.Label,
	}

	// Configure PHP-FPM pool, then Apache vhost.
	if err := s.php.ConfigureSite(ctx, site, version, owner.SystemUser); err != nil {
		s.rollbackFiles(domain, docRoot, external)
		return nil, fmt.Errorf("php-fpm: %w", err)
	}
	if err := s.renderVHost(site); err != nil {
		_ = s.php.RemoveSite(ctx, domain)
		s.rollbackFiles(domain, docRoot, external)
		return nil, fmt.Errorf("apache config: %w", err)
	}
	if err := s.web().Apply(ctx); err != nil {
		_ = s.web().Remove(domain)
		_ = s.php.RemoveSite(ctx, domain)
		s.rollbackFiles(domain, docRoot, external)
		return nil, fmt.Errorf("apache reload: %w", err)
	}

	created, err := s.store.CreateSite(site)
	if err != nil {
		_ = s.web().Remove(domain)
		_ = s.php.RemoveSite(ctx, domain)
		_ = s.web().Apply(ctx)
		s.rollbackFiles(domain, docRoot, external)
		return nil, err
	}
	return created, nil
}

// AddSubdomain creates <label>.<parentDomain> under an existing site. docRootArg
// is an optional custom document root; empty uses the default layout.
// allowSharedRoot must be true only for an admin caller (see CreateSite).
func (s *Service) AddSubdomain(ctx context.Context, parentID int64, label, docRootArg string, allowSharedRoot bool) (*store.Site, error) {
	label = strings.TrimSpace(strings.ToLower(label))
	if !labelRe.MatchString(label) {
		return nil, fmt.Errorf("invalid subdomain label %q", label)
	}
	parent, err := s.store.SiteByID(parentID)
	if err != nil {
		return nil, errors.New("parent site not found")
	}
	if parent.Source != store.SourceManaged {
		return nil, errImportedReadOnly
	}
	domain := label + "." + parent.Domain
	if _, err := s.store.SiteByDomain(domain); err == nil {
		return nil, fmt.Errorf("subdomain %q already exists", domain)
	}
	owner, err := s.store.UserByID(parent.UserID)
	if err != nil {
		return nil, errors.New("owner account not found")
	}
	version, err := s.resolveVersion(parent.PHPVersion)
	if err != nil {
		return nil, err
	}

	docRoot := s.docRootFor(domain)
	external := false // operator supplied a custom path we must not seed over or delete
	if strings.TrimSpace(docRootArg) != "" {
		p, verr := s.validateDocRoot(docRootArg, owner, domain, allowSharedRoot)
		if verr != nil {
			return nil, verr
		}
		docRoot, external = p, true
	}
	if err := s.provisionDocRoot(docRoot, domain, owner.SystemUser, external); err != nil {
		return nil, err
	}

	site := &store.Site{
		UserID:     parent.UserID,
		Domain:     domain,
		Type:       store.SiteSubdomain,
		ParentID:   sql.NullInt64{Int64: parent.ID, Valid: true},
		DocRoot:    docRoot,
		PHPVersion: version.Label,
	}
	if err := s.php.ConfigureSite(ctx, site, version, owner.SystemUser); err != nil {
		s.rollbackFiles(domain, docRoot, external)
		return nil, fmt.Errorf("php-fpm: %w", err)
	}
	if err := s.renderVHost(site); err != nil {
		_ = s.php.RemoveSite(ctx, domain)
		s.rollbackFiles(domain, docRoot, external)
		return nil, err
	}
	if err := s.web().Apply(ctx); err != nil {
		_ = s.web().Remove(domain)
		_ = s.php.RemoveSite(ctx, domain)
		s.rollbackFiles(domain, docRoot, external)
		return nil, err
	}
	created, err := s.store.CreateSite(site)
	if err != nil {
		// Roll back the live artifacts so we don't leave an orphaned subdomain
		// (vhost + pool) with no matching DB row — mirrors CreateSite.
		_ = s.web().Remove(domain)
		_ = s.php.RemoveSite(ctx, domain)
		_ = s.web().Apply(ctx)
		s.rollbackFiles(domain, docRoot, external)
		return nil, err
	}
	return created, nil
}

// DeleteAccount removes a hosting account after tearing down every one of its
// sites' server-side artifacts (Apache vhosts + php-fpm pools), so nothing is
// left running unmanaged on disk. The user's site/session rows cascade away
// when the account row is deleted. Its Linux system user is removed too, but
// only when no other account still references it (and its files are kept).
func (s *Service) DeleteAccount(ctx context.Context, userID int64) error {
	// Serialize deletions so the last-admin check and the delete are atomic
	// (two concurrent admin deletes can't both slip through).
	s.accountMu.Lock()
	defer s.accountMu.Unlock()

	acct, err := s.store.UserByID(userID)
	if err != nil {
		return err
	}
	if acct.Role == store.RoleAdmin {
		if n, err := s.store.CountAdmins(); err == nil && n <= 1 {
			return errors.New("cannot delete the last administrator account")
		}
	}
	sites, err := s.store.ListSitesByUser(userID)
	if err != nil {
		return err
	}
	for _, site := range sites {
		s.teardownArtifacts(ctx, site)
	}
	if err := s.web().Apply(ctx); err != nil {
		return err
	}
	// Drop the account's MariaDB databases and users BEFORE removing the panel
	// rows (which cascade-delete their records), so a deprovisioned tenant keeps
	// no live credentials or data. Best-effort per object.
	if dbs, e := s.store.ListDatabasesByUser(userID); e == nil {
		for _, d := range dbs {
			_ = s.mariadb.DropDatabase(ctx, d.Name)
		}
	}
	if dus, e := s.store.ListDBUsersByUser(userID); e == nil {
		for _, du := range dus {
			_ = s.mariadb.DropUser(ctx, du.Name)
		}
	}
	if err := s.store.DeleteUser(userID); err != nil {
		return err
	}
	if acct.SystemUser != "" {
		if n, err := s.store.CountBySystemUser(acct.SystemUser); err == nil && n == 0 {
			_ = s.sysuser.Remove(ctx, acct.SystemUser)
		}
	}
	return nil
}

// DeleteSite tears down a managed site and all of its subdomains. An imported
// (never-adopted) site is only forgotten from the panel — its original config
// and files are left untouched — and a dismissal is recorded so startup
// discovery does not resurrect it.
func (s *Service) DeleteSite(ctx context.Context, id int64) error {
	site, err := s.store.SiteByID(id)
	if err != nil {
		return err
	}
	if site.Source != store.SourceManaged {
		_ = s.store.DismissImport(site.Domain)
		return s.store.DeleteSite(id)
	}
	// Remove subdomains' server-side artefacts first (DB rows cascade). If we
	// cannot enumerate them, abort rather than leaving orphaned live vhosts.
	if site.Type == store.SiteMain {
		subs, err := s.store.ListSubdomains(id)
		if err != nil {
			return err
		}
		for _, sub := range subs {
			s.teardownArtifacts(ctx, sub)
		}
	}
	s.teardownArtifacts(ctx, site)
	if err := s.web().Apply(ctx); err != nil {
		return err
	}
	return s.store.DeleteSite(id)
}

// EnableSSL requests a certificate and switches the site to HTTPS.
func (s *Service) EnableSSL(ctx context.Context, id int64) error {
	site, err := s.store.SiteByID(id)
	if err != nil {
		return err
	}
	if site.Source != store.SourceManaged {
		return errImportedReadOnly
	}
	var alts []string
	if site.Type == store.SiteMain {
		alts = append(alts, "www."+site.Domain)
	}
	if err := s.ssl.Issue(ctx, site.Domain, alts, site.DocRoot); err != nil {
		return fmt.Errorf("certificate issuance failed: %w", err)
	}
	site.SSLEnabled = true
	// certbot issued a Let's Encrypt cert, so the panel now owns it: clear any
	// custom cert paths (e.g. inherited from adoption) and fall back to the
	// panel-managed LE paths in renderVHost.
	site.CertFile, site.KeyFile = "", ""
	if err := s.renderVHost(site); err != nil {
		return err
	}
	if err := s.web().Apply(ctx); err != nil {
		return err
	}
	if err := s.store.SetSiteCerts(id, "", ""); err != nil {
		return err
	}
	return s.store.SetSiteSSL(id, true)
}

// DisableSSL reverts a site to plain HTTP (the certificate is left on disk).
func (s *Service) DisableSSL(ctx context.Context, id int64) error {
	site, err := s.store.SiteByID(id)
	if err != nil {
		return err
	}
	if site.Source != store.SourceManaged {
		return errImportedReadOnly
	}
	site.SSLEnabled = false
	if err := s.renderVHost(site); err != nil {
		return err
	}
	if err := s.web().Apply(ctx); err != nil {
		return err
	}
	return s.store.SetSiteSSL(id, false)
}

// ChangePHP switches a site to a different PHP version.
func (s *Service) ChangePHP(ctx context.Context, id int64, phpLabel string) error {
	site, err := s.store.SiteByID(id)
	if err != nil {
		return err
	}
	if site.Source != store.SourceManaged {
		return errImportedReadOnly
	}
	version, err := s.resolveVersion(phpLabel)
	if err != nil {
		return err
	}
	owner, err := s.store.UserByID(site.UserID)
	if err != nil {
		return errors.New("owner account not found")
	}
	if err := s.php.ConfigureSite(ctx, site, version, owner.SystemUser); err != nil {
		return err
	}
	site.PHPVersion = version.Label
	if err := s.renderVHost(site); err != nil {
		return err
	}
	if err := s.web().Apply(ctx); err != nil {
		return err
	}
	return s.store.UpdateSitePHP(id, version.Label)
}

// IssuePanelCert obtains a Let's Encrypt certificate for the panel's OWN
// hostname and returns the issued cert/key paths plus the normalised host. It
// publishes a temporary Apache :80 vhost to answer the HTTP-01 challenge, so
// Apache must be running and the hostname must resolve to this server with port
// 80 reachable from the internet.
func (s *Service) IssuePanelCert(ctx context.Context, rawHost string) (certFile, keyFile, host string, err error) {
	if s.cfg.Dev {
		return "", "", "", errors.New("Let's Encrypt is unavailable in dev mode (it needs a public server)")
	}
	host, err = NormalizeDomain(rawHost)
	if err != nil {
		return "", "", "", err
	}
	// The HTTP-01 challenge file must be readable by the WEB-SERVER user (Apache/
	// nginx), which fetches it for the ACME CA. The data dir is deliberately
	// root-only (0700 — it holds the session key, SQLite store and TLS keys), so
	// serving the challenge from there makes the web server return 403 (and on
	// SELinux hosts /var/lib content is not httpd-readable at all). Serve it from
	// under the web root instead — world-traversable and httpd_sys_content_t —
	// exactly like the per-site SSL path that already works.
	webroot := filepath.Join(s.cfg.WebRoot, "openpropanel-acme")
	if err = os.MkdirAll(filepath.Join(webroot, ".well-known", "acme-challenge"), 0o755); err != nil {
		return "", "", "", err
	}
	// MkdirAll honours the process umask, which can strip the o+rx the web server
	// needs to traverse in; force the public, traversable bits on the tree.
	_ = os.Chmod(webroot, 0o755)
	_ = os.Chmod(filepath.Join(webroot, ".well-known"), 0o755)
	_ = os.Chmod(filepath.Join(webroot, ".well-known", "acme-challenge"), 0o755)
	if err = s.web().WritePanelChallengeVHost(host, webroot); err != nil {
		return "", "", "", err
	}
	if err = s.web().Apply(ctx); err != nil {
		return "", "", "", fmt.Errorf("apache reload for challenge vhost: %w", err)
	}
	if err = s.ssl.Issue(ctx, host, nil, webroot); err != nil {
		return "", "", "", err
	}
	certFile, keyFile = s.ssl.CertPaths(host)
	return certFile, keyFile, host, nil
}

// reprovisionSite regenerates BOTH a site's php-fpm pool (so the socket owner
// matches the active web server) and its web-server config. Used when switching
// web servers, where the php-fpm socket ownership must follow the new server.
func (s *Service) reprovisionSite(ctx context.Context, site *store.Site) error {
	owner, err := s.store.UserByID(site.UserID)
	if err != nil {
		return err
	}
	version, err := s.resolveVersion(site.PHPVersion)
	if err != nil {
		return err
	}
	if err := s.php.ConfigureSite(ctx, site, version, owner.SystemUser); err != nil {
		return err
	}
	return s.renderVHost(site)
}

// RegenerateAll reprovisions every site (php pool + web config) for the
// currently-active web server and applies it.
func (s *Service) RegenerateAll(ctx context.Context) error {
	// Pool files + cfg.WebServer are shared with server switches, adoption and
	// tenant upgrades; regenerating mid-switch would write pools for a server
	// that is not running yet.
	s.switchMu.Lock()
	defer s.switchMu.Unlock()

	sites, err := s.store.ListSites()
	if err != nil {
		return err
	}
	for _, site := range sites {
		if site.Source != store.SourceManaged {
			continue // imported sites are read-only until adopted
		}
		if err := s.reprovisionSite(ctx, site); err != nil {
			return err
		}
	}
	return s.web().Apply(ctx)
}

// reprovisionPHP regenerates ONLY a site's php-fpm pool, so its socket owner
// matches the active web server. Used during a switch, after the new server is
// running.
func (s *Service) reprovisionPHP(ctx context.Context, site *store.Site) error {
	owner, err := s.store.UserByID(site.UserID)
	if err != nil {
		return err
	}
	version, err := s.resolveVersion(site.PHPVersion)
	if err != nil {
		return err
	}
	return s.php.ConfigureSite(ctx, site, version, owner.SystemUser)
}

// SwitchWebServer changes the active web server safely. The ordering matters:
// the old server and its php-fpm sockets stay untouched until the new config is
// validated and the services are swapped, so any failure up to that point is
// fully recoverable by restarting the old server. Only once the new server is
// running are the php-fpm sockets re-owned to it.
func (s *Service) SwitchWebServer(ctx context.Context, target string) error {
	if target != "apache" && target != "nginx" {
		return fmt.Errorf("unknown web server %q", target)
	}
	s.switchMu.Lock()
	defer s.switchMu.Unlock()

	oldTarget := s.cfg.WebServerName()
	if target == oldTarget {
		return nil
	}
	oldService := s.cfg.ActiveWebService()
	s.cfg.SetWebServer(target)
	newService := s.cfg.ActiveWebService()

	sites, err := s.store.ListSites()
	if err != nil {
		s.cfg.SetWebServer(oldTarget)
		return err
	}

	// 1. Write the new server's site configs (managed sites only — imported
	//    ones are never rewritten). This touches neither the running old server
	//    nor any php-fpm socket, so the old server keeps serving.
	for _, site := range sites {
		if site.Source != store.SourceManaged {
			continue
		}
		if err := s.renderVHost(site); err != nil {
			s.cfg.SetWebServer(oldTarget)
			return err
		}
	}
	// 2. Validate before touching any service; a failure here is a clean no-op.
	if _, err := s.web().Validate(ctx); err != nil {
		s.cfg.SetWebServer(oldTarget)
		return fmt.Errorf("generated %s configuration is invalid: %w", target, err)
	}
	// 3. Swap services. Up to here the old server + sockets are intact, so a
	//    start failure is recovered by simply restarting the old server.
	if !s.cfg.Dev && oldService != newService {
		_ = system.ServiceAction(ctx, "stop", oldService)
		_ = system.ServiceAction(ctx, "disable", oldService)
		_ = system.ServiceAction(ctx, "enable", newService)
		if err := system.ServiceAction(ctx, "start", newService); err != nil {
			s.cfg.SetWebServer(oldTarget)
			_ = system.ServiceAction(ctx, "enable", oldService)
			_ = system.ServiceAction(ctx, "start", oldService)
			return fmt.Errorf("failed to start %s (reverted to %s): %w", newService, oldTarget, err)
		}
	}
	// 4. Persist the switch now that services agree, so on-disk config never
	//    disagrees with what is running.
	if err := s.cfg.Save(s.cfgPath); err != nil {
		return fmt.Errorf("switched to %s but failed to persist config: %w", target, err)
	}
	// 5. The new server is live — hand each php-fpm socket to its user. (A brief
	//    PHP blip during this manual cutover is expected.)
	var reErr error
	for _, site := range sites {
		if site.Source != store.SourceManaged {
			continue
		}
		if err := s.reprovisionPHP(ctx, site); err != nil {
			reErr = err
		}
	}
	// 6. Remove the now-inactive server's stale per-site configs (managed only —
	//    never delete a config the panel did not create).
	for _, site := range sites {
		if site.Source != store.SourceManaged {
			continue
		}
		_ = s.managerFor(oldTarget).Remove(site.Domain)
	}
	if err := s.web().Reload(ctx); err != nil {
		return err
	}
	if reErr != nil {
		return fmt.Errorf("switched to %s but some php-fpm pools failed to reprovision: %w", target, reErr)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Import / adopt existing (pre-existing, non-managed) sites
// ---------------------------------------------------------------------------

// ImportExisting discovers virtual hosts already present on the host that Open
// ProPanel did not create, and registers new ones as "imported" sites owned by
// the first admin. It never edits the discovered configs. Returns the count of
// newly imported sites.
func (s *Service) ImportExisting(ctx context.Context) (int, error) {
	admin, err := s.store.FirstAdmin()
	if err != nil {
		return 0, err
	}
	var found []vhostscan.Site
	if s.cfg.UseNginx() {
		found, err = vhostscan.Nginx(s.cfg.NginxVhostDir)
	} else {
		found, err = vhostscan.Apache(s.cfg.ApacheVhostDir)
	}
	if err != nil {
		return 0, err
	}
	dismissed, _ := s.store.DismissedImports()

	// Filter to importable, not-yet-tracked candidates.
	var candidates []vhostscan.Site
	for _, d := range found {
		if d.Managed || !validImportDomain(d.Domain) || dismissed[d.Domain] {
			continue
		}
		if _, err := s.store.SiteByDomain(d.Domain); err == nil {
			continue // already tracked
		}
		candidates = append(candidates, d)
	}

	// Universe of possible parents = every existing site + every candidate, so a
	// discovered subdomain (api.example.com) can be grouped under its parent
	// (example.com) whether the parent is already tracked or in this same batch.
	universe := map[string]bool{}
	if existing, e := s.store.ListSites(); e == nil {
		for _, st := range existing {
			universe[st.Domain] = true
		}
	}
	for _, d := range candidates {
		universe[d.Domain] = true
	}

	n := 0
	create := func(d vhostscan.Site, typ string, parent sql.NullInt64) {
		if _, err := s.store.CreateSite(&store.Site{
			UserID: admin.ID, Domain: d.Domain, Type: typ, ParentID: parent,
			DocRoot: d.DocRoot, SSLEnabled: d.SSL, CertFile: d.CertFile, KeyFile: d.KeyFile,
			Source: store.SourceImported, ConfFile: d.File,
		}); err == nil {
			n++
		}
	}
	// Pass 1: import parents (mains) first so their rows exist to link against.
	for _, d := range candidates {
		if parentDomainIn(d.Domain, universe) == "" {
			create(d, store.SiteMain, sql.NullInt64{})
		}
	}
	// Pass 2: import subdomains linked to their parent (falling back to a flat
	// main only if the parent turns out not to be tracked).
	for _, d := range candidates {
		pd := parentDomainIn(d.Domain, universe)
		if pd == "" {
			continue
		}
		if parent, perr := s.store.SiteByDomain(pd); perr == nil {
			create(d, store.SiteSubdomain, sql.NullInt64{Int64: parent.ID, Valid: true})
		} else {
			create(d, store.SiteMain, sql.NullInt64{})
		}
	}

	// Relink: an existing IMPORTED main that is really a subdomain of another
	// site (e.g. imported before its parent, or from an older version) is grouped
	// under that parent. Only imported rows are touched — managed vhosts aren't.
	if existing, e := s.store.ListSites(); e == nil {
		for _, st := range existing {
			if st.Source != store.SourceImported || st.Type != store.SiteMain {
				continue
			}
			pd := parentDomainIn(st.Domain, universe)
			if pd == "" {
				continue
			}
			if parent, perr := s.store.SiteByDomain(pd); perr == nil && parent.ID != st.ID {
				_ = s.store.SetSiteParent(st.ID, parent.ID)
			}
		}
	}

	// Prune: drop IMPORTED sites whose backing vhost has disappeared from disk
	// (e.g. the operator deleted the .conf and reloaded). Only imported rows are
	// removed — never managed/adopted sites the panel is responsible for. A
	// still-present child cascaded away by pruning its parent is re-imported on
	// the next scan.
	onDisk := map[string]bool{}
	for _, d := range found {
		onDisk[d.Domain] = true
	}
	if existing, e := s.store.ListSites(); e == nil {
		for _, st := range existing {
			if st.Source == store.SourceImported && !onDisk[st.Domain] {
				_ = s.store.DeleteSite(st.ID)
			}
		}
	}
	return n, nil
}

// parentDomainIn returns the longest domain in universe that is a strict parent
// suffix of d (d == "<label>." + parent), or "" if none. It is what groups
// subdomains under their parent project on import.
func parentDomainIn(d string, universe map[string]bool) string {
	best := ""
	for p := range universe {
		if p != d && strings.HasSuffix(d, "."+p) && len(p) > len(best) {
			best = p
		}
	}
	return best
}

// AdoptSite converts an imported site to fully-managed. It generates an Open
// ProPanel vhost + php-fpm pool pointing at the SAME document root, disables the
// original config (renamed to *.disabled-by-openpropanel, which doubles as a
// backup), validates, and reloads. On any validation failure it rolls back so
// the previously-running config is restored untouched.
func (s *Service) AdoptSite(ctx context.Context, id int64, phpLabel string) error {
	// Serialize against web-server switches, bulk regeneration and other adopts,
	// which share the same config paths and cfg.WebServer.
	s.switchMu.Lock()
	defer s.switchMu.Unlock()

	site, err := s.store.SiteByID(id)
	if err != nil {
		return err
	}
	if site.Source != store.SourceImported {
		return errors.New("site is already managed")
	}
	version, err := s.resolveVersion(phpLabel)
	if err != nil {
		return err
	}

	nginx := s.cfg.UseNginx()
	vhostDir := s.cfg.ApacheVhostDir
	if nginx {
		vhostDir = s.cfg.NginxVhostDir
	}
	orig := site.ConfFile
	target := s.web().ConfPath(site.Domain)

	// Collect every config file that defines this domain. certbot's Apache
	// plugin splits a site across <domain>.conf and <domain>-le-ssl.conf, so
	// "multiple files" is normal — we back them ALL up rather than refusing. A
	// single file that ALSO defines other sites is still unsafe to auto-split.
	var origFiles []string
	if orig != "" {
		origFiles = vhostscan.FilesForDomain(vhostDir, nginx, site.Domain)
		if len(origFiles) == 0 {
			origFiles = []string{orig}
		}
		for _, f := range origFiles {
			if len(distinctDomains(vhostscan.ParseFile(f, nginx))) > 1 {
				return fmt.Errorf("%s shares %s with other sites — split them into separate files before adopting", site.Domain, filepath.Base(f))
			}
		}
	}

	targetBackup, wrote := "", false
	var disabled [][2]string // {backupPath, originalPath}
	restore := func() {
		if wrote {
			_ = os.Remove(target)
		}
		if targetBackup != "" {
			_ = os.Rename(targetBackup, target)
		}
		for _, d := range disabled {
			_ = os.Rename(d[0], d[1])
		}
		_ = s.php.RemoveSite(ctx, site.Domain)
		_ = s.web().Reload(ctx)
	}

	// Disable (and thereby back up) every original config file for this domain.
	for _, f := range origFiles {
		if _, serr := os.Stat(f); serr != nil {
			continue
		}
		bak := f + ".disabled-by-openpropanel"
		if rerr := os.Rename(f, bak); rerr != nil {
			restore()
			return fmt.Errorf("could not back up the original config %s: %w", f, rerr)
		}
		disabled = append(disabled, [2]string{bak, f})
	}
	// Back up any UNRELATED file already occupying our target path.
	if target != orig {
		if _, serr := os.Stat(target); serr == nil {
			bak := target + ".pre-openpropanel.bak"
			if rerr := os.Rename(target, bak); rerr != nil {
				restore()
				return fmt.Errorf("could not back up existing file at %s: %w", target, rerr)
			}
			targetBackup = bak
		}
	}

	site.Source = store.SourceManaged
	site.PHPVersion = version.Label
	// Imported sites have no dedicated system user, so the pool runs as the
	// web-server user (empty systemUser).
	if err := s.php.ConfigureSite(ctx, site, version, ""); err != nil {
		restore()
		return fmt.Errorf("php-fpm: %w", err)
	}
	if err := s.renderVHost(site); err != nil {
		restore()
		return err
	}
	wrote = true
	if _, err := s.web().Validate(ctx); err != nil {
		restore()
		return fmt.Errorf("generated config was invalid, reverted to the original: %w", err)
	}
	if err := s.web().Reload(ctx); err != nil {
		restore()
		return err
	}
	return s.store.MarkSiteManaged(id, version.Label)
}

// ---------------------------------------------------------------------------
// internal helpers
// ---------------------------------------------------------------------------

// renderVHost writes the Apache config reflecting the site's current state.
func (s *Service) renderVHost(site *store.Site) error {
	// Defence in depth: the doc root is interpolated verbatim into the
	// (unescaped) vhost the panel reloads as root. Every caller should already
	// have validated it, but refuse outright if a config metacharacter ever
	// reaches here — including the one externally-sourced path, an adopted
	// site's scanned-from-disk doc root.
	if !safeVHostPath(site.DocRoot) {
		return fmt.Errorf("document root %q contains characters that are not allowed in a vhost", site.DocRoot)
	}
	vh := webserver.VHost{
		Domain:    site.Domain,
		DocRoot:   site.DocRoot,
		PHPSocket: s.php.SocketPath(site.Domain),
		SSL:       site.SSLEnabled,
		Mode:      site.WebMode,
	}
	if vh.Mode == "" {
		vh.Mode = store.WebModePHP
	}
	if site.Type == store.SiteMain {
		vh.ServerAlias = "www." + site.Domain
	}
	if site.SSLEnabled {
		// Preserve a custom certificate (e.g. an adopted site using its own cert)
		// rather than forcing the panel's Let's Encrypt paths, which may not exist.
		if site.CertFile != "" && site.KeyFile != "" {
			vh.CertFile, vh.KeyFile = site.CertFile, site.KeyFile
		} else {
			vh.CertFile, vh.KeyFile = s.ssl.CertPaths(site.Domain)
		}
	}
	return s.web().Write(vh)
}

func (s *Service) teardownArtifacts(ctx context.Context, site *store.Site) {
	if site.Source != store.SourceManaged {
		return // never remove a config/pool the panel did not create
	}
	_ = s.web().Remove(site.Domain)
	_ = s.php.RemoveSite(ctx, site.Domain)
	// Document root is deliberately left in place so user data is never
	// destroyed automatically; operators can remove it manually.
}

func (s *Service) resolveVersion(label string) (php.Version, error) {
	versions := s.php.DetectVersions()
	if len(versions) == 0 {
		return php.Version{}, errors.New("no PHP-FPM versions detected on this host")
	}
	if label == "" {
		return versions[0], nil
	}
	if v, ok := s.php.FindVersion(label); ok {
		return v, nil
	}
	return php.Version{}, fmt.Errorf("PHP version %q is not installed", label)
}

// provisionDocRoot ensures the document root and its ACME challenge dir exist.
// For the DEFAULT layout it also seeds a landing page and hands ownership to the
// tenant. For an EXTERNAL (operator-supplied) root it does neither: it must not
// drop files into — or chown — a folder that may already hold the site's own
// content (or that is about to receive a git checkout).
func (s *Service) provisionDocRoot(docRoot, domain, systemUser string, external bool) error {
	if err := os.MkdirAll(docRoot, 0o755); err != nil {
		return err
	}
	// ACME challenge directory so certbot webroot mode works out of the box.
	// Additive (a subdir) — safe even inside an existing doc root.
	if err := os.MkdirAll(filepath.Join(docRoot, ".well-known", "acme-challenge"), 0o755); err != nil {
		return err
	}
	if external {
		return nil
	}
	index := filepath.Join(docRoot, "index.html")
	if _, err := os.Stat(index); os.IsNotExist(err) {
		_ = os.WriteFile(index, landingPage(domain), 0o644)
	}
	if !s.cfg.Dev && systemUser != "" {
		s.chown(docRoot, systemUser)
	}
	return nil
}

// validateDocRoot vets a caller-supplied document root. It must be an absolute
// path, free of characters that could break out of the generated vhost, and
// contained within an allowed base with no symlink escape. The returned path is
// interpolated verbatim into the Apache/Nginx config the panel reloads as root,
// so both the character check and the containment check are security-critical.
//
// Containment is scoped by trust: a non-admin caller (allowShared=false) may
// only point a doc root at THIS site's own tree (/var/www/<domain>) or the
// owner's home directory, so a tenant can never aim it into another tenant's
// directory or at the shared web root itself. Admins (allowShared=true) may use
// the whole web root. Returns the cleaned, resolved path.
func (s *Service) validateDocRoot(raw string, owner *store.User, domain string, allowShared bool) (string, error) {
	p := filepath.Clean(strings.TrimSpace(raw))
	if !filepath.IsAbs(p) {
		return "", errors.New("document root must be an absolute path")
	}
	if !safeVHostPath(p) {
		return "", errors.New("document root contains characters that are not allowed in a path")
	}
	var bases []string
	if allowShared {
		bases = append(bases, filepath.Clean(s.cfg.WebRoot))
	} else if domain != "" {
		// A non-admin is confined to this specific site's own directory tree.
		bases = append(bases, filepath.Clean(filepath.Join(s.cfg.WebRoot, domain)))
	}
	if owner != nil && owner.SystemUser != "" {
		if u, err := osuser.Lookup(owner.SystemUser); err == nil && u.HomeDir != "" {
			bases = append(bases, filepath.Clean(u.HomeDir))
		}
	}
	if len(bases) == 0 {
		return "", errors.New("no permitted location for a custom document root")
	}
	within := func(base, path string) bool {
		return path == base || strings.HasPrefix(path, base+string(os.PathSeparator))
	}
	contained := func(path string) bool {
		for _, b := range bases {
			if within(b, path) {
				return true
			}
		}
		return false
	}
	if !contained(p) {
		return "", fmt.Errorf("document root must be inside %s", strings.Join(bases, " or "))
	}
	// If the path already exists, resolve symlinks and re-check so a symlink
	// cannot point the doc root outside the allowed area.
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		okResolved := false
		for _, b := range bases {
			rb, e := filepath.EvalSymlinks(b)
			if e != nil {
				rb = b
			}
			if within(rb, resolved) {
				okResolved = true
				break
			}
		}
		if !okResolved {
			return "", errors.New("document root resolves outside the allowed area (symlink)")
		}
		// Re-check the RESOLVED path: EvalSymlinks can introduce on-disk
		// directory names the tenant controls (e.g. a symlink whose target is
		// named `x;autoindex on`), laundering a config metacharacter past the
		// raw-input check and into the unescaped vhost.
		if !safeVHostPath(resolved) {
			return "", errors.New("document root resolves to a path with characters that are not allowed")
		}
		p = resolved
	}
	return p, nil
}

// SafeDocRoot returns the site's document root, resolved through symlinks, after
// re-checking (for a non-admin caller — trusted=false) that it still lies inside
// the owner's permitted area. This guards the file manager against a TOCTOU:
// site.DocRoot may sit in a tenant-writable location (the owner's home, or their
// git checkout) that the tenant can swap for a symlink into another tenant's
// tree AFTER the site was created — a creation-time check alone cannot catch it,
// and os.OpenRoot follows symlinks in the root path itself. Admin callers
// (trusted=true) are unrestricted, matching validateDocRoot's allowShared model.
func (s *Service) SafeDocRoot(site *store.Site, trusted bool) (string, error) {
	if site == nil {
		return "", errors.New("no site")
	}
	if trusted {
		return site.DocRoot, nil
	}
	resolved, err := filepath.EvalSymlinks(site.DocRoot)
	if err != nil {
		return "", fmt.Errorf("cannot resolve document root: %w", err)
	}
	bases := []string{filepath.Join(s.cfg.WebRoot, site.Domain)}
	if s.store != nil {
		if owner, oerr := s.store.UserByID(site.UserID); oerr == nil && owner.SystemUser != "" {
			if u, uerr := osuser.Lookup(owner.SystemUser); uerr == nil && u.HomeDir != "" {
				bases = append(bases, u.HomeDir)
			}
		}
	}
	for _, b := range bases {
		rb, e := filepath.EvalSymlinks(b)
		if e != nil {
			rb = filepath.Clean(b)
		}
		if resolved == rb || strings.HasPrefix(resolved, rb+string(os.PathSeparator)) {
			return resolved, nil
		}
	}
	return "", errors.New("document root is outside the permitted area")
}

// safeVHostPath reports whether a filesystem path is safe to interpolate
// verbatim into an Apache/Nginx vhost directive. The vhost templates are
// text/template (no escaping), so a document root containing a newline or a
// config metacharacter could inject arbitrary directives that the panel then
// reloads as root. We reject control characters and the shell/config
// metacharacters that can break out of `root <X>;` or `<Directory "<X>">`.
// Path separators, drive colons, dots, dashes, underscores and spaces stay
// allowed so ordinary (including Windows dev) paths pass. ToSlash first so a
// literal backslash is rejected on Linux while the Windows separator is not.
func safeVHostPath(p string) bool {
	for _, r := range filepath.ToSlash(p) {
		if r < 0x20 || r == 0x7f {
			return false
		}
		switch r {
		case '\\', '"', '\'', '`', ';', '{', '}', '#', '<', '>', '|', '*', '?', '$':
			return false
		}
	}
	return true
}

func (s *Service) chown(path, systemUser string) {
	u, err := osuser.Lookup(systemUser)
	if err != nil {
		return
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		return
	}
	// Recursively hand ownership of the whole doc root (including the seeded
	// index and the acme-challenge dir) to the site user. Best-effort: skip
	// entries we cannot read rather than aborting.
	_ = filepath.WalkDir(path, func(p string, _ os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		_ = os.Lchown(p, uid, gid)
		return nil
	})
}

func (s *Service) rollbackFiles(domain, docRoot string, external bool) {
	_ = s.web().Remove(domain)
	// NEVER delete an operator-supplied (external) doc root — it may hold the
	// site's real files or a git checkout. Only the default, freshly-created
	// /var/www/<domain>/public_html layout is safe to remove on rollback.
	if external {
		return
	}
	if isFreshDocRoot(docRoot) {
		_ = os.RemoveAll(filepath.Dir(docRoot)) // remove /var/www/<domain>
	}
}

func isFreshDocRoot(docRoot string) bool {
	entries, err := os.ReadDir(docRoot)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.Name() != "index.html" && e.Name() != ".well-known" {
			return false
		}
	}
	return true
}

func landingPage(domain string) []byte {
	return []byte(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>` + domain + `</title>
  <style>
    body{font-family:system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;margin:0;background:#0b0f17;color:#e5e7eb}
    .card{text-align:center;padding:2rem}
    h1{font-weight:600;margin:.5rem 0}
    p{color:#9ca3af}
    code{background:#111827;padding:.15rem .4rem;border-radius:.35rem}
  </style>
</head>
<body>
  <div class="card">
    <h1>` + domain + ` is live 🎉</h1>
    <p>This site was provisioned by <strong>Open ProPanel</strong>.</p>
    <p>Upload your files to <code>` + domain + `/public_html</code>.</p>
  </div>
</body>
</html>
`)
}
