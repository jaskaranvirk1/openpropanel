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
	"os"
	osuser "os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/openpropanel/openpropanel/internal/config"
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

	switchMu sync.Mutex // serializes web-server switches
}

// New wires the orchestrator.
func New(cfg *config.Config, cfgPath string, s *store.Store, apacheWeb, nginxWeb webserver.Manager, p *php.Manager, sl *ssl.Manager, su *sysuser.Manager) *Service {
	return &Service{cfg: cfg, cfgPath: cfgPath, store: s, apacheWeb: apacheWeb, nginxWeb: nginxWeb, php: p, ssl: sl, sysuser: su}
}

// web returns the active web-server manager based on the current config.
func (s *Service) web() webserver.Manager { return s.managerFor(s.cfg.WebServer) }

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

// CreateSite provisions a brand-new main domain for an owner.
func (s *Service) CreateSite(ctx context.Context, ownerID int64, rawDomain, phpLabel string) (*store.Site, error) {
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
	version, err := s.resolveVersion(phpLabel)
	if err != nil {
		return nil, err
	}

	docRoot := s.docRootFor(domain)
	if err := s.provisionDocRoot(docRoot, domain, owner.SystemUser); err != nil {
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
		s.rollbackFiles(domain, docRoot)
		return nil, fmt.Errorf("php-fpm: %w", err)
	}
	if err := s.renderVHost(site); err != nil {
		_ = s.php.RemoveSite(ctx, domain)
		s.rollbackFiles(domain, docRoot)
		return nil, fmt.Errorf("apache config: %w", err)
	}
	if err := s.web().Apply(ctx); err != nil {
		_ = s.web().Remove(domain)
		_ = s.php.RemoveSite(ctx, domain)
		s.rollbackFiles(domain, docRoot)
		return nil, fmt.Errorf("apache reload: %w", err)
	}

	created, err := s.store.CreateSite(site)
	if err != nil {
		_ = s.web().Remove(domain)
		_ = s.php.RemoveSite(ctx, domain)
		_ = s.web().Apply(ctx)
		s.rollbackFiles(domain, docRoot)
		return nil, err
	}
	return created, nil
}

// AddSubdomain creates <label>.<parentDomain> under an existing site.
func (s *Service) AddSubdomain(ctx context.Context, parentID int64, label string) (*store.Site, error) {
	label = strings.TrimSpace(strings.ToLower(label))
	if !labelRe.MatchString(label) {
		return nil, fmt.Errorf("invalid subdomain label %q", label)
	}
	parent, err := s.store.SiteByID(parentID)
	if err != nil {
		return nil, errors.New("parent site not found")
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
	if err := s.provisionDocRoot(docRoot, domain, owner.SystemUser); err != nil {
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
		s.rollbackFiles(domain, docRoot)
		return nil, fmt.Errorf("php-fpm: %w", err)
	}
	if err := s.renderVHost(site); err != nil {
		_ = s.php.RemoveSite(ctx, domain)
		s.rollbackFiles(domain, docRoot)
		return nil, err
	}
	if err := s.web().Apply(ctx); err != nil {
		_ = s.web().Remove(domain)
		_ = s.php.RemoveSite(ctx, domain)
		s.rollbackFiles(domain, docRoot)
		return nil, err
	}
	created, err := s.store.CreateSite(site)
	if err != nil {
		// Roll back the live artifacts so we don't leave an orphaned subdomain
		// (vhost + pool) with no matching DB row — mirrors CreateSite.
		_ = s.web().Remove(domain)
		_ = s.php.RemoveSite(ctx, domain)
		_ = s.web().Apply(ctx)
		s.rollbackFiles(domain, docRoot)
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
	acct, err := s.store.UserByID(userID)
	if err != nil {
		return err
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

// DeleteSite tears down a site and all of its subdomains.
func (s *Service) DeleteSite(ctx context.Context, id int64) error {
	site, err := s.store.SiteByID(id)
	if err != nil {
		return err
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
	var alts []string
	if site.Type == store.SiteMain {
		alts = append(alts, "www."+site.Domain)
	}
	if err := s.ssl.Issue(ctx, site.Domain, alts, site.DocRoot); err != nil {
		return fmt.Errorf("certificate issuance failed: %w", err)
	}
	site.SSLEnabled = true
	if err := s.renderVHost(site); err != nil {
		return err
	}
	if err := s.web().Apply(ctx); err != nil {
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
	webroot := filepath.Join(s.cfg.DataDir, "acme-webroot")
	if err = os.MkdirAll(filepath.Join(webroot, ".well-known", "acme-challenge"), 0o755); err != nil {
		return "", "", "", err
	}
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
	sites, err := s.store.ListSites()
	if err != nil {
		return err
	}
	for _, site := range sites {
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

	oldTarget := s.cfg.WebServer
	if target == oldTarget {
		return nil
	}
	oldService := s.cfg.ActiveWebService()
	s.cfg.WebServer = target
	newService := s.cfg.ActiveWebService()

	sites, err := s.store.ListSites()
	if err != nil {
		s.cfg.WebServer = oldTarget
		return err
	}

	// 1. Write the new server's site configs. This touches neither the running
	//    old server nor any php-fpm socket, so the old server keeps serving.
	for _, site := range sites {
		if err := s.renderVHost(site); err != nil {
			s.cfg.WebServer = oldTarget
			return err
		}
	}
	// 2. Validate before touching any service; a failure here is a clean no-op.
	if _, err := s.web().Validate(ctx); err != nil {
		s.cfg.WebServer = oldTarget
		return fmt.Errorf("generated %s configuration is invalid: %w", target, err)
	}
	// 3. Swap services. Up to here the old server + sockets are intact, so a
	//    start failure is recovered by simply restarting the old server.
	if !s.cfg.Dev && oldService != newService {
		_ = system.ServiceAction(ctx, "stop", oldService)
		_ = system.ServiceAction(ctx, "disable", oldService)
		_ = system.ServiceAction(ctx, "enable", newService)
		if err := system.ServiceAction(ctx, "start", newService); err != nil {
			s.cfg.WebServer = oldTarget
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
		if err := s.reprovisionPHP(ctx, site); err != nil {
			reErr = err
		}
	}
	// 6. Remove the now-inactive server's stale per-site configs.
	for _, site := range sites {
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
	n := 0
	for _, d := range found {
		if d.Managed {
			continue // a config we generated ourselves
		}
		if _, err := s.store.SiteByDomain(d.Domain); err == nil {
			continue // already tracked
		}
		if _, err := s.store.CreateSite(&store.Site{
			UserID:     admin.ID,
			Domain:     d.Domain,
			Type:       store.SiteMain,
			DocRoot:    d.DocRoot,
			SSLEnabled: d.SSL,
			Source:     store.SourceImported,
			ConfFile:   d.File,
		}); err != nil {
			continue
		}
		n++
	}
	return n, nil
}

// AdoptSite converts an imported site to fully-managed. It generates an Open
// ProPanel vhost + php-fpm pool pointing at the SAME document root, disables the
// original config (renamed to *.disabled-by-openpropanel, which doubles as a
// backup), validates, and reloads. On any validation failure it rolls back so
// the previously-running config is restored untouched.
func (s *Service) AdoptSite(ctx context.Context, id int64, phpLabel string) error {
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

	orig := site.ConfFile
	target := s.web().ConfPath(site.Domain)
	disabled := ""
	if orig != "" {
		disabled = orig + ".disabled-by-openpropanel"
		if err := os.Rename(orig, disabled); err != nil {
			disabled = "" // original already gone; nothing to restore
		}
	}

	site.Source = store.SourceManaged
	site.PHPVersion = version.Label
	// Imported sites have no dedicated system user, so the pool runs as the
	// web-server user (empty systemUser).
	if err := s.php.ConfigureSite(ctx, site, version, ""); err != nil {
		restoreAdopt(orig, disabled, target)
		return fmt.Errorf("php-fpm: %w", err)
	}
	if err := s.renderVHost(site); err != nil {
		_ = s.php.RemoveSite(ctx, site.Domain)
		restoreAdopt(orig, disabled, target)
		return err
	}
	if _, err := s.web().Validate(ctx); err != nil {
		_ = s.php.RemoveSite(ctx, site.Domain)
		restoreAdopt(orig, disabled, target)
		_ = s.web().Reload(ctx)
		return fmt.Errorf("generated config was invalid, reverted to the original: %w", err)
	}
	if err := s.web().Apply(ctx); err != nil {
		return err
	}
	return s.store.MarkSiteManaged(id, version.Label)
}

// restoreAdopt undoes a failed adoption: remove our generated vhost and restore
// the original (disabled) config.
func restoreAdopt(orig, disabled, target string) {
	_ = os.Remove(target)
	if disabled != "" && orig != "" {
		_ = os.Rename(disabled, orig)
	}
}

// ---------------------------------------------------------------------------
// internal helpers
// ---------------------------------------------------------------------------

// renderVHost writes the Apache config reflecting the site's current state.
func (s *Service) renderVHost(site *store.Site) error {
	vh := webserver.VHost{
		Domain:    site.Domain,
		DocRoot:   site.DocRoot,
		PHPSocket: s.php.SocketPath(site.Domain),
		SSL:       site.SSLEnabled,
	}
	if site.Type == store.SiteMain {
		vh.ServerAlias = "www." + site.Domain
	}
	if site.SSLEnabled {
		vh.CertFile, vh.KeyFile = s.ssl.CertPaths(site.Domain)
	}
	return s.web().Write(vh)
}

func (s *Service) teardownArtifacts(ctx context.Context, site *store.Site) {
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

// provisionDocRoot creates the document root, seeds a landing page, and (in
// production, when the owner has a system user) hands ownership to that user.
func (s *Service) provisionDocRoot(docRoot, domain, systemUser string) error {
	if err := os.MkdirAll(docRoot, 0o755); err != nil {
		return err
	}
	// ACME challenge directory so certbot webroot mode works out of the box.
	if err := os.MkdirAll(filepath.Join(docRoot, ".well-known", "acme-challenge"), 0o755); err != nil {
		return err
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

func (s *Service) rollbackFiles(domain, docRoot string) {
	_ = s.web().Remove(domain)
	// Only remove the doc root during rollback if it is empty-ish (freshly
	// created). We check for our seeded index and no user files beyond it.
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
