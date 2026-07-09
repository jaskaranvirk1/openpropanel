// Package config holds Open ProPanel's runtime configuration.
//
// Defaults target AlmaLinux / RHEL-family layouts (httpd in /etc/httpd,
// php-fpm in /etc/php-fpm.d, sites under /var/www). When Open ProPanel is run on a
// non-Linux host (e.g. a developer's Windows/macOS machine) it falls back to a
// self-contained ./data directory so the UI can be worked on without touching
// any system services.
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

// Config is the fully-resolved configuration used across the application.
type Config struct {
	// ListenAddr is the address the web UI binds to. We default to :9443 — an
	// easy-to-remember HTTPS-style port that avoids the common control-panel
	// ports (2087 WHM, 9090 Cockpit, 8888 aaPanel, 10000 Webmin).
	ListenAddr string `json:"listen_addr"`

	// DataDir holds the SQLite database and other panel state.
	DataDir string `json:"data_dir"`

	// WebRoot is the parent directory under which per-site document roots live.
	WebRoot string `json:"web_root"`

	// WebServer selects the active web server: "apache" or "nginx". Sites are
	// served by exactly one of them; switching regenerates all vhosts.
	WebServer string `json:"web_server"`

	// ApacheVhostDir is where generated vhost .conf files are written. On
	// AlmaLinux, files in /etc/httpd/conf.d are auto-included by httpd.
	ApacheVhostDir string `json:"apache_vhost_dir"`

	// NginxVhostDir is where generated Nginx server-block files are written
	// (/etc/nginx/conf.d is auto-included by nginx).
	NginxVhostDir string `json:"nginx_vhost_dir"`

	// PHPFPMConfDir is where per-site php-fpm pool files are written.
	PHPFPMConfDir string `json:"php_fpm_conf_dir"`

	// ApacheService / NginxService / PHPFPMService are systemd unit names.
	ApacheService string `json:"apache_service"`
	NginxService  string `json:"nginx_service"`
	PHPFPMService string `json:"php_fpm_service"`

	// LetsEncryptLive is where certbot stores issued certificates.
	LetsEncryptLive string `json:"letsencrypt_live"`

	// ACMEEmail is the contact email used when requesting certificates.
	ACMEEmail string `json:"acme_email"`

	// TLSEnabled serves the panel over HTTPS.
	TLSEnabled bool `json:"tls_enabled"`

	// TLSCert/TLSKey are OPTIONAL overrides pointing at a real certificate
	// (bring-your-own, or one auto-issued by Let's Encrypt for PanelHostname).
	// When empty — or when the files are missing — the panel falls back to a
	// self-signed certificate generated under DataDir/tls. The cert is served
	// via a hot-reloading loader, so a renewal on disk is picked up live.
	TLSCert string `json:"tls_cert"`
	TLSKey  string `json:"tls_key"`

	// PanelHostname is the DNS name the panel is reached at. When set, Open ProPanel
	// can auto-issue a Let's Encrypt certificate for it (Settings → Panel HTTPS).
	PanelHostname string `json:"panel_hostname"`

	// PMARoot is the parent directory phpMyAdmin is installed under (the app
	// lives at PMARoot/phpmyadmin). Served behind the panel at /phpmyadmin.
	PMARoot string `json:"pma_root"`

	// SessionKey signs session cookies. Generated on first run if empty.
	SessionKey string `json:"session_key"`

	// Dev is true when running on a non-production/non-Linux host. In dev mode
	// system-mutating actions are simulated rather than executed.
	Dev bool `json:"-"`

	// mu guards the fields mutated at runtime (WebServer, TLSCert, TLSKey,
	// PanelHostname) against concurrent request-path readers. Access those
	// fields only through the accessor methods below.
	mu sync.RWMutex
}

// Default returns a Config populated with AlmaLinux-appropriate defaults, or a
// self-contained local layout when not running on Linux.
func Default() *Config {
	c := &Config{
		ListenAddr:      ":9443",
		DataDir:         "/var/lib/openpropanel",
		WebRoot:         "/var/www",
		WebServer:       "apache",
		ApacheVhostDir:  "/etc/httpd/conf.d",
		NginxVhostDir:   "/etc/nginx/conf.d",
		PHPFPMConfDir:   "/etc/php-fpm.d",
		ApacheService:   "httpd",
		NginxService:    "nginx",
		PHPFPMService:   "php-fpm",
		LetsEncryptLive: "/etc/letsencrypt/live",
		// phpMyAdmin lives under /var (NOT /usr): the systemd unit sets
		// ProtectSystem=true, which mounts /usr read-only, so the panel could not
		// install there. It is also deliberately OUTSIDE the 0700 StateDirectory
		// (/var/lib/openpropanel) so the unprivileged phpMyAdmin pool user can
		// traverse in to read the app files.
		PMARoot: "/var/lib/openpropanel-pma",
	}

	if runtime.GOOS != "linux" {
		// Developer fallback: keep everything inside the working directory so
		// nothing on the host is touched and the UI can be developed anywhere.
		wd, _ := os.Getwd()
		base := filepath.Join(wd, "data")
		c.Dev = true
		c.DataDir = base
		c.WebRoot = filepath.Join(base, "www")
		c.ApacheVhostDir = filepath.Join(base, "vhosts")
		c.NginxVhostDir = filepath.Join(base, "nginx")
		c.PHPFPMConfDir = filepath.Join(base, "php-fpm.d")
		c.LetsEncryptLive = filepath.Join(base, "letsencrypt", "live")
		c.PMARoot = filepath.Join(base, "pma")
	}

	// TLS: serve HTTPS in production, plain HTTP for local dev (avoids cert
	// warnings while developing). TLSCert/TLSKey are left empty by default,
	// which selects the self-signed fallback.
	c.TLSEnabled = !c.Dev
	return c
}

// SelfSignedCertPath / SelfSignedKeyPath are where the auto-generated
// self-signed certificate lives when no override cert is configured.
func (c *Config) SelfSignedCertPath() string { return filepath.Join(c.DataDir, "tls", "cert.pem") }
func (c *Config) SelfSignedKeyPath() string  { return filepath.Join(c.DataDir, "tls", "key.pem") }

// CertDir is a Cockpit-style drop-in directory for the panel's own TLS cert:
// place panel.crt + panel.key there and the panel serves them automatically
// (no config edit), taking precedence over the self-signed fallback.
func (c *Config) CertDir() string {
	if c.Dev {
		return filepath.Join(c.DataDir, "certs")
	}
	return "/etc/openpropanel/certs"
}

// PhpMyAdminDir is where the phpMyAdmin app files live.
func (c *Config) PhpMyAdminDir() string { return filepath.Join(c.PMARoot, "phpmyadmin") }

// PMASocket is the php-fpm unix socket the panel dispatches phpMyAdmin's PHP to.
func (c *Config) PMASocket() string {
	if c.Dev {
		return filepath.Join(c.DataDir, "run", "openpropanel-pma.sock")
	}
	return "/run/php-fpm/openpropanel-pma.sock"
}

// WebServerName returns the active web server ("apache"|"nginx"), locked.
func (c *Config) WebServerName() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.WebServer
}

// SetWebServer atomically changes the active web server.
func (c *Config) SetWebServer(v string) {
	c.mu.Lock()
	c.WebServer = v
	c.mu.Unlock()
}

// UseNginx reports whether Nginx is the active web server.
func (c *Config) UseNginx() bool { return c.WebServerName() == "nginx" }

// ActiveWebService is the systemd unit name of the active web server.
func (c *Config) ActiveWebService() string {
	if c.UseNginx() {
		return c.NginxService
	}
	return c.ApacheService
}

// WebServerUser is the OS user the active web server runs as. It is used as the
// owner of each site's php-fpm socket so the web server can connect to it.
func (c *Config) WebServerUser() string {
	if c.UseNginx() {
		return "nginx"
	}
	return "apache"
}

// TLSOverride returns the operator/LE override cert+key paths, locked.
func (c *Config) TLSOverride() (cert, key string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.TLSCert, c.TLSKey
}

// SetTLSOverride atomically records a new panel certificate + hostname.
func (c *Config) SetTLSOverride(cert, key, host string) {
	c.mu.Lock()
	c.TLSCert, c.TLSKey, c.PanelHostname = cert, key, host
	c.mu.Unlock()
}

// Load reads configuration from a JSON file, layering it over the defaults.
// A missing file is not an error — defaults are returned.
func Load(path string) (*Config, error) {
	c := Default()
	if path == "" {
		return c, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, err
	}
	// A JSON file never carries the Dev flag; recompute it from the platform.
	c.Dev = runtime.GOOS != "linux"
	return c, nil
}

// Save writes the configuration back to disk (used to persist a generated
// session key on first run).
func (c *Config) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	c.mu.RLock()
	b, err := json.MarshalIndent(c, "", "  ")
	c.mu.RUnlock()
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// DBPath is the SQLite database file location.
func (c *Config) DBPath() string { return filepath.Join(c.DataDir, "openpropanel.db") }

// EnsureDirs creates the directories Open ProPanel writes to. In production, the
// system directories (/etc/httpd/conf.d, ...) are expected to already exist and
// are left alone; we only guarantee our own data/web-root dirs.
func (c *Config) EnsureDirs() error {
	dirs := []string{c.DataDir, c.WebRoot}
	if c.Dev {
		dirs = append(dirs, c.ApacheVhostDir, c.NginxVhostDir, c.PHPFPMConfDir, c.LetsEncryptLive)
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	return nil
}
