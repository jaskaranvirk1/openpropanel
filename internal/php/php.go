// Package php manages PHP-FPM: it discovers the PHP versions installed on the
// host and writes a dedicated FPM pool per site so each site can run a
// different PHP version, isolated under its own system user.
//
// On AlmaLinux the default PHP-FPM lives under /etc/php-fpm.d with the systemd
// unit "php-fpm". Additional versions installed from the Remi repository follow
// the SCL layout: /etc/opt/remi/php<NN>/php-fpm.d with unit "php<NN>-php-fpm"
// (e.g. php83-php-fpm). Both layouts are auto-detected.
package php

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"github.com/openpropanel/openpropanel/internal/config"
	"github.com/openpropanel/openpropanel/internal/store"
	"github.com/openpropanel/openpropanel/internal/system"
)

// Version describes one installed PHP-FPM version and where its pools live.
type Version struct {
	Label   string // human label, e.g. "8.3" or "system"
	Service string // systemd unit to reload, e.g. "php-fpm" or "php83-php-fpm"
	ConfDir string // php-fpm.d directory to drop pool files into
}

// Manager handles PHP-FPM pools.
type Manager struct {
	cfg *config.Config
}

// New constructs a Manager.
func New(cfg *config.Config) *Manager { return &Manager{cfg: cfg} }

// DetectVersions returns the PHP versions available on the host. In dev mode a
// static placeholder list is returned so the UI has something to render.
func (m *Manager) DetectVersions() []Version {
	if m.cfg.Dev {
		return []Version{
			{Label: "8.3", Service: "php-fpm", ConfDir: m.cfg.PHPFPMConfDir},
			{Label: "8.2", Service: "php82-php-fpm", ConfDir: m.cfg.PHPFPMConfDir},
			{Label: "8.1", Service: "php81-php-fpm", ConfDir: m.cfg.PHPFPMConfDir},
		}
	}

	var versions []Version
	// System default PHP-FPM.
	if dirExists(m.cfg.PHPFPMConfDir) {
		versions = append(versions, Version{
			Label:   "system",
			Service: m.cfg.PHPFPMService,
			ConfDir: m.cfg.PHPFPMConfDir,
		})
	}
	// Remi SCL versions: /etc/opt/remi/php<NN>/php-fpm.d
	if entries, err := os.ReadDir("/etc/opt/remi"); err == nil {
		for _, e := range entries {
			name := e.Name() // e.g. "php83"
			if !e.IsDir() || !strings.HasPrefix(name, "php") {
				continue
			}
			confDir := filepath.Join("/etc/opt/remi", name, "php-fpm.d")
			if !dirExists(confDir) {
				continue
			}
			versions = append(versions, Version{
				Label:   labelFromRemi(name), // "php83" -> "8.3"
				Service: name + "-php-fpm",
				ConfDir: confDir,
			})
		}
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i].Label < versions[j].Label })
	return versions
}

// FindVersion returns the Version whose Label matches, or false.
func (m *Manager) FindVersion(label string) (Version, bool) {
	for _, v := range m.DetectVersions() {
		if v.Label == label {
			return v, true
		}
	}
	return Version{}, false
}

// SocketPath is the php-fpm unix socket a site's Apache vhost connects to.
func (m *Manager) SocketPath(domain string) string {
	if m.cfg.Dev {
		return filepath.Join(m.cfg.DataDir, "run", "openpropanel-"+domain+".sock")
	}
	return filepath.Join("/run/php-fpm", "openpropanel-"+domain+".sock")
}

func poolFileName(domain string) string { return "openpropanel-" + domain + ".conf" }

// ConfigureSite writes (or rewrites) the FPM pool for a site using the chosen
// PHP version, then reloads that version's php-fpm service. Any stale pool
// files for the site under other versions are removed first so switching
// versions leaves exactly one active pool.
func (m *Manager) ConfigureSite(ctx context.Context, site *store.Site, version Version, systemUser string) error {
	m.removePoolFiles(site.Domain)

	user := systemUser
	group := systemUser
	if user == "" {
		user, group = "apache", "apache"
	}

	data := poolData{
		Pool:        "openpropanel-" + site.Domain,
		User:        user,
		Group:       group,
		Socket:      m.SocketPath(site.Domain),
		DocRoot:     site.DocRoot,
		SocketOwner: m.cfg.WebServerUser(),
	}
	var buf bytes.Buffer
	if err := poolTmpl.Execute(&buf, data); err != nil {
		return err
	}
	if err := os.MkdirAll(version.ConfDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(version.ConfDir, poolFileName(site.Domain)), buf.Bytes(), 0o644); err != nil {
		return err
	}
	return m.reload(ctx, version.Service)
}

// RemoveSite deletes a site's pool files across all versions and reloads FPM.
func (m *Manager) RemoveSite(ctx context.Context, domain string) error {
	m.removePoolFiles(domain)
	// Reload every detected version so whichever one held the pool is refreshed.
	for _, v := range m.DetectVersions() {
		_ = m.reload(ctx, v.Service)
	}
	return nil
}

func (m *Manager) removePoolFiles(domain string) {
	for _, v := range m.DetectVersions() {
		_ = os.Remove(filepath.Join(v.ConfDir, poolFileName(domain)))
	}
}

func (m *Manager) reload(ctx context.Context, service string) error {
	if m.cfg.Dev {
		return nil
	}
	return system.ServiceAction(ctx, "reload", service)
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// labelFromRemi turns "php83" into "8.3", "php7" stays "php7" if unparseable.
func labelFromRemi(name string) string {
	digits := strings.TrimPrefix(name, "php")
	if len(digits) >= 2 {
		return digits[:1] + "." + digits[1:]
	}
	return name
}

type poolData struct {
	Pool        string
	User        string
	Group       string
	Socket      string
	DocRoot     string
	SocketOwner string // OS user of the active web server (socket owner/group)
}

var poolTmpl = template.Must(template.New("pool").Parse(`; Managed by Open ProPanel — do not edit by hand.
[{{.Pool}}]
user = {{.User}}
group = {{.Group}}

listen = {{.Socket}}
listen.owner = {{.SocketOwner}}
listen.group = {{.SocketOwner}}
listen.mode = 0660

pm = ondemand
pm.max_children = 10
pm.process_idle_timeout = 10s
pm.max_requests = 500

; Confine each site's PHP to its own document root.
php_admin_value[open_basedir] = {{.DocRoot}}:/tmp
php_admin_value[disable_functions] = exec,passthru,shell_exec,system,proc_open,popen
php_admin_flag[log_errors] = on

; Only ever execute genuine .php files, and don't let PATH_INFO trick FPM into
; running an uploaded file (e.g. evil.jpg) as PHP.
security.limit_extensions = .php
php_admin_value[cgi.fix_pathinfo] = 0
`))
