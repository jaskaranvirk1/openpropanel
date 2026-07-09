// Package apache generates, validates and reloads Apache (httpd) virtual-host
// configuration. Each managed site owns exactly one <domain>.conf file in the
// vhost directory; Open ProPanel never edits a file it did not create.
package apache

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"text/template"

	"github.com/openpropanel/openpropanel/internal/config"
	"github.com/openpropanel/openpropanel/internal/system"
	"github.com/openpropanel/openpropanel/internal/webserver"
)

// Manager renders and applies Apache vhost configuration. It implements
// webserver.Manager.
type Manager struct {
	cfg *config.Config
}

// New constructs a Manager.
func New(cfg *config.Config) *Manager { return &Manager{cfg: cfg} }

// ConfPath is the on-disk path of a domain's vhost file.
func (m *Manager) ConfPath(domain string) string {
	return filepath.Join(m.cfg.ApacheVhostDir, domain+".conf")
}

// Write renders vh and writes its .conf file (0644). It does not reload Apache;
// call Apply once all pending files are written.
func (m *Manager) Write(vh webserver.VHost) error {
	var buf bytes.Buffer
	if err := vhostTmpl.Execute(&buf, vh); err != nil {
		return err
	}
	if err := os.MkdirAll(m.cfg.ApacheVhostDir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(m.ConfPath(vh.Domain), buf.Bytes(), 0o644)
}

// WritePanelChallengeVHost writes a minimal :80 vhost that serves the ACME
// HTTP-01 challenge for the panel's OWN hostname from webroot. It is named
// distinctly (openpropanel-panel-<host>.conf) so it never collides with a hosted
// site's vhost. The standard template already exposes /.well-known/acme-
// challenge/ from the document root, which is all certbot webroot needs.
func (m *Manager) WritePanelChallengeVHost(host, webroot string) error {
	var buf bytes.Buffer
	if err := vhostTmpl.Execute(&buf, webserver.VHost{Domain: host, DocRoot: webroot}); err != nil {
		return err
	}
	if err := os.MkdirAll(m.cfg.ApacheVhostDir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(m.cfg.ApacheVhostDir, "openpropanel-panel-"+host+".conf")
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

// Remove deletes a domain's vhost file if present.
func (m *Manager) Remove(domain string) error {
	err := os.Remove(m.ConfPath(domain))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// Validate runs `httpd -t` to check the full configuration before reloading.
// In dev mode (non-Linux) it is a no-op.
func (m *Manager) Validate(ctx context.Context) (string, error) {
	if m.cfg.Dev {
		return "dev mode: skipped httpd -t", nil
	}
	return system.Run(ctx, m.cfg.ApacheService, "-t")
}

// Reload gracefully reloads Apache so config changes take effect without
// dropping connections. No-op in dev mode.
func (m *Manager) Reload(ctx context.Context) error {
	if m.cfg.Dev {
		return nil
	}
	return system.ServiceAction(ctx, "reload", m.cfg.ApacheService)
}

// Apply validates the configuration and, if valid, reloads Apache.
func (m *Manager) Apply(ctx context.Context) error {
	if _, err := m.Validate(ctx); err != nil {
		return err
	}
	return m.Reload(ctx)
}

// vhostTmpl is the Apache 2.4 virtual-host template. PHP is wired through
// mod_proxy_fcgi to a per-site php-fpm socket. When SSL is enabled, plain HTTP
// is redirected to HTTPS except for the ACME challenge path.
var vhostTmpl = template.Must(template.New("vhost").Parse(`# Managed by Open ProPanel — do not edit by hand.
# Site: {{.Domain}}
<VirtualHost *:80>
    ServerName {{.Domain}}
{{- if .ServerAlias}}
    ServerAlias {{.ServerAlias}}
{{- end}}
    DocumentRoot "{{.DocRoot}}"

    # Always serve the Let's Encrypt HTTP-01 challenge over plain HTTP.
    Alias /.well-known/acme-challenge/ "{{.DocRoot}}/.well-known/acme-challenge/"
    <Directory "{{.DocRoot}}/.well-known/acme-challenge/">
        Require all granted
    </Directory>

    # Deny dotfiles/dirs (.git, .env, .user.ini, ...) except .well-known.
    <DirectoryMatch "/\.(?!well-known)">
        Require all denied
    </DirectoryMatch>
    <FilesMatch "^\.">
        Require all denied
    </FilesMatch>
{{- if .SSL}}

    RewriteEngine On
    RewriteCond %{REQUEST_URI} !^/\.well-known/acme-challenge/
    RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]
{{- else}}

{{template "apacheServe" .}}
{{- end}}

    ErrorLog "/var/log/httpd/{{.Domain}}-error.log"
    CustomLog "/var/log/httpd/{{.Domain}}-access.log" combined
</VirtualHost>
{{- if .SSL}}

<VirtualHost *:443>
    ServerName {{.Domain}}
{{- if .ServerAlias}}
    ServerAlias {{.ServerAlias}}
{{- end}}
    DocumentRoot "{{.DocRoot}}"

    SSLEngine on
    SSLCertificateFile "{{.CertFile}}"
    SSLCertificateKeyFile "{{.KeyFile}}"

    # Deny dotfiles/dirs (.git, .env, .user.ini, ...) except .well-known.
    <DirectoryMatch "/\.(?!well-known)">
        Require all denied
    </DirectoryMatch>
    <FilesMatch "^\.">
        Require all denied
    </FilesMatch>

{{template "apacheServe" .}}

    ErrorLog "/var/log/httpd/{{.Domain}}-ssl-error.log"
    CustomLog "/var/log/httpd/{{.Domain}}-ssl-access.log" combined
</VirtualHost>
{{- end}}
{{define "apacheServe"}}    <Directory "{{.DocRoot}}">
        Options -Indexes +SymLinksIfOwnerMatch
        AllowOverride All
        Require all granted
{{- if eq .Mode "spa"}}
        FallbackResource /index.html
{{- end}}
    </Directory>
{{- if eq .Mode "php"}}
{{- if .PHPSocket}}
    <FilesMatch \.php$>
        SetHandler "proxy:unix:{{.PHPSocket}}|fcgi://localhost"
    </FilesMatch>
{{- end}}
    DirectoryIndex index.php index.html
{{- else}}
    DirectoryIndex index.html
{{- end}}
{{- end}}`))
