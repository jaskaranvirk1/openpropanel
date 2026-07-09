// Package nginx generates, validates and reloads Nginx server-block
// configuration. It is the Nginx counterpart to the apache package and
// implements webserver.Manager, so the domains orchestrator can drive either.
package nginx

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

// Manager renders and applies Nginx configuration.
type Manager struct {
	cfg *config.Config
}

// New constructs a Manager.
func New(cfg *config.Config) *Manager { return &Manager{cfg: cfg} }

// ConfPath is the on-disk path of a domain's server-block file.
func (m *Manager) ConfPath(domain string) string {
	return filepath.Join(m.cfg.NginxVhostDir, domain+".conf")
}

// Write renders vh and writes its .conf file (0644). It does not reload Nginx.
func (m *Manager) Write(vh webserver.VHost) error {
	var buf bytes.Buffer
	if err := serverTmpl.Execute(&buf, vh); err != nil {
		return err
	}
	if err := os.MkdirAll(m.cfg.NginxVhostDir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(m.ConfPath(vh.Domain), buf.Bytes(), 0o644)
}

// Remove deletes a domain's server-block file if present.
func (m *Manager) Remove(domain string) error {
	err := os.Remove(m.ConfPath(domain))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// WritePanelChallengeVHost publishes a :80 server block that answers the ACME
// HTTP-01 challenge for the panel's own hostname.
func (m *Manager) WritePanelChallengeVHost(host, webroot string) error {
	var buf bytes.Buffer
	if err := serverTmpl.Execute(&buf, webserver.VHost{Domain: host, DocRoot: webroot}); err != nil {
		return err
	}
	if err := os.MkdirAll(m.cfg.NginxVhostDir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(m.cfg.NginxVhostDir, "openpropanel-panel-"+host+".conf")
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

// Validate runs `nginx -t`. No-op in dev mode.
func (m *Manager) Validate(ctx context.Context) (string, error) {
	if m.cfg.Dev {
		return "dev mode: skipped nginx -t", nil
	}
	return system.Run(ctx, m.cfg.NginxService, "-t")
}

// Reload gracefully reloads Nginx. No-op in dev mode.
func (m *Manager) Reload(ctx context.Context) error {
	if m.cfg.Dev {
		return nil
	}
	return system.ServiceAction(ctx, "reload", m.cfg.NginxService)
}

// Apply validates the configuration and, if valid, reloads Nginx.
func (m *Manager) Apply(ctx context.Context) error {
	if _, err := m.Validate(ctx); err != nil {
		return err
	}
	return m.Reload(ctx)
}

// serverTmpl is the Nginx server-block template. PHP is wired through
// fastcgi_pass to a per-site php-fpm socket; `try_files $uri =404` ensures only
// existing .php files are executed. When SSL is enabled, plain HTTP redirects
// to HTTPS except for the ACME challenge path. The listen directives avoid the
// version-specific `http2 on;` for compatibility across nginx 1.20+.
var serverTmpl = template.Must(template.New("server").Parse(`# Managed by Open ProPanel — do not edit by hand.
# Site: {{.Domain}}
server {
    listen 80;
    listen [::]:80;
    server_name {{.Domain}}{{if .ServerAlias}} {{.ServerAlias}}{{end}};
    root {{.DocRoot}};

    location ^~ /.well-known/acme-challenge/ {
        root {{.DocRoot}};
        default_type "text/plain";
        allow all;
    }
{{- if .SSL}}

    location / {
        return 301 https://{{.Domain}}$request_uri;
    }
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name {{.Domain}}{{if .ServerAlias}} {{.ServerAlias}}{{end}};
    root {{.DocRoot}};

    ssl_certificate {{.CertFile}};
    ssl_certificate_key {{.KeyFile}};
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

{{template "nginxServe" .}}
    access_log /var/log/nginx/{{.Domain}}-access.log;
    error_log /var/log/nginx/{{.Domain}}-error.log;
}
{{- else}}

{{template "nginxServe" .}}
    access_log /var/log/nginx/{{.Domain}}-access.log;
    error_log /var/log/nginx/{{.Domain}}-error.log;
}
{{- end}}
{{define "nginxServe"}}    index {{if eq .Mode "php"}}index.php index.html{{else}}index.html{{end}};

    # Deny dotfiles (.git, .env, .user.ini, ...) while keeping .well-known reachable.
    location ~ /\.(?!well-known/) {
        deny all;
    }

    location / {
        try_files $uri $uri/ {{if eq .Mode "spa"}}/index.html{{else if eq .Mode "static"}}=404{{else}}/index.php?$query_string{{end}};
    }
{{- if eq .Mode "php"}}
{{- if .PHPSocket}}

    location ~ \.php$ {
        try_files $uri =404;
        fastcgi_pass unix:{{.PHPSocket}};
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    }
{{- end}}
{{- end}}
{{end}}`))
