// Package webserver defines the shared virtual-host model and the backend
// interface that both the Apache and Nginx managers implement. The domains
// orchestrator talks to this interface, so a site can be served by either web
// server without the orchestration logic knowing which is active.
package webserver

import "context"

// VHost is the data used to render a virtual host for either backend.
type VHost struct {
	Domain      string // primary ServerName; also the config filename stem
	ServerAlias string // e.g. "www.example.com"; empty for subdomains
	DocRoot     string
	PHPSocket   string // php-fpm unix socket; empty disables PHP handling
	SSL         bool
	CertFile    string // fullchain.pem
	KeyFile     string // privkey.pem
	// Mode selects how the doc root is served: "php" (PHP-FPM + index.php),
	// "static" (plain files), or "spa" (unknown paths fall back to index.html
	// for client-side-routed apps like Angular/React). Empty is treated as php.
	Mode string
}

// Manager is implemented by each web-server backend (Apache, Nginx).
type Manager interface {
	// Write renders and writes a site's config file (does not reload).
	Write(vh VHost) error
	// Remove deletes a site's config file if present.
	Remove(domain string) error
	// ConfPath is the on-disk path of a domain's config file.
	ConfPath(domain string) string
	// WritePanelChallengeVHost publishes a :80 config that answers the ACME
	// HTTP-01 challenge for the panel's own hostname.
	WritePanelChallengeVHost(host, webroot string) error
	// Validate checks the full configuration before reloading.
	Validate(ctx context.Context) (string, error)
	// Reload gracefully reloads the web server.
	Reload(ctx context.Context) error
	// Apply validates and, if valid, reloads.
	Apply(ctx context.Context) error
}
