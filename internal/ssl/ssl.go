// Package ssl issues and tracks Let's Encrypt certificates via certbot in
// webroot mode. Renewal is handled by certbot's own systemd timer
// (certbot-renew.timer), which Open ProPanel does not need to manage.
package ssl

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/openpropanel/openpropanel/internal/config"
	"github.com/openpropanel/openpropanel/internal/system"
)

// Manager issues certificates and reports their status.
type Manager struct {
	cfg *config.Config
}

// New constructs a Manager.
func New(cfg *config.Config) *Manager { return &Manager{cfg: cfg} }

// LiveDir is the certbot live directory for a domain.
func (m *Manager) LiveDir(domain string) string {
	return filepath.Join(m.cfg.LetsEncryptLive, domain)
}

// CertPaths returns the fullchain and private-key paths for a domain.
func (m *Manager) CertPaths(domain string) (fullchain, privkey string) {
	dir := m.LiveDir(domain)
	return filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem")
}

// HasCert reports whether a usable certificate already exists for a domain.
func (m *Manager) HasCert(domain string) bool {
	fullchain, _ := m.CertPaths(domain)
	_, err := os.Stat(fullchain)
	return err == nil
}

// Issue obtains a certificate for domain (plus any altNames) using the HTTP-01
// challenge served from docRoot. The site's vhost must already be live on port
// 80 and resolve publicly for the challenge to succeed.
func (m *Manager) Issue(ctx context.Context, domain string, altNames []string, docRoot string) error {
	if m.cfg.Dev {
		return m.simulateIssue(domain)
	}
	if m.cfg.ACMEEmail == "" {
		return errors.New("no ACME contact email configured (set acme_email in the panel settings)")
	}
	// ACME can take longer than the default command timeout, and must not be
	// killed if the browser request is cancelled mid-issue, so give it its own
	// several-minute deadline detached from the request context.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Minute)
	defer cancel()

	args := []string{
		"certonly", "--webroot",
		"-w", docRoot,
		"-d", domain,
	}
	for _, alt := range altNames {
		args = append(args, "-d", alt)
	}
	args = append(args,
		"--non-interactive", "--agree-tos",
		"-m", m.cfg.ACMEEmail,
		"--no-eff-email",
		"--keep-until-expiring",
		// Reload Apache after issuance AND after every future renewal (certbot
		// persists this hook per-certificate), so the new cert is actually
		// served instead of Apache clinging to the expired one in memory.
		"--deploy-hook", fmt.Sprintf("systemctl reload %s", m.cfg.ApacheService),
	)
	_, err := system.Run(ctx, "certbot", args...)
	return err
}

// simulateIssue writes placeholder cert files so the SSL flow is exercisable
// during local UI development without a real ACME round-trip.
func (m *Manager) simulateIssue(domain string) error {
	dir := m.LiveDir(domain)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	fullchain, privkey := m.CertPaths(domain)
	placeholder := []byte("# dev placeholder certificate for " + domain + "\n")
	if err := os.WriteFile(fullchain, placeholder, 0o644); err != nil {
		return err
	}
	return os.WriteFile(privkey, placeholder, 0o600)
}
