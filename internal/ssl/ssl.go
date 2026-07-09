// Package ssl issues and tracks Let's Encrypt certificates via certbot in
// webroot mode. Renewal is handled by certbot's own systemd timer
// (certbot-renew.timer), which Open ProPanel does not need to manage.
package ssl

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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
	// --- DNS preflight -------------------------------------------------------
	// Fail fast with a clear, actionable message instead of letting certbot emit
	// a raw challenge log. Also drop any alt name that has no DNS record (e.g. an
	// unconfigured "www") so a single missing record doesn't sink the whole
	// request.
	pfCtx, pfCancel := context.WithTimeout(ctx, 8*time.Second)
	server := serverIPs(pfCtx)
	primaryIPs := lookupHost(pfCtx, domain)
	if len(primaryIPs) == 0 {
		pfCancel()
		return fmt.Errorf("%s has no DNS record yet — add a DNS A record pointing it to this server%s, then retry (DNS changes can take a few minutes to propagate)",
			domain, ipHint(server))
	}
	var alts, dropped []string
	for _, a := range altNames {
		if len(lookupHost(pfCtx, a)) > 0 {
			alts = append(alts, a)
		} else {
			dropped = append(dropped, a)
		}
	}
	pfCancel()

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
	for _, alt := range alts {
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
	if _, err := system.Run(ctx, "certbot", args...); err != nil {
		// Enrich the failure with DNS context: the #1 cause is the domain not
		// pointing at this server.
		if !anyMatch(primaryIPs, server) {
			return fmt.Errorf("%s currently resolves to %s, not this server%s — point its DNS A record here and retry. (Using Cloudflare? Set the record to DNS-only/grey-cloud during issuance.)%s",
				domain, strings.Join(primaryIPs, ", "), ipHint(server), droppedNote(dropped))
		}
		return fmt.Errorf("certificate issuance failed — check that port 80 is reachable from the internet for the ACME challenge.%s (%w)",
			droppedNote(dropped), err)
	}
	return nil
}

// lookupHost resolves a host to its A/AAAA addresses, returning nil on failure
// (including NXDOMAIN).
func lookupHost(ctx context.Context, host string) []string {
	ips, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return nil
	}
	return ips
}

// serverIPs returns the set of IP addresses that belong to this host: its
// non-loopback interface addresses plus, best-effort, its public IP (so the
// check still works when the public IP is NAT'd rather than bound locally).
func serverIPs(ctx context.Context) map[string]bool {
	set := map[string]bool{}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				set[ipnet.IP.String()] = true
			}
		}
	}
	if ip := publicIP(ctx); ip != "" {
		set[ip] = true
	}
	return set
}

func publicIP(ctx context.Context) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ipify.org", nil)
	if err != nil {
		return ""
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
	if ip := net.ParseIP(strings.TrimSpace(string(b))); ip != nil {
		return ip.String()
	}
	return ""
}

func anyMatch(resolved []string, server map[string]bool) bool {
	for _, r := range resolved {
		if ip := net.ParseIP(r); ip != nil && server[ip.String()] {
			return true
		}
	}
	return false
}

// ipHint returns " (<ip>)" preferring a public address, for the error message.
func ipHint(server map[string]bool) string {
	var fallback string
	for ip := range server {
		p := net.ParseIP(ip)
		if p == nil {
			continue
		}
		if fallback == "" {
			fallback = ip
		}
		if !p.IsPrivate() && !p.IsLoopback() && !p.IsLinkLocalUnicast() {
			return " (" + ip + ")"
		}
	}
	if fallback != "" {
		return " (" + fallback + ")"
	}
	return ""
}

func droppedNote(dropped []string) string {
	if len(dropped) == 0 {
		return ""
	}
	return " Skipped (no DNS record): " + strings.Join(dropped, ", ") + "."
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
