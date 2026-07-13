// Package appserver supervises reverse-proxied applications (Node, Python, any
// command) as per-site systemd units. It mirrors internal/php: one Manager, a
// unit template, and lifecycle methods that go through internal/system.
//
// SECURITY: the tenant controls only the start command and env, and the app
// runs as the site's non-root system user. The tenant command is NEVER inlined
// into the (root-generated) systemd unit — that would allow injecting systemd
// directives like `User=root`. Instead it goes into a root-owned run-script the
// fixed unit execs (`ExecStart=/bin/bash <script>`), so anything the tenant
// writes there merely runs as the tenant. Env with secrets goes into a 0600
// EnvironmentFile systemd reads as PID 1 before dropping privileges.
package appserver

import (
	"context"
	"errors"
	"os"
	osuser "os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/template"

	"github.com/openpropanel/openpropanel/internal/config"
	"github.com/openpropanel/openpropanel/internal/store"
	"github.com/openpropanel/openpropanel/internal/system"
)

// Manager provisions and controls per-site app units.
type Manager struct{ cfg *config.Config }

// New constructs a Manager.
func New(cfg *config.Config) *Manager { return &Manager{cfg: cfg} }

// UnitName is the systemd unit for a site's app.
func UnitName(domain string) string { return "openpropanel-app-" + domain + ".service" }

func (m *Manager) scriptPath(domain string) string {
	return filepath.Join(m.cfg.AppConfDir(), "openpropanel-app-"+domain+".sh")
}
func (m *Manager) envPath(domain string) string {
	return filepath.Join(m.cfg.AppConfDir(), "openpropanel-app-"+domain+".env")
}
func (m *Manager) unitPath(domain string) string {
	return filepath.Join(m.cfg.AppUnitDir(), UnitName(domain))
}

// socketDir is the per-app run directory (owned tenant:<webserver-group>, 2770);
// SocketPath is the unix socket inside it that the app listens on and the web
// server reverse-proxies to.
func (m *Manager) socketDir(domain string) string {
	return filepath.Join(m.cfg.AppRunDir(), domain)
}
func (m *Manager) SocketPath(domain string) string {
	return filepath.Join(m.socketDir(domain), "app.sock")
}

var envKeyRe = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

// Configure writes the run-script, env file and unit, then enables + restarts.
// systemUser must be the site's provisioned non-root tenant user (the domains
// layer guards uid/gid != 0 before calling here).
func (m *Manager) Configure(ctx context.Context, app *store.App, site *store.Site, systemUser string) error {
	if systemUser == "" || systemUser == "root" {
		return errors.New("a non-root system user is required to run an app")
	}
	cmd := sanitizeCommand(app.StartCommand)
	if cmd == "" {
		return errors.New("a start command is required to run the app")
	}
	if err := os.MkdirAll(m.cfg.AppConfDir(), 0o755); err != nil {
		return err
	}
	_ = os.Chmod(m.cfg.AppConfDir(), 0o755)

	// Per-app run directory: owned tenant:<webserver-group>, mode 2770 (setgid) so
	// the socket the tenant app creates inside inherits the web-server group and is
	// reachable ONLY by that tenant and the web server — no other tenant can
	// traverse, create, unlink or squat inside it (the run root is root-owned 0755).
	if err := m.provisionSocketDir(site.Domain, systemUser); err != nil {
		return err
	}

	// Run-script (root-owned, world-readable so the tenant can exec it; it holds
	// only the tenant's own non-secret command). `umask 0007` makes the app's
	// socket group-connectable (0770); `rm -f` clears a stale socket left by a
	// crash (Node/uvicorn don't). `exec` is the last line, so a stray newline in
	// the command can only append lines that also run as the tenant — no
	// escalation into the unit.
	script := "#!/usr/bin/env bash\n" +
		"# Managed by Open ProPanel — do not edit by hand.\n" +
		"set -euo pipefail\n" +
		"umask 0007\n" +
		"rm -f " + shellQuote(m.SocketPath(site.Domain)) + "\n" +
		"exec " + cmd + "\n"
	if err := os.WriteFile(m.scriptPath(site.Domain), []byte(script), 0o755); err != nil {
		return err
	}
	// Env (root-owned 0600: read by systemd PID 1 before it drops to User=).
	if err := os.WriteFile(m.envPath(site.Domain), []byte(renderEnv(app.Env)), 0o600); err != nil {
		return err
	}
	if err := os.MkdirAll(m.cfg.AppUnitDir(), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(m.unitPath(site.Domain), []byte(m.renderUnit(app, site, systemUser)), 0o644); err != nil {
		return err
	}
	if m.cfg.Dev {
		return nil // no systemd on the dev host
	}
	if err := system.DaemonReload(ctx); err != nil {
		return err
	}
	if _, err := system.Run(ctx, "systemctl", "enable", UnitName(site.Domain)); err != nil {
		return err
	}
	if _, err := system.Run(ctx, "systemctl", "restart", UnitName(site.Domain)); err != nil {
		return err
	}
	return nil
}

// Remove stops, disables and deletes a site's app unit + files. No-op for a
// site that never had one.
func (m *Manager) Remove(ctx context.Context, domain string) error {
	if !m.cfg.Dev {
		if _, err := os.Stat(m.unitPath(domain)); err == nil {
			_, _ = system.Run(ctx, "systemctl", "disable", "--now", UnitName(domain))
		}
	}
	_ = os.Remove(m.unitPath(domain))
	_ = os.Remove(m.scriptPath(domain))
	_ = os.Remove(m.envPath(domain))
	_ = os.RemoveAll(m.socketDir(domain)) // per-app run dir + any leftover socket
	if !m.cfg.Dev {
		return system.DaemonReload(ctx)
	}
	return nil
}

// provisionSocketDir creates the run root and the per-app socket directory with
// owner tenant:<webserver-group> and mode 2770 (setgid). In dev (non-Linux) the
// ownership/mode dance is skipped — only the directory is created so paths exist.
func (m *Manager) provisionSocketDir(domain, systemUser string) error {
	if err := os.MkdirAll(m.cfg.AppRunDir(), 0o755); err != nil {
		return err
	}
	dir := m.socketDir(domain)
	if err := os.MkdirAll(dir, 0o770); err != nil {
		return err
	}
	if m.cfg.Dev {
		return nil
	}
	uid, err := lookupUID(systemUser)
	if err != nil {
		return err
	}
	gid, err := lookupGID(m.cfg.WebServerUser())
	if err != nil {
		return err
	}
	if err := os.Chown(dir, uid, gid); err != nil {
		return err
	}
	// os.ModeSetgid (not octal 0o2000) is how Go encodes the setgid bit; a bare
	// 0o2770 would silently yield a plain 0770 dir and break group inheritance.
	if err := os.Chmod(dir, 0o770|os.ModeSetgid); err != nil {
		return err
	}
	// /run is tmpfs and starts unlabeled; relabel so the web server (httpd_t under
	// SELinux enforcing) may connect to sockets created here. Best-effort: relies
	// on the fcontext rule the installer adds; a no-op when SELinux is off.
	_, _ = system.Run(context.Background(), "restorecon", "-R", dir)
	return nil
}

// lookupUID / lookupGID resolve a system user / group name to its numeric id.
func lookupUID(name string) (int, error) {
	u, err := osuser.Lookup(name)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(u.Uid)
}
func lookupGID(name string) (int, error) {
	g, err := osuser.LookupGroup(name)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(g.Gid)
}

// shellQuote wraps s in single quotes for safe use in the run-script (the path
// is panel-derived from a validated domain, so this is hygiene, not a barrier).
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Start / Stop / Restart control a configured app unit.
func (m *Manager) Start(ctx context.Context, domain string) error { return m.svc(ctx, "start", domain) }
func (m *Manager) Stop(ctx context.Context, domain string) error  { return m.svc(ctx, "stop", domain) }
func (m *Manager) Restart(ctx context.Context, domain string) error {
	return m.svc(ctx, "restart", domain)
}

func (m *Manager) svc(ctx context.Context, action, domain string) error {
	if m.cfg.Dev {
		return nil
	}
	return system.ServiceAction(ctx, action, UnitName(domain))
}

// Status reports whether a site's app unit is active and enabled.
func (m *Manager) Status(ctx context.Context, domain string) (active, enabled bool) {
	if m.cfg.Dev {
		return false, false
	}
	return system.ServiceActive(ctx, UnitName(domain)), system.ServiceEnabled(ctx, UnitName(domain))
}

// Logs returns the last n journald lines for a site's app.
func (m *Manager) Logs(ctx context.Context, domain string, n int) (string, error) {
	if m.cfg.Dev {
		return "(logs are only available on a Linux host)", nil
	}
	return system.JournalTail(ctx, UnitName(domain), n)
}

func (m *Manager) renderUnit(app *store.App, site *store.Site, user string) string {
	var b strings.Builder
	_ = unitTmpl.Execute(&b, unitData{
		Domain: site.Domain, User: user, Group: user, WorkingDir: site.DocRoot,
		SocketPath: m.SocketPath(site.Domain),
		EnvFile:    m.envPath(site.Domain), ScriptPath: m.scriptPath(site.Domain),
	})
	return b.String()
}

type unitData struct {
	Domain, User, Group, WorkingDir string
	SocketPath                      string
	EnvFile, ScriptPath             string
}

// sanitizeCommand drops NUL bytes and caps length; the rest runs verbatim as
// the tenant via the run-script.
func sanitizeCommand(s string) string {
	s = strings.ReplaceAll(s, "\x00", "")
	s = strings.TrimSpace(s)
	if len(s) > 8192 {
		s = s[:8192]
	}
	return s
}

// renderEnv keeps only VALID KEY=VALUE lines (systemd EnvironmentFile syntax),
// rejecting PORT (the panel owns it) and malformed keys.
func renderEnv(env string) string {
	var out []string
	for _, line := range strings.Split(env, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "PORT" || !envKeyRe.MatchString(k) {
			continue
		}
		out = append(out, k+"="+strings.TrimRight(v, "\r"))
	}
	if len(out) == 0 {
		return ""
	}
	return strings.Join(out, "\n") + "\n"
}

// unitTmpl is the fixed systemd unit — only vetted, panel-controlled values are
// interpolated (User/WorkingDir/socket path/paths); the tenant command is not
// here. PORT holds the unix-socket path the app must listen on; it is set AFTER
// EnvironmentFile so the panel's value always wins over anything in user env.
var unitTmpl = template.Must(template.New("unit").Parse(`# Managed by Open ProPanel — do not edit by hand.
[Unit]
Description=Open ProPanel app: {{.Domain}}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User={{.User}}
Group={{.Group}}
WorkingDirectory={{.WorkingDir}}
EnvironmentFile=-{{.EnvFile}}
Environment=PORT={{.SocketPath}}
ExecStart=/bin/bash {{.ScriptPath}}
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
`))
