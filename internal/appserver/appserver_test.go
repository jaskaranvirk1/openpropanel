package appserver

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/openpropanel/openpropanel/internal/config"
	"github.com/openpropanel/openpropanel/internal/store"
)

func devManager(t *testing.T) *Manager {
	t.Helper()
	dir := t.TempDir()
	// Dev=true skips systemctl; AppConfDir/AppUnitDir fall back under DataDir.
	return New(&config.Config{Dev: true, DataDir: dir})
}

// The tenant's start command must NEVER be interpolated into the systemd unit —
// that would let a tenant inject directives like `User=root`. It belongs only in
// the root-owned run-script, which execs as the tenant.
func TestCommandNeverInUnit(t *testing.T) {
	m := devManager(t)
	app := &store.App{Port: 3100, StartCommand: "node server.js\nUser=root\nExecStartPre=/bin/rmforbomb"}
	site := &store.Site{Domain: "app.com", DocRoot: "/srv/app"}
	if err := m.Configure(context.Background(), app, site, "tenant7"); err != nil {
		t.Fatalf("configure: %v", err)
	}
	unit, err := os.ReadFile(m.unitPath("app.com"))
	if err != nil {
		t.Fatal(err)
	}
	u := string(unit)
	if strings.Contains(u, "server.js") || strings.Contains(u, "rmforbomb") {
		t.Fatal("start command leaked into the systemd unit")
	}
	// The only User= line must be the tenant, not an injected root.
	if strings.Count(u, "User=") != 1 || !strings.Contains(u, "User=tenant7") {
		t.Fatalf("unit User= is not exactly the tenant:\n%s", u)
	}
	if !strings.Contains(u, "ExecStart=/bin/bash "+m.scriptPath("app.com")) {
		t.Error("unit must exec the run-script, not the command")
	}
	// PORT carries the socket path and is set AFTER EnvironmentFile so it always wins.
	if !strings.Contains(u, "Environment=PORT="+m.SocketPath("app.com")) {
		t.Errorf("unit PORT must be the socket path:\n%s", u)
	}
	if strings.Index(u, "EnvironmentFile=") > strings.Index(u, "Environment=PORT=") {
		t.Error("Environment=PORT must come AFTER EnvironmentFile so the panel value wins")
	}

	// The command lands in the run-script, execed on the last line, after a umask
	// tightening and a stale-socket cleanup.
	script, err := os.ReadFile(m.scriptPath("app.com"))
	if err != nil {
		t.Fatal(err)
	}
	sc := string(script)
	if !strings.Contains(sc, "exec node server.js") {
		t.Errorf("run-script should exec the tenant command:\n%s", sc)
	}
	if !strings.Contains(sc, "umask 0007") {
		t.Error("run-script should tighten umask so the socket is group-connectable")
	}
	if !strings.Contains(sc, "rm -f '"+m.SocketPath("app.com")+"'") {
		t.Errorf("run-script should clear a stale socket before exec:\n%s", sc)
	}
}

// Configure creates the per-app socket directory (owner/mode are enforced only
// on Linux; here we just confirm the dir + path scheme exist in dev).
func TestConfigureCreatesSocketDir(t *testing.T) {
	m := devManager(t)
	app := &store.App{Port: 3200, StartCommand: "node x"}
	site := &store.Site{Domain: "sock.com", DocRoot: "/srv/s"}
	if err := m.Configure(context.Background(), app, site, "tenant7"); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(m.socketDir("sock.com")); err != nil || !fi.IsDir() {
		t.Fatalf("socket dir not created: %v", err)
	}
	if got, want := m.SocketPath("sock.com"), filepath.Join(m.socketDir("sock.com"), "app.sock"); got != want {
		t.Errorf("SocketPath = %q, want %q", got, want)
	}
}

// The run-script must be root-owned & world-readable but not writable (0755),
// and the env file 0600 (it may hold secrets).
func TestFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not honour Unix file modes")
	}
	m := devManager(t)
	app := &store.App{Port: 3101, StartCommand: "npm start", Env: "SECRET=hunter2"}
	site := &store.Site{Domain: "p.com", DocRoot: "/srv/p"}
	if err := m.Configure(context.Background(), app, site, "tenant7"); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{
		m.scriptPath("p.com"): 0o755,
		m.envPath("p.com"):    0o600,
	} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != want {
			t.Errorf("%s: mode %o, want %o", filepath.Base(path), got, want)
		}
	}
}

// Env is filtered to valid KEY=VALUE lines; PORT is reserved (the panel sets it)
// and malformed keys are dropped so nothing bleeds into the unit's Environment.
func TestRenderEnvFiltering(t *testing.T) {
	in := "NODE_ENV=production\nPORT=9999\nbad key=x\n# comment\nlower=y\nDB_URL=postgres://a:b@h/db\n"
	out := renderEnv(in)
	if !strings.Contains(out, "NODE_ENV=production") {
		t.Error("valid key should survive")
	}
	if !strings.Contains(out, "DB_URL=postgres://a:b@h/db") {
		t.Error("value with = and special chars should survive")
	}
	if strings.Contains(out, "PORT=") {
		t.Error("PORT must be rejected (panel-owned)")
	}
	if strings.Contains(out, "bad key") || strings.Contains(out, "lower=") {
		t.Error("malformed / lowercase keys must be dropped")
	}
}

// A root (or empty) system user must be refused — apps run as the tenant only.
func TestConfigureRefusesRoot(t *testing.T) {
	m := devManager(t)
	app := &store.App{Port: 3102, StartCommand: "node x"}
	site := &store.Site{Domain: "r.com", DocRoot: "/srv/r"}
	if err := m.Configure(context.Background(), app, site, "root"); err == nil {
		t.Error("Configure must refuse User=root")
	}
	if err := m.Configure(context.Background(), app, site, ""); err == nil {
		t.Error("Configure must refuse an empty system user")
	}
}

// An empty start command is an error (nothing to run).
func TestConfigureRequiresCommand(t *testing.T) {
	m := devManager(t)
	app := &store.App{Port: 3103, StartCommand: "   \n  "}
	site := &store.Site{Domain: "e.com", DocRoot: "/srv/e"}
	if err := m.Configure(context.Background(), app, site, "tenant7"); err == nil {
		t.Error("Configure must refuse an empty command")
	}
}

func TestSanitizeCommand(t *testing.T) {
	if got := sanitizeCommand("node\x00 x"); strings.ContainsRune(got, 0) {
		t.Error("NUL bytes must be stripped")
	}
	if got := sanitizeCommand(strings.Repeat("a", 9000)); len(got) > 8192 {
		t.Errorf("command not capped: len=%d", len(got))
	}
}
