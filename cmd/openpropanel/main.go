// Command openpropanel is the Open ProPanel server daemon: a single self-contained
// binary that serves the web UI and manages Apache, PHP-FPM and SSL on the
// host. It is designed to run as a systemd service on AlmaLinux/RHEL.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/openpropanel/openpropanel/internal/apache"
	"github.com/openpropanel/openpropanel/internal/appserver"
	"github.com/openpropanel/openpropanel/internal/auth"
	"github.com/openpropanel/openpropanel/internal/config"
	"github.com/openpropanel/openpropanel/internal/deploy"
	"github.com/openpropanel/openpropanel/internal/doctor"
	"github.com/openpropanel/openpropanel/internal/domains"
	"github.com/openpropanel/openpropanel/internal/mariadb"
	"github.com/openpropanel/openpropanel/internal/nginx"
	"github.com/openpropanel/openpropanel/internal/php"
	"github.com/openpropanel/openpropanel/internal/phpmyadmin"
	"github.com/openpropanel/openpropanel/internal/ssl"
	"github.com/openpropanel/openpropanel/internal/store"
	"github.com/openpropanel/openpropanel/internal/sysuser"
	"github.com/openpropanel/openpropanel/internal/system"
	"github.com/openpropanel/openpropanel/internal/web"
)

// version is stamped at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(); err != nil {
		log.Fatalf("openpropanel: %v", err)
	}
}

func run() error {
	defaultCfg := "/etc/openpropanel/config.json"
	if runtime.GOOS != "linux" {
		defaultCfg = filepath.Join("data", "config.json")
	}
	cfgPath := flag.String("config", defaultCfg, "path to config JSON file")
	listen := flag.String("listen", "", "override listen address (e.g. :9443)")
	tlsFlag := flag.String("tls", "", "override TLS: 'on' or 'off'")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("openpropanel", version)
		return nil
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// `openpropanel doctor` — environment health check, then exit.
	if flag.Arg(0) == "doctor" {
		os.Exit(doctor.Run(cfg, *cfgPath))
	}
	// `openpropanel reset-password [username]` — reset a panel account's password
	// to a new random one and print it (defaults to the first admin). Useful when
	// the first-run password was lost.
	if flag.Arg(0) == "reset-password" {
		os.Exit(resetPassword(cfg, flag.Arg(1)))
	}
	if *listen != "" {
		cfg.ListenAddr = *listen
	}
	switch *tlsFlag {
	case "on":
		cfg.TLSEnabled = true
	case "off":
		cfg.TLSEnabled = false
	}
	if cfg.SessionKey == "" {
		if cfg.SessionKey, err = randomHex(32); err != nil {
			return err
		}
		_ = cfg.Save(*cfgPath) // best-effort; persists the key for next boot
	}
	if err := cfg.EnsureDirs(); err != nil {
		return fmt.Errorf("prepare directories: %w", err)
	}
	if err := checkSecurePerms(*cfgPath, cfg.DataDir); err != nil {
		return err
	}
	// Append-only audit trail of every privileged action (best-effort).
	if err := system.EnableAudit(filepath.Join(cfg.DataDir, "audit.log")); err != nil {
		log.Printf("audit log disabled: %v", err)
	}

	st, err := store.Open(cfg.DBPath())
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer st.Close()
	_ = st.DeleteExpiredSessions()
	// Background clone/deploy jobs do not survive a restart; un-strand any repo
	// a previous process left mid-job so its card offers a retry.
	_ = st.ResetStaleRepoDeploys()

	if err := ensureAdmin(cfg, st, *cfgPath); err != nil {
		return err
	}

	// Wire the sub-systems. Session cookies are marked Secure whenever the panel
	// is served over HTTPS (the default in production), so they are never sent
	// over plaintext.
	authMgr := auth.New(st, cfg.TLSEnabled)
	apacheMgr := apache.New(cfg)
	nginxMgr := nginx.New(cfg)
	phpMgr := php.New(cfg)
	sslMgr := ssl.New(cfg)
	sysuserMgr := sysuser.New(cfg)
	mariadbMgr := mariadb.New(cfg)
	pmaMgr := phpmyadmin.New(cfg)
	deployMgr := deploy.New(cfg)
	appserverMgr := appserver.New(cfg)
	domainSvc := domains.New(cfg, *cfgPath, st, apacheMgr, nginxMgr, phpMgr, sslMgr, sysuserMgr, mariadbMgr, deployMgr, appserverMgr)

	// Adopt any vhosts already configured on the host so they show up in the
	// panel immediately (imported, read-only until explicitly adopted).
	if n, ierr := domainSvc.ImportExisting(context.Background()); ierr != nil {
		log.Printf("scan for existing sites: %v", ierr)
	} else if n > 0 {
		log.Printf("imported %d existing site(s) already configured on this host", n)
	}
	// Re-materialise managed app units (systemd) from the DB, in case a panel
	// upgrade or a wiped /etc/systemd left them out of date.
	domainSvc.ReconcileApps(context.Background())

	srv, err := web.New(cfg, st, authMgr, domainSvc, phpMgr, sysuserMgr, mariadbMgr, pmaMgr, *cfgPath)
	if err != nil {
		return fmt.Errorf("init web server: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cfg.Dev {
		log.Printf("Open ProPanel running in DEV mode — system changes are simulated. Data dir: %s", cfg.DataDir)
	}
	return srv.Start(ctx)
}

// ensureAdmin creates a default admin account on first run and surfaces the
// generated bootstrap password both on stdout and in a 0600 file in the data
// directory. It also flags SetupPending so the first login runs the setup
// wizard (choose your own username + password).
func ensureAdmin(cfg *config.Config, st *store.Store, cfgPath string) error {
	n, err := st.CountUsers()
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	pw, err := randomHex(12) // 24 hex chars
	if err != nil {
		return err
	}
	suffix, err := randomHex(3) // random username: admin_<6 hex>
	if err != nil {
		return err
	}
	username := "admin_" + suffix
	hash, err := auth.HashPassword(pw)
	if err != nil {
		return err
	}
	if _, err := st.CreateUser(&store.User{
		Username:     username,
		PasswordHash: hash,
		Role:         store.RoleAdmin,
	}); err != nil {
		return err
	}

	// Persist the generated credentials (0600) so the installer can print them.
	credFile := filepath.Join(cfg.DataDir, "initial-admin-password.txt")
	_ = os.WriteFile(credFile, []byte("username: "+username+"\npassword: "+pw+"\n"), 0o600)

	// First login must run the setup wizard (pick a real username + password).
	cfg.MarkSetupPending()
	_ = cfg.Save(cfgPath)

	line := "──────────────────────────────────────────────────────"
	log.Printf("\n%s\n  Open ProPanel first-run: admin account created\n    username: %s\n    password: %s\n  (also saved to %s)\n  Log in with these; you'll set your own username + password.\n%s", line, username, pw, credFile, line)
	return nil
}

// checkSecurePerms refuses to start if the config file or data directory is
// group- or world-writable: a writable config/state dir would let a local
// non-root user tamper with what the root panel reads and executes. Enforced on
// Linux only — Windows/dev file modes do not carry meaningful POSIX bits.
func checkSecurePerms(cfgPath, dataDir string) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	// The config file and data dir hold secrets (session key, the SQLite user
	// store, the first-run admin password, the audit log), so they must not be
	// group/world *accessible* at all — reject any of those bits, not just write.
	for _, p := range []string{cfgPath, dataDir} {
		fi, err := os.Stat(p)
		if err != nil {
			continue // absent config falls back to defaults; dir was just created
		}
		if perm := fi.Mode().Perm(); perm&0o077 != 0 {
			return fmt.Errorf("refusing to start: %s is group/world accessible (%#o) — chmod it to 0700 (dir) / 0600 (config)", p, perm)
		}
	}
	// A group/world-writable *parent* of the config would let a local user swap
	// the file out from under the 0600 check, so reject that too.
	if dir := filepath.Dir(cfgPath); dir != "" {
		if fi, err := os.Stat(dir); err == nil && fi.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("refusing to start: %s (config directory) is group/world-writable (%#o) — chmod it to 0755 or stricter", dir, fi.Mode().Perm())
		}
	}
	return nil
}

// resetPassword sets a new random password on a panel account (the first admin
// if no username is given) and prints it. Runs as a one-shot subcommand.
func resetPassword(cfg *config.Config, username string) int {
	st, err := store.Open(cfg.DBPath())
	if err != nil {
		fmt.Fprintln(os.Stderr, "open database:", err)
		return 1
	}
	defer st.Close()

	var u *store.User
	if username != "" {
		u, err = st.UserByUsername(username)
	} else {
		u, err = st.FirstAdmin()
	}
	if err != nil || u == nil {
		fmt.Fprintln(os.Stderr, "no matching account found (is the panel installed and initialised?)")
		return 1
	}
	pw, err := randomHex(12) // 24 hex chars
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := st.UpdateUserPassword(u.ID, hash); err != nil {
		fmt.Fprintln(os.Stderr, "update password:", err, "\n(if it says the database is locked, stop the service first: systemctl stop openpropanel)")
		return 1
	}
	fmt.Println("──────────────────────────────────────────────")
	fmt.Println("  Password reset. Log in with:")
	fmt.Printf("    username: %s\n", u.Username)
	fmt.Printf("    password: %s\n", pw)
	fmt.Println("──────────────────────────────────────────────")
	return 0
}

func randomHex(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
