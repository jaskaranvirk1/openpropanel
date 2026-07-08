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
	"github.com/openpropanel/openpropanel/internal/auth"
	"github.com/openpropanel/openpropanel/internal/config"
	"github.com/openpropanel/openpropanel/internal/domains"
	"github.com/openpropanel/openpropanel/internal/mariadb"
	"github.com/openpropanel/openpropanel/internal/nginx"
	"github.com/openpropanel/openpropanel/internal/php"
	"github.com/openpropanel/openpropanel/internal/phpmyadmin"
	"github.com/openpropanel/openpropanel/internal/ssl"
	"github.com/openpropanel/openpropanel/internal/store"
	"github.com/openpropanel/openpropanel/internal/sysuser"
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
	listen := flag.String("listen", "", "override listen address (e.g. :2087)")
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

	st, err := store.Open(cfg.DBPath())
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer st.Close()
	_ = st.DeleteExpiredSessions()

	if err := ensureAdmin(cfg, st); err != nil {
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
	domainSvc := domains.New(cfg, *cfgPath, st, apacheMgr, nginxMgr, phpMgr, sslMgr, sysuserMgr, mariadbMgr)

	// Adopt any vhosts already configured on the host so they show up in the
	// panel immediately (imported, read-only until explicitly adopted).
	if n, ierr := domainSvc.ImportExisting(context.Background()); ierr != nil {
		log.Printf("scan for existing sites: %v", ierr)
	} else if n > 0 {
		log.Printf("imported %d existing site(s) already configured on this host", n)
	}

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
// generated password both on stdout and in a 0600 file in the data directory.
func ensureAdmin(cfg *config.Config, st *store.Store) error {
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

	line := "──────────────────────────────────────────────────────"
	log.Printf("\n%s\n  Open ProPanel first-run: admin account created\n    username: %s\n    password: %s\n  (also saved to %s)\n  Log in and change the password right away.\n%s", line, username, pw, credFile, line)
	return nil
}

func randomHex(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
