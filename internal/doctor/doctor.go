// Package doctor runs a preflight/health check of the host environment and
// prints a human-readable report. It backs the `openpropanel doctor` command
// and is run by the installer at the end of setup so problems are surfaced
// clearly ("it just works, and tells you if it can't").
package doctor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/openpropanel/openpropanel/internal/config"
	"github.com/openpropanel/openpropanel/internal/system"
)

// Run prints the report and returns the number of hard failures (0 = healthy).
func Run(cfg *config.Config, cfgPath string) int {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fmt.Println("Open ProPanel — environment check")
	fmt.Println(strings.Repeat("─", 52))

	fails := 0
	ok := func(name, detail string) { fmt.Printf("  [ OK ]  %s%s\n", name, tail(detail)) }
	warn := func(name, detail string) { fmt.Printf("  [WARN]  %s%s\n", name, tail(detail)) }
	bad := func(name, detail string) { fails++; fmt.Printf("  [FAIL]  %s%s\n", name, tail(detail)) }

	linux := runtime.GOOS == "linux"
	if !linux {
		warn("Dev mode ("+runtime.GOOS+")", "system changes are simulated; host checks are limited")
	} else if os.Geteuid() == 0 {
		ok("Running as root", "")
	} else {
		bad("Not running as root", "the panel manages system services and must run as root")
	}

	// --- config + data dir permissions ---
	if linux {
		checkSecret(cfgPath, "config file", ok, bad)
		checkSecret(cfg.DataDir, "data dir", ok, bad)
	}

	// --- managed services ---
	if linux {
		serviceCheck(ctx, cfg.ActiveWebService(), "web server ("+cfg.ActiveWebService()+")", true, ok, bad, warn)
		serviceCheck(ctx, cfg.PHPFPMService, "PHP-FPM", true, ok, bad, warn)
		if system.ServiceActive(ctx, "mariadb") {
			ok("MariaDB active", "")
		} else {
			warn("MariaDB not active", "Databases & phpMyAdmin are disabled — dnf install -y mariadb-server && systemctl enable --now mariadb")
		}
		if _, err := exec.LookPath("certbot"); err == nil {
			ok("certbot present", "")
		} else {
			warn("certbot not found", "automatic Let's Encrypt SSL is disabled — dnf install -y certbot")
		}
		if system.ServiceActive(ctx, "firewalld") {
			ok("firewalld active", "")
		} else {
			warn("firewalld not active", "the panel port is not being filtered by firewalld")
		}
		if out, err := exec.CommandContext(ctx, "getenforce").Output(); err == nil {
			ok("SELinux", strings.TrimSpace(string(out)))
		}
	}

	// --- panel TLS ---
	ok("Panel TLS", tlsKind(cfg))

	// --- access reminder ---
	ok("Panel listens on", cfg.ListenAddr+"  (open https://<server-ip>"+cfg.ListenAddr+" — it's HTTPS)")

	fmt.Println(strings.Repeat("─", 52))
	if fails == 0 {
		fmt.Println("All critical checks passed. ✔")
	} else {
		fmt.Printf("%d critical problem(s) found — see [FAIL] above.\n", fails)
	}
	return fails
}

func serviceCheck(ctx context.Context, unit, label string, critical bool,
	ok, bad, warn func(string, string)) {
	if system.ServiceActive(ctx, unit) {
		ok(label+" active", "")
		return
	}
	msg := "not active — systemctl status " + unit
	if critical {
		bad(label+" not active", msg)
	} else {
		warn(label+" not active", msg)
	}
}

// checkSecret flags a path that is group/world accessible (secrets must be 0700/0600).
func checkSecret(path, label string, ok, bad func(string, string)) {
	fi, err := os.Stat(path)
	if err != nil {
		return // absent config falls back to defaults; nothing to check
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		bad(label+" is group/world accessible", fmt.Sprintf("%s (%#o) — chmod 0700 dir / 0600 file", path, perm))
		return
	}
	ok(label+" permissions", path)
}

func tlsKind(cfg *config.Config) string {
	if c, k := cfg.TLSOverride(); c != "" && k != "" {
		if strings.Contains(c, "letsencrypt") {
			return "Let's Encrypt certificate (" + c + ")"
		}
		return "custom certificate (" + c + ")"
	}
	// The drop-in is only served when BOTH files are present (see tls.resolvePaths).
	crt := cfg.CertDir() + string(os.PathSeparator) + "panel.crt"
	key := cfg.CertDir() + string(os.PathSeparator) + "panel.key"
	if isFile(crt) && isFile(key) {
		return "drop-in certificate (" + crt + ")"
	}
	return "self-signed (browser will warn — configure a domain under Settings → Panel HTTPS for a free cert)"
}

func tail(detail string) string {
	if detail == "" {
		return ""
	}
	return " — " + detail
}

func isFile(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}
