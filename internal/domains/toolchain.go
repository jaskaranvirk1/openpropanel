package domains

import (
	"context"
	"fmt"
	"strings"

	"github.com/openpropanel/openpropanel/internal/system"
)

// InstallBuildTools installs the deploy build toolchain — Node.js/npm (Angular/
// React/Vite frontend builds) and, best effort, Composer (Laravel/PHP builds) —
// with the system package manager (dnf).
//
// The panel's own service runs with ProtectSystem=true, so /usr is read-only and
// a direct package install would fail; the install therefore runs OUTSIDE that
// sandbox via system.RunHost (systemd-run). The commands are FIXED — no
// caller-supplied input reaches the shell/argv — so this is safe to trigger from
// the admin UI and the AI assistant. It is idempotent: re-running when a tool is
// already present is a no-op. Simulated in dev mode.
func (s *Service) InstallBuildTools(ctx context.Context) (string, error) {
	if s.cfg.Dev {
		return "Dev mode: would install Node.js/npm and Composer with the system package manager (dnf).", nil
	}
	// One install at a time. dnf itself takes a system lock, but this stops a
	// button-mash or a prompt-injected loop from piling up waiting dnf processes.
	if !s.buildToolsMu.TryLock() {
		return "", fmt.Errorf("a build-tools install is already running — wait about a minute for it to finish, then check again")
	}
	defer s.buildToolsMu.Unlock()

	var b strings.Builder
	// Node.js (bundles npm) — required for Angular/React/Vite builds. Hard-fail
	// if this cannot be installed, since it is the common case.
	if _, err := system.RunHost(ctx, "dnf", "install", "-y", "nodejs"); err != nil {
		// A context timeout SIGKILLs the systemd-run client, but the transient dnf
		// unit keeps running to completion. Report that honestly instead of a bare
		// "failed", and steer the operator away from an immediate retry (which
		// would hit dnf's lock).
		if ctx.Err() != nil {
			return "", fmt.Errorf("the install is taking longer than expected and is still running in the background — wait a minute, then check with a deploy; do not start another install yet")
		}
		return b.String(), fmt.Errorf("could not install Node.js: %w", err)
	}
	b.WriteString("Node.js and npm are installed.")
	// Composer may only be packaged in EPEL — enable it best-effort, then install.
	// Composer is optional (only Laravel/PHP builds need it), so a failure here is
	// a warning, not an error.
	_, _ = system.RunHost(ctx, "dnf", "install", "-y", "epel-release")
	if _, err := system.RunHost(ctx, "dnf", "install", "-y", "composer"); err != nil {
		if ctx.Err() != nil {
			b.WriteString(" Composer is still installing in the background — check again shortly.")
			return b.String(), nil
		}
		b.WriteString(" Composer could not be installed automatically — Laravel/PHP builds need it; install it from getcomposer.org.")
	} else {
		b.WriteString(" Composer is installed.")
	}
	b.WriteString(" You can deploy now.")
	return b.String(), nil
}
