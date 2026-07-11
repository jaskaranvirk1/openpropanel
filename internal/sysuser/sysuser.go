// Package sysuser provisions the Linux system accounts that own each hosting
// account's files and run its PHP-FPM pool. Creating a real OS user per tenant
// is what makes the per-site open_basedir + non-root pool isolation meaningful.
//
// All names are validated by the caller (web layer) with the same regex used
// for panel usernames; this package adds a second layer of safety: it refuses
// reserved/service names outright and refuses to *reuse* any existing account
// that is privileged (UID below minUID), so a pool can never be pointed at
// root or a daemon account.
package sysuser

import (
	"context"
	"fmt"
	osuser "os/user"
	"strconv"

	"github.com/openpropanel/openpropanel/internal/config"
	"github.com/openpropanel/openpropanel/internal/system"
)

// minUID is the lowest UID we treat as an ordinary (non-service) user.
const minUID = 1000

// reserved names must never be provisioned or used to run a pool.
var reserved = map[string]bool{
	"root": true, "bin": true, "daemon": true, "adm": true, "sync": true,
	"shutdown": true, "halt": true, "mail": true, "operator": true, "games": true,
	"ftp": true, "nobody": true, "apache": true, "httpd": true, "nginx": true,
	"mysql": true, "mariadb": true, "sshd": true, "dbus": true, "polkitd": true,
	"postfix": true, "chrony": true, "systemd-network": true, "systemd-resolve": true,
}

// Manager provisions and removes system users.
type Manager struct {
	cfg *config.Config
}

// New constructs a Manager.
func New(cfg *config.Config) *Manager { return &Manager{cfg: cfg} }

// Exists reports whether a system account with this name exists.
func (m *Manager) Exists(name string) bool {
	_, err := osuser.Lookup(name)
	return err == nil
}

// IsReserved reports whether name is a reserved service/system account that
// must never own tenant files or run a pool.
func IsReserved(name string) bool { return reserved[name] }

// Ensure guarantees an unprivileged system user exists, creating it with
// useradd (login-less, with a home directory) if necessary. It reuses an
// existing ordinary account, but refuses reserved names and privileged
// (service) accounts. On a non-Linux dev host it simulates success.
func (m *Manager) Ensure(ctx context.Context, name string) error {
	if reserved[name] {
		return fmt.Errorf("%q is a reserved system account", name)
	}
	if u, err := osuser.Lookup(name); err == nil {
		// Already present — only allow reuse of a genuine unprivileged user so a
		// pool can never end up running as a service/root account.
		if uid, e := strconv.Atoi(u.Uid); e == nil && uid < minUID {
			return fmt.Errorf("%q is a privileged system account (uid %d); refusing to use it", name, uid)
		}
		return nil
	}
	if m.cfg.Dev {
		return nil // no useradd on a developer machine
	}
	if _, err := system.Run(ctx, "useradd", "--create-home", "--shell", "/sbin/nologin", name); err != nil {
		return fmt.Errorf("create system user %q: %w", name, err)
	}
	return nil
}

// Remove deletes a system user, leaving its files on disk (Open ProPanel never
// destroys hosting data automatically). It is a no-op for empty/reserved names,
// for accounts that do not exist, and in dev mode. Callers must first confirm
// no other hosting account still references this system user.
func (m *Manager) Remove(ctx context.Context, name string) error {
	if name == "" || reserved[name] || !m.Exists(name) || m.cfg.Dev {
		return nil
	}
	if _, err := system.Run(ctx, "userdel", name); err != nil {
		return fmt.Errorf("delete system user %q: %w", name, err)
	}
	return nil
}
