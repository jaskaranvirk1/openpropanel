// Package mariadb runs administrative SQL against the local MariaDB/MySQL
// server. It shells out to the `mysql` client as root, which on AlmaLinux
// authenticates over the unix socket (no password needed), and pipes the SQL
// via stdin so no secret ever appears in the process argument list.
//
// NOTE: the panel currently talks to MariaDB as OS root (unix_socket => MariaDB
// root). De-privileging this to a dedicated least-privilege account is tracked
// as a follow-up: a partial-REVOKE of GRANT ALL is NOT sufficient (a global-DML
// account can rewrite the grant tables, and on MariaDB 10.5+ the SUPER split
// leaves SET USER), so it needs a positive least-privilege grant model with no
// privilege on the mysql schema — and validation against a live MariaDB.
//
// SECURITY: database and user *names* are validated by callers (the web layer)
// to a strict [a-z0-9_-] charset, so — combined with backtick/quote wrapping
// and escapeGrantDB for the LIKE-matched GRANT position — they cannot break out
// of their SQL context. The only free-form input is a user-chosen password,
// always emitted as an escaped single-quoted literal via escapeLiteral. Every
// mutating operation is recorded (secret-free) in the system audit log.
package mariadb

import (
	"context"
	"fmt"
	"strings"

	"github.com/openpropanel/openpropanel/internal/config"
	"github.com/openpropanel/openpropanel/internal/system"
)

// Manager executes MariaDB administrative operations.
type Manager struct {
	cfg *config.Config
}

// New constructs a Manager.
func New(cfg *config.Config) *Manager { return &Manager{cfg: cfg} }

// Available reports whether the local MariaDB server is reachable, so the UI
// can show a friendly "install MariaDB" state instead of failing an operation.
// In dev it is always true (the DB is stubbed); on a real host it checks that
// the mariadb service is active.
func (m *Manager) Available(ctx context.Context) bool {
	if m.cfg.Dev {
		return true
	}
	return system.ServiceActive(ctx, "mariadb")
}

// sessionPrologue pins the SQL parsing mode and connection charset for every
// script so that string-literal escaping is deterministic regardless of the
// server's global configuration:
//   - NO_BACKSLASH_ESCAPES makes backslash a literal character, so the ONLY way
//     to terminate a '...' literal is a quote — which escapeLiteral doubles.
//   - utf8mb4 avoids multibyte charsets (e.g. GBK) that could swallow an escape
//     byte and let a quote slip through.
const sessionPrologue = "SET SESSION sql_mode='NO_BACKSLASH_ESCAPES';\nSET NAMES utf8mb4;\n"

// exec pipes an SQL script to the mysql client. On a non-Linux dev host it is a
// no-op so the UI can be exercised without a database server.
func (m *Manager) exec(ctx context.Context, sql string) error {
	if m.cfg.Dev {
		return nil
	}
	_, err := system.RunInput(ctx, sessionPrologue+sql, "mysql", "--protocol=socket")
	return err
}

// CreateDatabase creates a utf8mb4 database. It fails if one already exists so
// callers never mistake a silent no-op for a fresh creation.
func (m *Manager) CreateDatabase(ctx context.Context, name string) error {
	system.Audit("mariadb", "CREATE DATABASE "+name)
	return m.exec(ctx, fmt.Sprintf(
		"CREATE DATABASE `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;", name))
}

// DropDatabase removes a database if present.
func (m *Manager) DropDatabase(ctx context.Context, name string) error {
	system.Audit("mariadb", "DROP DATABASE "+name)
	return m.exec(ctx, fmt.Sprintf("DROP DATABASE IF EXISTS `%s`;", name))
}

// CreateUser creates a localhost user with the given password.
func (m *Manager) CreateUser(ctx context.Context, name, password string) error {
	system.Audit("mariadb", "CREATE USER "+name)
	return m.exec(ctx, fmt.Sprintf(
		"CREATE USER '%s'@'localhost' IDENTIFIED BY '%s';", name, escapeLiteral(password)))
}

// SetPassword resets a user's password.
func (m *Manager) SetPassword(ctx context.Context, name, password string) error {
	system.Audit("mariadb", "SET PASSWORD "+name)
	return m.exec(ctx, fmt.Sprintf(
		"ALTER USER '%s'@'localhost' IDENTIFIED BY '%s';", name, escapeLiteral(password)))
}

// DropUser removes a user if present.
func (m *Manager) DropUser(ctx context.Context, name string) error {
	system.Audit("mariadb", "DROP USER "+name)
	return m.exec(ctx, fmt.Sprintf("DROP USER IF EXISTS '%s'@'localhost';", name))
}

// Grant gives a user ALL PRIVILEGES on a database.
func (m *Manager) Grant(ctx context.Context, dbName, userName string) error {
	system.Audit("mariadb", "GRANT "+dbName+" -> "+userName)
	return m.exec(ctx, fmt.Sprintf(
		"GRANT ALL PRIVILEGES ON `%s`.* TO '%s'@'localhost'; FLUSH PRIVILEGES;", escapeGrantDB(dbName), userName))
}

// Revoke removes a user's privileges on a database.
func (m *Manager) Revoke(ctx context.Context, dbName, userName string) error {
	system.Audit("mariadb", "REVOKE "+dbName+" -> "+userName)
	return m.exec(ctx, fmt.Sprintf(
		"REVOKE ALL PRIVILEGES ON `%s`.* FROM '%s'@'localhost'; FLUSH PRIVILEGES;", escapeGrantDB(dbName), userName))
}

// escapeLiteral makes a string safe inside a single-quoted SQL string literal
// by doubling embedded single quotes. Combined with the NO_BACKSLASH_ESCAPES
// session mode set in sessionPrologue, this is correct under both default and
// ANSI-compatible server configurations and preserves the value exactly (no
// backslash rewriting), so passwords are stored verbatim.
func escapeLiteral(s string) string {
	return strings.ReplaceAll(s, `'`, `''`)
}

// escapeGrantDB escapes the LIKE wildcards ('_' and '%') in a database name for
// the `db`.* position of GRANT/REVOKE. MySQL/MariaDB match that position with
// LIKE semantics, where '_' and '%' are wildcards and backtick quoting does NOT
// suppress them — only a backslash escape pins the grant to one literal
// database. Every panel db name is "<owner>_<suffix>" and contains underscores,
// so without this a grant intended for `alice_wp` would also authorize
// `aliceXwp`, `alice2_wp`, etc. — a cross-tenant privilege leak when one
// account name is a prefix of another. Inside a backtick-quoted identifier the
// backslash is preserved verbatim (identifier parsing performs no escape
// processing, so the NO_BACKSLASH_ESCAPES session mode does not apply here), and
// the privilege system then treats "\_" / "\%" as the literal characters.
// Callers validate names to [a-z0-9_-], so only '_' can actually occur, but '%'
// is escaped too as defence in depth against any future loosening.
func escapeGrantDB(name string) string {
	name = strings.ReplaceAll(name, "_", `\_`)
	name = strings.ReplaceAll(name, "%", `\%`)
	return name
}
