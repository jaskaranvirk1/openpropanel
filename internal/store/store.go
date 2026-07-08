// Package store is Open ProPanel's persistence layer. It uses SQLite via the
// pure-Go modernc.org/sqlite driver, which means no CGO and therefore a single
// static binary that cross-compiles trivially for the AlmaLinux target.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

// ErrNotFound is returned by lookups that match no row.
var ErrNotFound = errors.New("openpropanel: record not found")

// Roles.
const (
	RoleAdmin = "admin"
	RoleUser  = "user"
)

// Site types.
const (
	SiteMain      = "main"
	SiteSubdomain = "subdomain"
)

// Store wraps the database connection and exposes typed accessors.
type Store struct {
	db *sql.DB
}

// User is a panel account. Admins manage the server; users own hosting sites.
type User struct {
	ID           int64
	Username     string
	Email        string
	PasswordHash string
	Role         string
	SystemUser   string // Linux system user that owns this account's files
	CreatedAt    time.Time
}

// Site is a domain or subdomain served by Apache.
type Site struct {
	ID         int64
	UserID     int64
	Domain     string
	Type       string
	ParentID   sql.NullInt64
	DocRoot    string
	PHPVersion string
	SSLEnabled bool
	CreatedAt  time.Time
}

// Session is a logged-in cookie session.
type Session struct {
	Token     string
	UserID    int64
	ExpiresAt time.Time
}

// Open opens (creating if needed) the SQLite database at path and runs
// migrations. Timestamps are stored as Unix seconds to avoid driver-specific
// time parsing quirks.
func Open(path string) (*Store, error) {
	dsn := fmt.Sprintf(
		"file:%s?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)",
		path,
	)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// SQLite serializes writers; a single connection keeps things simple and
	// avoids spurious "database is locked" errors for this low-traffic panel.
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

// Close releases the database handle.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    email         TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user',
    system_user   TEXT NOT NULL DEFAULT '',
    created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sites (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    domain      TEXT NOT NULL UNIQUE,
    type        TEXT NOT NULL DEFAULT 'main',
    parent_id   INTEGER REFERENCES sites(id) ON DELETE CASCADE,
    doc_root    TEXT NOT NULL,
    php_version TEXT NOT NULL DEFAULT '',
    ssl_enabled INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS databases (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name       TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS db_users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name       TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS db_grants (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    database_id INTEGER NOT NULL REFERENCES databases(id) ON DELETE CASCADE,
    db_user_id  INTEGER NOT NULL REFERENCES db_users(id) ON DELETE CASCADE,
    UNIQUE(database_id, db_user_id)
);

CREATE INDEX IF NOT EXISTS idx_sites_user ON sites(user_id);
CREATE INDEX IF NOT EXISTS idx_sites_parent ON sites(parent_id);
CREATE INDEX IF NOT EXISTS idx_databases_user ON databases(user_id);
CREATE INDEX IF NOT EXISTS idx_dbusers_user ON db_users(user_id);
`
	_, err := s.db.Exec(schema)
	return err
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

// CountUsers returns the total number of accounts (used to detect first-run).
func (s *Store) CountUsers() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// CreateUser inserts a new account and returns it with its assigned ID.
func (s *Store) CreateUser(u *User) (*User, error) {
	now := time.Now()
	res, err := s.db.Exec(
		`INSERT INTO users (username, email, password_hash, role, system_user, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		u.Username, u.Email, u.PasswordHash, u.Role, u.SystemUser, now.Unix(),
	)
	if err != nil {
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	u.ID = id
	u.CreatedAt = now
	return u, nil
}

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	var created int64
	err := row.Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.Role, &u.SystemUser, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	u.CreatedAt = time.Unix(created, 0)
	return &u, nil
}

const userCols = `id, username, email, password_hash, role, system_user, created_at`

// UserByUsername looks up an account by its login name.
func (s *Store) UserByUsername(username string) (*User, error) {
	row := s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE username = ?`, username)
	return scanUser(row)
}

// UserByID looks up an account by primary key.
func (s *Store) UserByID(id int64) (*User, error) {
	row := s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE id = ?`, id)
	return scanUser(row)
}

// ListUsers returns all accounts ordered by creation time.
func (s *Store) ListUsers() ([]*User, error) {
	rows, err := s.db.Query(`SELECT ` + userCols + ` FROM users ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// UpdateUserPassword sets a new bcrypt hash for an account.
func (s *Store) UpdateUserPassword(id int64, hash string) error {
	_, err := s.db.Exec(`UPDATE users SET password_hash = ? WHERE id = ?`, hash, id)
	return err
}

// DeleteUser removes an account (and, via cascade, its sites and sessions).
func (s *Store) DeleteUser(id int64) error {
	_, err := s.db.Exec(`DELETE FROM users WHERE id = ?`, id)
	return err
}

// CountBySystemUser returns how many accounts reference a given Linux system
// user, so callers can avoid removing a system user still in use by others.
func (s *Store) CountBySystemUser(name string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE system_user = ?`, name).Scan(&n)
	return n, err
}

// ---------------------------------------------------------------------------
// Sites
// ---------------------------------------------------------------------------

const siteCols = `id, user_id, domain, type, parent_id, doc_root, php_version, ssl_enabled, created_at`

func scanSite(row interface{ Scan(...any) error }) (*Site, error) {
	var st Site
	var created int64
	var ssl int
	err := row.Scan(&st.ID, &st.UserID, &st.Domain, &st.Type, &st.ParentID, &st.DocRoot, &st.PHPVersion, &ssl, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	st.SSLEnabled = ssl != 0
	st.CreatedAt = time.Unix(created, 0)
	return &st, nil
}

// CreateSite inserts a new site row.
func (s *Store) CreateSite(st *Site) (*Site, error) {
	now := time.Now()
	ssl := 0
	if st.SSLEnabled {
		ssl = 1
	}
	res, err := s.db.Exec(
		`INSERT INTO sites (user_id, domain, type, parent_id, doc_root, php_version, ssl_enabled, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		st.UserID, st.Domain, st.Type, st.ParentID, st.DocRoot, st.PHPVersion, ssl, now.Unix(),
	)
	if err != nil {
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	st.ID = id
	st.CreatedAt = now
	return st, nil
}

// SiteByID looks up a site by primary key.
func (s *Store) SiteByID(id int64) (*Site, error) {
	row := s.db.QueryRow(`SELECT `+siteCols+` FROM sites WHERE id = ?`, id)
	return scanSite(row)
}

// SiteByDomain looks up a site by its (unique) domain.
func (s *Store) SiteByDomain(domain string) (*Site, error) {
	row := s.db.QueryRow(`SELECT `+siteCols+` FROM sites WHERE domain = ?`, domain)
	return scanSite(row)
}

func (s *Store) querySites(where string, args ...any) ([]*Site, error) {
	q := `SELECT ` + siteCols + ` FROM sites`
	if where != "" {
		q += ` WHERE ` + where
	}
	q += ` ORDER BY type ASC, domain ASC`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Site
	for rows.Next() {
		st, err := scanSite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// ListSites returns every site (admin view).
func (s *Store) ListSites() ([]*Site, error) { return s.querySites("") }

// ListSitesByUser returns the sites owned by a single account.
func (s *Store) ListSitesByUser(userID int64) ([]*Site, error) {
	return s.querySites("user_id = ?", userID)
}

// ListSubdomains returns the subdomains of a parent site.
func (s *Store) ListSubdomains(parentID int64) ([]*Site, error) {
	return s.querySites("parent_id = ?", parentID)
}

// UpdateSitePHP changes the PHP version recorded for a site.
func (s *Store) UpdateSitePHP(id int64, version string) error {
	_, err := s.db.Exec(`UPDATE sites SET php_version = ? WHERE id = ?`, version, id)
	return err
}

// SetSiteSSL records whether SSL is enabled for a site.
func (s *Store) SetSiteSSL(id int64, enabled bool) error {
	v := 0
	if enabled {
		v = 1
	}
	_, err := s.db.Exec(`UPDATE sites SET ssl_enabled = ? WHERE id = ?`, v, id)
	return err
}

// DeleteSite removes a site (and its subdomains via cascade).
func (s *Store) DeleteSite(id int64) error {
	_, err := s.db.Exec(`DELETE FROM sites WHERE id = ?`, id)
	return err
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

// CreateSession stores a login session token.
func (s *Store) CreateSession(sess *Session) error {
	_, err := s.db.Exec(
		`INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)`,
		sess.Token, sess.UserID, sess.ExpiresAt.Unix(),
	)
	return err
}

// SessionUser resolves a session token to its (non-expired) user.
func (s *Store) SessionUser(token string) (*User, error) {
	var userID int64
	var expires int64
	err := s.db.QueryRow(`SELECT user_id, expires_at FROM sessions WHERE token = ?`, token).
		Scan(&userID, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if time.Now().Unix() > expires {
		_ = s.DeleteSession(token)
		return nil, ErrNotFound
	}
	return s.UserByID(userID)
}

// DeleteSession removes a single session (logout).
func (s *Store) DeleteSession(token string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE token = ?`, token)
	return err
}

// DeleteExpiredSessions garbage-collects stale sessions.
func (s *Store) DeleteExpiredSessions() error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at < ?`, time.Now().Unix())
	return err
}
