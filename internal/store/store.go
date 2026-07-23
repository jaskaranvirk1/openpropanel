// Package store is Open ProPanel's persistence layer. It uses SQLite via the
// pure-Go modernc.org/sqlite driver, which means no CGO and therefore a single
// static binary that cross-compiles trivially for the AlmaLinux target.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
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

// Site sources.
const (
	SourceManaged  = "managed"  // vhost generated & owned by Open ProPanel
	SourceImported = "imported" // discovered from a pre-existing config
)

// Web serving modes for a site's document root.
const (
	WebModePHP    = "php"    // PHP-FPM handler + index.php (default; today's behaviour)
	WebModeStatic = "static" // plain static files, no SPA fallback
	WebModeSPA    = "spa"    // single-page app: unknown paths fall back to index.html
	WebModeProxy  = "proxy"  // reverse-proxy to a local app port (Node/Python/…)
)

// Site is a domain or subdomain served by the active web server.
type Site struct {
	ID         int64
	UserID     int64
	Domain     string
	Type       string
	ParentID   sql.NullInt64
	DocRoot    string
	PHPVersion string
	SSLEnabled bool
	CertFile   string // TLS cert path when custom (adopted sites); "" = panel-managed Let's Encrypt path
	KeyFile    string // TLS key path when custom; "" = panel-managed
	Source     string // SourceManaged | SourceImported
	ConfFile   string // original config path (for imported sites)
	RepoID     sql.NullInt64 // linked GitHub repo (project), if any
	RepoSubdir string        // folder inside the repo checkout this doc root maps to
	WebMode    string        // WebModePHP | WebModeStatic | WebModeSPA
	CreatedAt  time.Time
}

// Repo is a GitHub repository linked to a project (its parent site), cloned once
// into checkout_dir; each domain/subdomain points its doc root at a subfolder.
type Repo struct {
	ID            int64
	ProjectSiteID int64
	Provider      string
	Owner         string
	Name          string
	URL           string
	AuthMode      string // deploy_key | pat | https_public
	Branch        string
	CheckoutDir   string
	PublicKey     string // deploy key public half (safe to store/display)
	KeyFingerprint string
	LastCommit    string
	LastStatus    string // ok | error | cloning | deploying
	LastError     string
	LastDeployAt  sql.NullInt64
	WebhookSecret string // HMAC key for the GitHub push webhook ("" = webhook disabled)
	DetectNote    string // standing note from app auto-detection (e.g. "needs a build step")
	CreatedAt     time.Time
}

// App is a reverse-proxied application attached to a site: the start command the
// panel supervises via a systemd unit running as the site's tenant user. The
// vhost forwards to the app over a private per-tenant unix socket.
type App struct {
	ID     int64
	SiteID int64
	// Port is a legacy NOT NULL UNIQUE column (the app is addressed by unix
	// socket now); it is populated with the site id as an inert unique value.
	Port         int
	Runtime      string // "node" | "python" | "custom" (label only)
	StartCommand string
	Managed      bool   // panel supervises the process via systemd (always true)
	Env          string // newline-separated KEY=VALUE
	LastStatus   string
	CreatedAt    time.Time
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
    source      TEXT NOT NULL DEFAULT 'managed',
    conf_file   TEXT NOT NULL DEFAULT '',
    repo_id     INTEGER,
    repo_subdir TEXT NOT NULL DEFAULT '',
    web_mode    TEXT NOT NULL DEFAULT 'php',
    cert_file   TEXT NOT NULL DEFAULT '',
    key_file    TEXT NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS repos (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    project_site_id INTEGER NOT NULL UNIQUE REFERENCES sites(id) ON DELETE CASCADE,
    provider        TEXT NOT NULL DEFAULT 'github',
    owner           TEXT NOT NULL,
    name            TEXT NOT NULL,
    url             TEXT NOT NULL,
    auth_mode       TEXT NOT NULL DEFAULT 'deploy_key',
    branch          TEXT NOT NULL DEFAULT 'main',
    checkout_dir    TEXT NOT NULL,
    public_key      TEXT NOT NULL DEFAULT '',
    key_fingerprint TEXT NOT NULL DEFAULT '',
    last_commit     TEXT NOT NULL DEFAULT '',
    last_status     TEXT NOT NULL DEFAULT '',
    last_error      TEXT NOT NULL DEFAULT '',
    last_deploy_at  INTEGER,
    webhook_secret  TEXT NOT NULL DEFAULT '',
    detect_note     TEXT NOT NULL DEFAULT '',
    created_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS apps (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id       INTEGER NOT NULL UNIQUE REFERENCES sites(id) ON DELETE CASCADE,
    port          INTEGER NOT NULL UNIQUE,
    runtime       TEXT NOT NULL DEFAULT '',
    start_command TEXT NOT NULL DEFAULT '',
    managed       INTEGER NOT NULL DEFAULT 0,
    env           TEXT NOT NULL DEFAULT '',
    last_status   TEXT NOT NULL DEFAULT '',
    created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS cron_jobs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    minute     TEXT NOT NULL DEFAULT '*',
    hour       TEXT NOT NULL DEFAULT '*',
    dom        TEXT NOT NULL DEFAULT '*',
    month      TEXT NOT NULL DEFAULT '*',
    dow        TEXT NOT NULL DEFAULT '*',
    command    TEXT NOT NULL,
    created_at INTEGER NOT NULL
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

CREATE TABLE IF NOT EXISTS dismissed_imports (
    domain     TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sites_user ON sites(user_id);
CREATE INDEX IF NOT EXISTS idx_sites_parent ON sites(parent_id);
CREATE INDEX IF NOT EXISTS idx_repos_project ON repos(project_site_id);
CREATE INDEX IF NOT EXISTS idx_apps_site ON apps(site_id);
CREATE INDEX IF NOT EXISTS idx_databases_user ON databases(user_id);
CREATE INDEX IF NOT EXISTS idx_dbusers_user ON db_users(user_id);
`
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}
	// Upgrade older databases: add columns that newer versions expect. SQLite
	// errors on a duplicate column, which we tolerate (already migrated).
	for _, alter := range []string{
		`ALTER TABLE sites ADD COLUMN source TEXT NOT NULL DEFAULT 'managed'`,
		`ALTER TABLE sites ADD COLUMN conf_file TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE sites ADD COLUMN repo_id INTEGER`,
		`ALTER TABLE sites ADD COLUMN repo_subdir TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE sites ADD COLUMN web_mode TEXT NOT NULL DEFAULT 'php'`,
		`ALTER TABLE sites ADD COLUMN cert_file TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE sites ADD COLUMN key_file TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE repos ADD COLUMN webhook_secret TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE repos ADD COLUMN detect_note TEXT NOT NULL DEFAULT ''`,
	} {
		if _, err := s.db.Exec(alter); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			return err
		}
	}
	// Ship C data migration (idempotent). Reverse-proxy apps moved from shared
	// TCP loopback ports to per-tenant unix sockets, and the "unmanaged" proxy
	// mode was retired:
	//  - Convert supervisable unmanaged apps (they have a start command) to managed
	//    so ReconcileApps materialises their socket + unit.
	//  - Drop the rest and revert their site to serving files, so its vhost no
	//    longer points at a socket nothing will ever create (which would 502).
	//  - Align every app's legacy `port` with its site_id: the column is now an
	//    inert NOT NULL UNIQUE mirror of site_id, so new inserts (port = site_id)
	//    can never collide with a stale allocated value from the old range.
	for _, stmt := range []string{
		`UPDATE sites SET web_mode = 'php' WHERE id IN (SELECT site_id FROM apps WHERE managed = 0 AND TRIM(start_command) = '')`,
		`DELETE FROM apps WHERE managed = 0 AND TRIM(start_command) = ''`,
		`UPDATE apps SET managed = 1 WHERE managed = 0`,
		`UPDATE apps SET port = site_id`,
	} {
		if _, err := s.db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
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

// CountAdmins returns how many admin accounts exist (used to prevent removing
// the last administrator).
func (s *Store) CountAdmins() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE role = ?`, RoleAdmin).Scan(&n)
	return n, err
}

// FirstAdmin returns the earliest-created admin account (used as the default
// owner for imported sites).
func (s *Store) FirstAdmin() (*User, error) {
	row := s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE role = ? ORDER BY created_at ASC, id ASC LIMIT 1`, RoleAdmin)
	return scanUser(row)
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

// UpdateUserSystemUser records the Linux system user backing an account (used
// by just-in-time tenant provisioning when an account gains its first site or
// repo deploy).
func (s *Store) UpdateUserSystemUser(id int64, name string) error {
	_, err := s.db.Exec(`UPDATE users SET system_user = ? WHERE id = ?`, name, id)
	return err
}

// UpdateUserCredentials sets both the username and the bcrypt hash for an
// account in one statement — used by the first-login setup wizard. The UNIQUE
// constraint on username surfaces a duplicate as an error.
func (s *Store) UpdateUserCredentials(id int64, username, hash string) error {
	_, err := s.db.Exec(`UPDATE users SET username = ?, password_hash = ? WHERE id = ?`, username, hash, id)
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

const siteCols = `id, user_id, domain, type, parent_id, doc_root, php_version, ssl_enabled, source, conf_file, repo_id, repo_subdir, web_mode, cert_file, key_file, created_at`

func scanSite(row interface{ Scan(...any) error }) (*Site, error) {
	var st Site
	var created int64
	var ssl int
	err := row.Scan(&st.ID, &st.UserID, &st.Domain, &st.Type, &st.ParentID, &st.DocRoot, &st.PHPVersion, &ssl, &st.Source, &st.ConfFile, &st.RepoID, &st.RepoSubdir, &st.WebMode, &st.CertFile, &st.KeyFile, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	st.SSLEnabled = ssl != 0
	if st.WebMode == "" {
		st.WebMode = WebModePHP
	}
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
	if st.Source == "" {
		st.Source = SourceManaged
	}
	res, err := s.db.Exec(
		`INSERT INTO sites (user_id, domain, type, parent_id, doc_root, php_version, ssl_enabled, source, conf_file, cert_file, key_file, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		st.UserID, st.Domain, st.Type, st.ParentID, st.DocRoot, st.PHPVersion, ssl, st.Source, st.ConfFile, st.CertFile, st.KeyFile, now.Unix(),
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

// SetSiteParent re-links a site as a subdomain of parentID (used when import
// discovers that a domain already tracked as a flat main is really a subdomain
// of another site, so the panel can group them under one project).
func (s *Store) SetSiteParent(id, parentID int64) error {
	_, err := s.db.Exec(`UPDATE sites SET type = ?, parent_id = ? WHERE id = ?`, SiteSubdomain, parentID, id)
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

// SetSiteCerts records a site's TLS certificate paths ("" = panel-managed
// Let's Encrypt paths, which renderVHost derives from the domain).
func (s *Store) SetSiteCerts(id int64, certFile, keyFile string) error {
	_, err := s.db.Exec(`UPDATE sites SET cert_file = ?, key_file = ? WHERE id = ?`, certFile, keyFile, id)
	return err
}

// MarkSiteManaged flips an imported site to fully-managed after adoption,
// recording the PHP version and clearing the original config-file reference.
func (s *Store) MarkSiteManaged(id int64, phpVersion string) error {
	_, err := s.db.Exec(
		`UPDATE sites SET source = ?, php_version = ?, conf_file = '' WHERE id = ?`,
		SourceManaged, phpVersion, id)
	return err
}

// DeleteSite removes a site (and its subdomains via cascade).
func (s *Store) DeleteSite(id int64) error {
	_, err := s.db.Exec(`DELETE FROM sites WHERE id = ?`, id)
	return err
}

// SetSiteMapping points a site's doc root at a subfolder of its project's repo
// checkout and records the serving mode (php|static|spa).
func (s *Store) SetSiteMapping(id int64, repoID sql.NullInt64, subdir, docRoot, webMode string) error {
	_, err := s.db.Exec(
		`UPDATE sites SET repo_id = ?, repo_subdir = ?, doc_root = ?, web_mode = ? WHERE id = ?`,
		repoID, subdir, docRoot, webMode, id)
	return err
}

// SetSiteServe updates a site's document root and serving mode WITHOUT touching
// its repo mapping — for a domain that is not fed by a linked repo (the repo
// path uses SetSiteMapping instead).
func (s *Store) SetSiteServe(id int64, docRoot, webMode string) error {
	_, err := s.db.Exec(`UPDATE sites SET doc_root = ?, web_mode = ? WHERE id = ?`, docRoot, webMode, id)
	return err
}

// ---------------------------------------------------------------------------
// Repositories (GitHub deploy)
// ---------------------------------------------------------------------------

const repoCols = `id, project_site_id, provider, owner, name, url, auth_mode, branch, checkout_dir, public_key, key_fingerprint, last_commit, last_status, last_error, last_deploy_at, webhook_secret, detect_note, created_at`

func scanRepo(row interface{ Scan(...any) error }) (*Repo, error) {
	var r Repo
	var created int64
	err := row.Scan(&r.ID, &r.ProjectSiteID, &r.Provider, &r.Owner, &r.Name, &r.URL, &r.AuthMode, &r.Branch,
		&r.CheckoutDir, &r.PublicKey, &r.KeyFingerprint, &r.LastCommit, &r.LastStatus, &r.LastError, &r.LastDeployAt,
		&r.WebhookSecret, &r.DetectNote, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	r.CreatedAt = time.Unix(created, 0)
	return &r, nil
}

// CreateRepo inserts a repository linked to a project (its parent site).
func (s *Store) CreateRepo(r *Repo) (*Repo, error) {
	now := time.Now()
	if r.Provider == "" {
		r.Provider = "github"
	}
	if r.Branch == "" {
		r.Branch = "main"
	}
	res, err := s.db.Exec(
		`INSERT INTO repos (project_site_id, provider, owner, name, url, auth_mode, branch, checkout_dir, public_key, key_fingerprint, last_commit, last_status, last_error, webhook_secret, detect_note, created_at)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		r.ProjectSiteID, r.Provider, r.Owner, r.Name, r.URL, r.AuthMode, r.Branch, r.CheckoutDir,
		r.PublicKey, r.KeyFingerprint, r.LastCommit, r.LastStatus, r.LastError, r.WebhookSecret, r.DetectNote, now.Unix())
	if err != nil {
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	r.ID = id
	r.CreatedAt = now
	return r, nil
}

// RepoByID looks up a repository by primary key.
func (s *Store) RepoByID(id int64) (*Repo, error) {
	return scanRepo(s.db.QueryRow(`SELECT `+repoCols+` FROM repos WHERE id = ?`, id))
}

// ListRepos returns every linked repository (used for startup reconciliation).
func (s *Store) ListRepos() ([]*Repo, error) {
	rows, err := s.db.Query(`SELECT ` + repoCols + ` FROM repos`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Repo
	for rows.Next() {
		r, err := scanRepo(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RepoByProject returns the repository linked to a project (its parent site).
func (s *Store) RepoByProject(siteID int64) (*Repo, error) {
	return scanRepo(s.db.QueryRow(`SELECT `+repoCols+` FROM repos WHERE project_site_id = ?`, siteID))
}

// SetRepoKey stores a repo's generated deploy-key public half + fingerprint.
func (s *Store) SetRepoKey(id int64, publicKey, fingerprint string) error {
	_, err := s.db.Exec(`UPDATE repos SET public_key = ?, key_fingerprint = ? WHERE id = ?`, publicKey, fingerprint, id)
	return err
}

// SetRepoWebhookSecret stores the HMAC key GitHub signs push webhooks with.
func (s *Store) SetRepoWebhookSecret(id int64, secret string) error {
	_, err := s.db.Exec(`UPDATE repos SET webhook_secret = ? WHERE id = ?`, secret, id)
	return err
}

// SetRepoDetectNote records the standing app-detection note shown on the repo
// card ("" clears it).
func (s *Store) SetRepoDetectNote(id int64, note string) error {
	_, err := s.db.Exec(`UPDATE repos SET detect_note = ? WHERE id = ?`, note, id)
	return err
}

// SetRepoBranch changes the branch a repo deploys from.
func (s *Store) SetRepoBranch(id int64, branch string) error {
	_, err := s.db.Exec(`UPDATE repos SET branch = ? WHERE id = ?`, branch, id)
	return err
}

// ClearRepoMapping detaches every site mapped into a repo's checkout, keeping
// doc_root/web_mode untouched so an unlinked site keeps serving its current
// files. Restores the invariant "RepoID valid ⇒ repo row exists" on unlink.
func (s *Store) ClearRepoMapping(repoID int64) error {
	_, err := s.db.Exec(`UPDATE sites SET repo_id = NULL, repo_subdir = '' WHERE repo_id = ?`, repoID)
	return err
}

// UpdateRepoDeploy records the outcome of a clone/deploy.
func (s *Store) UpdateRepoDeploy(id int64, commit, status, errMsg string, when time.Time) error {
	_, err := s.db.Exec(
		`UPDATE repos SET last_commit = ?, last_status = ?, last_error = ?, last_deploy_at = ? WHERE id = ?`,
		commit, status, errMsg, when.Unix(), id)
	return err
}

// ResetStaleRepoDeploys flips repos stranded in a busy status ("cloning" /
// "deploying") to a retryable error. Busy statuses are only ever resolved by
// an in-memory background job, so any busy row found at startup was orphaned
// by a restart mid-job — without this sweep its card would spin forever with
// every action hidden.
func (s *Store) ResetStaleRepoDeploys() error {
	_, err := s.db.Exec(
		`UPDATE repos SET last_status = 'error', last_error = 'the panel restarted during this deploy — click Deploy to retry'
		 WHERE last_status IN ('cloning', 'deploying')`)
	return err
}

// DeleteRepo removes a repository record (keys/checkout on disk are cleaned by
// the caller).
func (s *Store) DeleteRepo(id int64) error {
	_, err := s.db.Exec(`DELETE FROM repos WHERE id = ?`, id)
	return err
}

// ---------------------------------------------------------------------------
// Apps (reverse-proxied runtimes)
// ---------------------------------------------------------------------------

const appCols = `id, site_id, port, runtime, start_command, managed, env, last_status, created_at`

func scanApp(row interface{ Scan(...any) error }) (*App, error) {
	var a App
	var created int64
	var managed int
	err := row.Scan(&a.ID, &a.SiteID, &a.Port, &a.Runtime, &a.StartCommand, &managed, &a.Env, &a.LastStatus, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	a.Managed = managed != 0
	a.CreatedAt = time.Unix(created, 0)
	return &a, nil
}

// CreateApp inserts an app row (one per site; the site_id/port UNIQUE
// constraints are the race backstop for port allocation).
func (s *Store) CreateApp(a *App) (*App, error) {
	now := time.Now()
	m := 0
	if a.Managed {
		m = 1
	}
	res, err := s.db.Exec(
		`INSERT INTO apps (site_id, port, runtime, start_command, managed, env, last_status, created_at)
		 VALUES (?,?,?,?,?,?,?,?)`,
		a.SiteID, a.Port, a.Runtime, a.StartCommand, m, a.Env, a.LastStatus, now.Unix())
	if err != nil {
		return nil, err
	}
	a.ID, _ = res.LastInsertId()
	a.CreatedAt = now
	return a, nil
}

// AppBySite returns the app attached to a site (ErrNotFound when none).
func (s *Store) AppBySite(siteID int64) (*App, error) {
	return scanApp(s.db.QueryRow(`SELECT `+appCols+` FROM apps WHERE site_id = ?`, siteID))
}

// UpdateApp updates the runtime config of an app (not its port).
func (s *Store) UpdateApp(id int64, runtime, startCmd, env string, managed bool) error {
	m := 0
	if managed {
		m = 1
	}
	_, err := s.db.Exec(`UPDATE apps SET runtime = ?, start_command = ?, env = ?, managed = ? WHERE id = ?`,
		runtime, startCmd, env, m, id)
	return err
}

// SetAppStatus records the last observed process status.
func (s *Store) SetAppStatus(id int64, status string) error {
	_, err := s.db.Exec(`UPDATE apps SET last_status = ? WHERE id = ?`, status, id)
	return err
}

// DeleteApp removes an app row (freeing its port).
func (s *Store) DeleteApp(id int64) error {
	_, err := s.db.Exec(`DELETE FROM apps WHERE id = ?`, id)
	return err
}

// ListManagedApps returns every managed app (for boot-time unit reconcile).
func (s *Store) ListManagedApps() ([]*App, error) {
	rows, err := s.db.Query(`SELECT ` + appCols + ` FROM apps WHERE managed = 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*App
	for rows.Next() {
		a, err := scanApp(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// CronJob is one scheduled command owned by an account; it runs as that account's
// Linux system user via the user's crontab.
type CronJob struct {
	ID                             int64
	UserID                         int64
	Minute, Hour, Dom, Month, Dow  string
	Command                        string
	CreatedAt                      time.Time
}

func scanCronJob(row interface{ Scan(...any) error }) (*CronJob, error) {
	var c CronJob
	var created int64
	err := row.Scan(&c.ID, &c.UserID, &c.Minute, &c.Hour, &c.Dom, &c.Month, &c.Dow, &c.Command, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	c.CreatedAt = time.Unix(created, 0)
	return &c, nil
}

const cronCols = `id, user_id, minute, hour, dom, month, dow, command, created_at`

// CreateCronJob inserts a scheduled job for an account.
func (s *Store) CreateCronJob(c *CronJob) (*CronJob, error) {
	now := time.Now()
	res, err := s.db.Exec(
		`INSERT INTO cron_jobs (user_id, minute, hour, dom, month, dow, command, created_at) VALUES (?,?,?,?,?,?,?,?)`,
		c.UserID, c.Minute, c.Hour, c.Dom, c.Month, c.Dow, c.Command, now.Unix())
	if err != nil {
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	c.ID, c.CreatedAt = id, now
	return c, nil
}

// CronJobByID looks up one job.
func (s *Store) CronJobByID(id int64) (*CronJob, error) {
	return scanCronJob(s.db.QueryRow(`SELECT `+cronCols+` FROM cron_jobs WHERE id = ?`, id))
}

// DeleteCronJob removes a job.
func (s *Store) DeleteCronJob(id int64) error {
	_, err := s.db.Exec(`DELETE FROM cron_jobs WHERE id = ?`, id)
	return err
}

// ListCronJobsByUser returns an account's jobs, newest first.
func (s *Store) ListCronJobsByUser(userID int64) ([]*CronJob, error) {
	return s.cronQuery(`SELECT `+cronCols+` FROM cron_jobs WHERE user_id = ? ORDER BY id DESC`, userID)
}

// ListCronJobsAll returns every job (admin view / crontab reconciliation).
func (s *Store) ListCronJobsAll() ([]*CronJob, error) {
	return s.cronQuery(`SELECT ` + cronCols + ` FROM cron_jobs ORDER BY user_id, id`)
}

func (s *Store) cronQuery(q string, args ...any) ([]*CronJob, error) {
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*CronJob
	for rows.Next() {
		c, err := scanCronJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// DismissImport records that an imported site was removed from the panel, so
// startup discovery does not resurrect it while its on-disk config still exists.
func (s *Store) DismissImport(domain string) error {
	_, err := s.db.Exec(`INSERT OR IGNORE INTO dismissed_imports (domain, created_at) VALUES (?, ?)`,
		domain, time.Now().Unix())
	return err
}

// DismissedImports returns the set of dismissed import domains.
func (s *Store) DismissedImports() (map[string]bool, error) {
	rows, err := s.db.Query(`SELECT domain FROM dismissed_imports`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out[d] = true
	}
	return out, rows.Err()
}

// ClearDismissals forgets all dismissals (used by an explicit re-scan).
func (s *Store) ClearDismissals() error {
	_, err := s.db.Exec(`DELETE FROM dismissed_imports`)
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
