package store

import (
	"database/sql"
	"errors"
	"time"
)

// Database is a MariaDB database managed by Open ProPanel, owned by an account.
type Database struct {
	ID        int64
	UserID    int64
	Name      string
	CreatedAt time.Time
}

// DBUser is a MariaDB user account managed by Open ProPanel.
type DBUser struct {
	ID        int64
	UserID    int64
	Name      string
	CreatedAt time.Time
}

// ---------------------------------------------------------------------------
// Databases
// ---------------------------------------------------------------------------

func scanDatabase(row interface{ Scan(...any) error }) (*Database, error) {
	var d Database
	var created int64
	err := row.Scan(&d.ID, &d.UserID, &d.Name, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	d.CreatedAt = time.Unix(created, 0)
	return &d, nil
}

// CreateDatabase records a database.
func (s *Store) CreateDatabase(d *Database) (*Database, error) {
	now := time.Now()
	res, err := s.db.Exec(`INSERT INTO databases (user_id, name, created_at) VALUES (?, ?, ?)`,
		d.UserID, d.Name, now.Unix())
	if err != nil {
		return nil, err
	}
	if d.ID, err = res.LastInsertId(); err != nil {
		return nil, err
	}
	d.CreatedAt = now
	return d, nil
}

// DatabaseByID looks up a database by primary key.
func (s *Store) DatabaseByID(id int64) (*Database, error) {
	return scanDatabase(s.db.QueryRow(`SELECT id, user_id, name, created_at FROM databases WHERE id = ?`, id))
}

func (s *Store) queryDatabases(where string, args ...any) ([]*Database, error) {
	q := `SELECT id, user_id, name, created_at FROM databases`
	if where != "" {
		q += ` WHERE ` + where
	}
	q += ` ORDER BY name ASC`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Database
	for rows.Next() {
		d, err := scanDatabase(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ListDatabases returns every database (admin view).
func (s *Store) ListDatabases() ([]*Database, error) { return s.queryDatabases("") }

// ListDatabasesByUser returns the databases owned by an account.
func (s *Store) ListDatabasesByUser(userID int64) ([]*Database, error) {
	return s.queryDatabases("user_id = ?", userID)
}

// DeleteDatabase removes a database row (grants cascade).
func (s *Store) DeleteDatabase(id int64) error {
	_, err := s.db.Exec(`DELETE FROM databases WHERE id = ?`, id)
	return err
}

// ---------------------------------------------------------------------------
// Database users
// ---------------------------------------------------------------------------

func scanDBUser(row interface{ Scan(...any) error }) (*DBUser, error) {
	var u DBUser
	var created int64
	err := row.Scan(&u.ID, &u.UserID, &u.Name, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	u.CreatedAt = time.Unix(created, 0)
	return &u, nil
}

// CreateDBUser records a database user.
func (s *Store) CreateDBUser(u *DBUser) (*DBUser, error) {
	now := time.Now()
	res, err := s.db.Exec(`INSERT INTO db_users (user_id, name, created_at) VALUES (?, ?, ?)`,
		u.UserID, u.Name, now.Unix())
	if err != nil {
		return nil, err
	}
	if u.ID, err = res.LastInsertId(); err != nil {
		return nil, err
	}
	u.CreatedAt = now
	return u, nil
}

// DBUserByID looks up a database user by primary key.
func (s *Store) DBUserByID(id int64) (*DBUser, error) {
	return scanDBUser(s.db.QueryRow(`SELECT id, user_id, name, created_at FROM db_users WHERE id = ?`, id))
}

func (s *Store) queryDBUsers(where string, args ...any) ([]*DBUser, error) {
	q := `SELECT id, user_id, name, created_at FROM db_users`
	if where != "" {
		q += ` WHERE ` + where
	}
	q += ` ORDER BY name ASC`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*DBUser
	for rows.Next() {
		u, err := scanDBUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// ListDBUsers returns every database user (admin view).
func (s *Store) ListDBUsers() ([]*DBUser, error) { return s.queryDBUsers("") }

// ListDBUsersByUser returns the database users owned by an account.
func (s *Store) ListDBUsersByUser(userID int64) ([]*DBUser, error) {
	return s.queryDBUsers("user_id = ?", userID)
}

// DeleteDBUser removes a database user row (grants cascade).
func (s *Store) DeleteDBUser(id int64) error {
	_, err := s.db.Exec(`DELETE FROM db_users WHERE id = ?`, id)
	return err
}

// ---------------------------------------------------------------------------
// Grants
// ---------------------------------------------------------------------------

// CreateGrant links a database user to a database (idempotent).
func (s *Store) CreateGrant(databaseID, dbUserID int64) error {
	_, err := s.db.Exec(
		`INSERT OR IGNORE INTO db_grants (database_id, db_user_id) VALUES (?, ?)`,
		databaseID, dbUserID)
	return err
}

// DeleteGrant removes a single database-user ↔ database link.
func (s *Store) DeleteGrant(databaseID, dbUserID int64) error {
	_, err := s.db.Exec(`DELETE FROM db_grants WHERE database_id = ? AND db_user_id = ?`,
		databaseID, dbUserID)
	return err
}

// GrantedUsers returns the database users granted access to a database.
func (s *Store) GrantedUsers(databaseID int64) ([]*DBUser, error) {
	rows, err := s.db.Query(`
		SELECT u.id, u.user_id, u.name, u.created_at
		FROM db_grants g JOIN db_users u ON u.id = g.db_user_id
		WHERE g.database_id = ? ORDER BY u.name ASC`, databaseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*DBUser
	for rows.Next() {
		u, err := scanDBUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}
