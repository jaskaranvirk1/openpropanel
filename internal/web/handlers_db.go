package web

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/openpropanel/openpropanel/internal/auth"
	"github.com/openpropanel/openpropanel/internal/store"
)

// dbSuffixRe validates the user-supplied part of a database / DB-user name. The
// full identifier is "<owner-username>_<suffix>"; restricting the suffix to
// [a-z0-9_] keeps the identifier safe to interpolate into SQL.
var dbSuffixRe = regexp.MustCompile(`^[a-z0-9_]{1,20}$`)

// ---------------------------------------------------------------------------
// view models
// ---------------------------------------------------------------------------

type dbRow struct {
	DB        *store.Database
	OwnerName string
	Granted   []*store.DBUser // users currently granted access
	Available []*store.DBUser // owner's users not yet granted (for the grant picker)
}

type dbUserRow struct {
	User      *store.DBUser
	OwnerName string
}

type databasesVM struct {
	Databases    []dbRow
	DBUsers      []dbUserRow
	IsAdmin      bool
	Users        []*store.User
	PMAInstalled bool
	MariaDBUp    bool
}

// ---------------------------------------------------------------------------
// page
// ---------------------------------------------------------------------------

func (s *Server) getDatabases(w http.ResponseWriter, r *http.Request) {
	viewer := auth.UserFrom(r.Context())
	isAdmin := viewer.Role == store.RoleAdmin

	var dbs []*store.Database
	var dbusers []*store.DBUser
	var err error
	if isAdmin {
		dbs, err = s.store.ListDatabases()
		if err == nil {
			dbusers, err = s.store.ListDBUsers()
		}
	} else {
		dbs, err = s.store.ListDatabasesByUser(viewer.ID)
		if err == nil {
			dbusers, err = s.store.ListDBUsersByUser(viewer.ID)
		}
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	names := map[int64]string{}
	if isAdmin {
		if users, e := s.store.ListUsers(); e == nil {
			for _, u := range users {
				names[u.ID] = u.Username
			}
		}
	} else {
		names[viewer.ID] = viewer.Username
	}

	// Group DB users by owner so each database can offer only its owner's users.
	usersByOwner := map[int64][]*store.DBUser{}
	for _, du := range dbusers {
		usersByOwner[du.UserID] = append(usersByOwner[du.UserID], du)
	}

	rows := make([]dbRow, 0, len(dbs))
	for _, d := range dbs {
		granted, _ := s.store.GrantedUsers(d.ID)
		grantedSet := map[int64]bool{}
		for _, g := range granted {
			grantedSet[g.ID] = true
		}
		var available []*store.DBUser
		for _, du := range usersByOwner[d.UserID] {
			if !grantedSet[du.ID] {
				available = append(available, du)
			}
		}
		rows = append(rows, dbRow{DB: d, OwnerName: names[d.UserID], Granted: granted, Available: available})
	}

	userRows := make([]dbUserRow, 0, len(dbusers))
	for _, du := range dbusers {
		userRows = append(userRows, dbUserRow{User: du, OwnerName: names[du.UserID]})
	}

	vm := databasesVM{
		Databases: rows, DBUsers: userRows, IsAdmin: isAdmin,
		PMAInstalled: s.pma.Installed(), MariaDBUp: s.mariadb.Available(r.Context()),
	}
	if isAdmin {
		vm.Users, _ = s.store.ListUsers()
	}
	s.render.page(w, http.StatusOK, "databases", pageData{
		User: viewer, Active: "databases",
		Flash: r.URL.Query().Get("msg"), Error: r.URL.Query().Get("err"),
		Data: vm,
	})
}

// ---------------------------------------------------------------------------
// databases
// ---------------------------------------------------------------------------

func (s *Server) postCreateDatabase(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.resolveOwner(w, r)
	if !ok {
		return
	}
	suffix := strings.TrimSpace(strings.ToLower(r.FormValue("name")))
	if !dbSuffixRe.MatchString(suffix) {
		redirect(w, r, "/databases", "err", "Database name must be 1-20 chars: a-z, 0-9, underscore")
		return
	}
	name := owner.Username + "_" + suffix
	// Record ownership FIRST: the UNIQUE(name) constraint rejects a duplicate
	// before we touch MariaDB, so the rollback path can never DROP a database
	// this request did not create (the earlier bug). On MariaDB failure we only
	// remove the store row we just inserted.
	db, err := s.store.CreateDatabase(&store.Database{UserID: owner.ID, Name: name})
	if err != nil {
		redirect(w, r, "/databases", "err", "Could not create database — the name "+name+" is already in use")
		return
	}
	if err := s.mariadb.CreateDatabase(r.Context(), name); err != nil {
		_ = s.store.DeleteDatabase(db.ID)
		redirect(w, r, "/databases", "err", s.opErr(r, err))
		return
	}
	redirect(w, r, "/databases", "msg", "Database "+name+" created")
}

func (s *Server) postDeleteDatabase(w http.ResponseWriter, r *http.Request) {
	viewer := auth.UserFrom(r.Context())
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	db, ok := s.ownedDatabase(w, viewer, id)
	if !ok {
		return
	}
	if err := s.mariadb.DropDatabase(r.Context(), db.Name); err != nil {
		redirect(w, r, "/databases", "err", s.opErr(r, err))
		return
	}
	if err := s.store.DeleteDatabase(db.ID); err != nil {
		redirect(w, r, "/databases", "err", s.opErr(r, err))
		return
	}
	redirect(w, r, "/databases", "msg", "Database "+db.Name+" deleted")
}

// ---------------------------------------------------------------------------
// database users
// ---------------------------------------------------------------------------

func (s *Server) postCreateDBUser(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.resolveOwner(w, r)
	if !ok {
		return
	}
	suffix := strings.TrimSpace(strings.ToLower(r.FormValue("name")))
	password := r.FormValue("password")
	if !dbSuffixRe.MatchString(suffix) {
		redirect(w, r, "/databases", "err", "DB user name must be 1-20 chars: a-z, 0-9, underscore")
		return
	}
	if len(password) < 8 {
		redirect(w, r, "/databases", "err", "Database user password must be at least 8 characters")
		return
	}
	name := owner.Username + "_" + suffix
	// Store first (same reasoning as databases): a duplicate name is rejected
	// before MariaDB, and the rollback only removes our own store row.
	du, err := s.store.CreateDBUser(&store.DBUser{UserID: owner.ID, Name: name})
	if err != nil {
		redirect(w, r, "/databases", "err", "Could not create database user — the name "+name+" is already in use")
		return
	}
	if err := s.mariadb.CreateUser(r.Context(), name, password); err != nil {
		_ = s.store.DeleteDBUser(du.ID)
		redirect(w, r, "/databases", "err", s.opErr(r, err))
		return
	}
	redirect(w, r, "/databases", "msg", "Database user "+name+" created")
}

func (s *Server) postDeleteDBUser(w http.ResponseWriter, r *http.Request) {
	viewer := auth.UserFrom(r.Context())
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	du, ok := s.ownedDBUser(w, viewer, id)
	if !ok {
		return
	}
	if err := s.mariadb.DropUser(r.Context(), du.Name); err != nil {
		redirect(w, r, "/databases", "err", s.opErr(r, err))
		return
	}
	if err := s.store.DeleteDBUser(du.ID); err != nil {
		redirect(w, r, "/databases", "err", s.opErr(r, err))
		return
	}
	redirect(w, r, "/databases", "msg", "Database user "+du.Name+" deleted")
}

func (s *Server) postResetDBUserPassword(w http.ResponseWriter, r *http.Request) {
	viewer := auth.UserFrom(r.Context())
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	du, ok := s.ownedDBUser(w, viewer, id)
	if !ok {
		return
	}
	password := r.FormValue("password")
	if len(password) < 8 {
		redirect(w, r, "/databases", "err", "New password must be at least 8 characters")
		return
	}
	if err := s.mariadb.SetPassword(r.Context(), du.Name, password); err != nil {
		redirect(w, r, "/databases", "err", s.opErr(r, err))
		return
	}
	redirect(w, r, "/databases", "msg", "Password updated for "+du.Name)
}

// ---------------------------------------------------------------------------
// grants
// ---------------------------------------------------------------------------

func (s *Server) postGrant(w http.ResponseWriter, r *http.Request)  { s.grantOrRevoke(w, r, true) }
func (s *Server) postRevoke(w http.ResponseWriter, r *http.Request) { s.grantOrRevoke(w, r, false) }

func (s *Server) grantOrRevoke(w http.ResponseWriter, r *http.Request, grant bool) {
	viewer := auth.UserFrom(r.Context())
	dbID, _ := strconv.ParseInt(r.FormValue("database_id"), 10, 64)
	userID, _ := strconv.ParseInt(r.FormValue("db_user_id"), 10, 64)

	db, ok := s.ownedDatabase(w, viewer, dbID)
	if !ok {
		return
	}
	du, ok := s.ownedDBUser(w, viewer, userID)
	if !ok {
		return
	}
	// A database and the user granted to it must belong to the same account —
	// no cross-tenant grants, even for an admin acting in the UI.
	if db.UserID != du.UserID {
		redirect(w, r, "/databases", "err", "Database and user belong to different accounts")
		return
	}

	if grant {
		if err := s.mariadb.Grant(r.Context(), db.Name, du.Name); err != nil {
			redirect(w, r, "/databases", "err", s.opErr(r, err))
			return
		}
		if err := s.store.CreateGrant(db.ID, du.ID); err != nil {
			_ = s.mariadb.Revoke(r.Context(), db.Name, du.Name) // roll back the live grant
			redirect(w, r, "/databases", "err", s.opErr(r, err))
			return
		}
		redirect(w, r, "/databases", "msg", du.Name+" granted access to "+db.Name)
		return
	}
	if err := s.mariadb.Revoke(r.Context(), db.Name, du.Name); err != nil {
		redirect(w, r, "/databases", "err", s.opErr(r, err))
		return
	}
	if err := s.store.DeleteGrant(db.ID, du.ID); err != nil {
		redirect(w, r, "/databases", "err", s.opErr(r, err))
		return
	}
	redirect(w, r, "/databases", "msg", du.Name+" access to "+db.Name+" revoked")
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// resolveOwner determines the account that will own a new database/user: the
// current user, or (for admins) the selected owner_id.
func (s *Server) resolveOwner(w http.ResponseWriter, r *http.Request) (*store.User, bool) {
	viewer := auth.UserFrom(r.Context())
	ownerID := viewer.ID
	if viewer.Role == store.RoleAdmin {
		if v := r.FormValue("owner_id"); v != "" {
			if id, err := strconv.ParseInt(v, 10, 64); err == nil {
				ownerID = id
			}
		}
	}
	owner, err := s.store.UserByID(ownerID)
	if err != nil {
		redirect(w, r, "/databases", "err", "Owner account not found")
		return nil, false
	}
	return owner, true
}

func (s *Server) ownedDatabase(w http.ResponseWriter, viewer *store.User, id int64) (*store.Database, bool) {
	db, err := s.store.DatabaseByID(id)
	if err != nil {
		http.Error(w, "database not found", http.StatusNotFound)
		return nil, false
	}
	if viewer.Role != store.RoleAdmin && db.UserID != viewer.ID {
		http.Error(w, "forbidden", http.StatusForbidden)
		return nil, false
	}
	return db, true
}

func (s *Server) ownedDBUser(w http.ResponseWriter, viewer *store.User, id int64) (*store.DBUser, bool) {
	du, err := s.store.DBUserByID(id)
	if err != nil {
		http.Error(w, "database user not found", http.StatusNotFound)
		return nil, false
	}
	if viewer.Role != store.RoleAdmin && du.UserID != viewer.ID {
		http.Error(w, "forbidden", http.StatusForbidden)
		return nil, false
	}
	return du, true
}
