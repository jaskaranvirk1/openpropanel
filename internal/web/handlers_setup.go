package web

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/openpropanel/openpropanel/internal/auth"
)

// setupGate forces the first-login setup wizard: while SetupPending is set (the
// initial admin still has its random bootstrap password), every authenticated
// route redirects to /setup, except /setup itself and /logout. It runs INSIDE
// the auth middleware, so the user is already resolved.
func (s *Server) setupGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.SetupRequired() && r.URL.Path != "/setup" && r.URL.Path != "/logout" {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) getSetup(w http.ResponseWriter, r *http.Request) {
	// If setup is already done, don't show the wizard again.
	if !s.cfg.SetupRequired() {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	s.render.page(w, http.StatusOK, "setup", pageData{
		User:  auth.UserFrom(r.Context()),
		Error: r.URL.Query().Get("err"),
	})
}

// postSetup applies the operator's chosen username + password, then clears the
// setup flag so normal navigation resumes.
func (s *Server) postSetup(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.SetupRequired() {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	u := auth.UserFrom(r.Context())
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	username := strings.TrimSpace(strings.ToLower(r.FormValue("username")))
	password := r.FormValue("password")
	confirm := r.FormValue("confirm")

	if !usernameRe.MatchString(username) {
		redirect(w, r, "/setup", "err", "Username must be 3-32 chars: letters, digits, underscore or hyphen, starting with a letter or digit")
		return
	}
	if len(password) < 8 {
		redirect(w, r, "/setup", "err", "Password must be at least 8 characters")
		return
	}
	if password != confirm {
		redirect(w, r, "/setup", "err", "The two passwords do not match")
		return
	}
	// If the username is changing, make sure it isn't taken by another account.
	if username != u.Username {
		if other, err := s.store.UserByUsername(username); err == nil && other.ID != u.ID {
			redirect(w, r, "/setup", "err", "That username is already taken")
			return
		}
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		redirect(w, r, "/setup", "err", "Could not secure the password — please try again")
		return
	}
	if err := s.store.UpdateUserCredentials(u.ID, username, hash); err != nil {
		redirect(w, r, "/setup", "err", "Could not save the account (is the username taken?)")
		return
	}

	s.cfg.ClearSetupPending()
	_ = s.cfg.Save(s.cfgPath)
	// The bootstrap password file is now obsolete.
	_ = os.Remove(filepath.Join(s.cfg.DataDir, "initial-admin-password.txt"))

	redirect(w, r, "/dashboard", "msg", "All set — your account is ready.")
}
