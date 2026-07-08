package web

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/openpropanel/openpropanel/internal/auth"
	"github.com/openpropanel/openpropanel/internal/store"
)

// servePMA serves phpMyAdmin behind the panel session. It is mounted on the
// authenticated app mux, so the caller is always a logged-in panel user; they
// still have to authenticate to MariaDB with their own credentials (cookie
// auth), and MariaDB's privilege model scopes each user to their own databases.
func (s *Server) servePMA(w http.ResponseWriter, r *http.Request) {
	if !s.pma.Installed() {
		// Not installed yet — send admins to the Databases page where they can
		// install it, and tell everyone else it is unavailable.
		if u := auth.UserFrom(r.Context()); u != nil && u.Role == store.RoleAdmin {
			redirect(w, r, "/databases", "err", "phpMyAdmin is not installed yet — use the Install button below.")
			return
		}
		redirect(w, r, "/databases", "err", "phpMyAdmin is not available. Ask an administrator to install it.")
		return
	}
	if !s.throttlePMALogin(w, r) {
		return
	}
	s.pma.Handler().ServeHTTP(w, r)
}

// throttlePMALogin rate-limits phpMyAdmin's own cookie-auth login submissions.
// MariaDB has no per-account lockout, so without this a tenant could use the
// proxied phpMyAdmin login form as an unthrottled password-guessing oracle
// against other tenants' DB users — the panel already throttles its OWN login,
// and this brings phpMyAdmin to parity. It returns false (and writes the
// response) when the request should be blocked.
//
// Only small urlencoded POSTs are inspected (phpMyAdmin login posts are tiny);
// large multipart bodies — e.g. SQL imports — are passed straight through so
// they are never buffered or throttled.
func (s *Server) throttlePMALogin(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		return true
	}
	ct := r.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/x-www-form-urlencoded") || r.ContentLength < 0 || r.ContentLength > 64<<10 {
		return true
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	_ = r.Body.Close()
	// Restore the body for the downstream FastCGI handler regardless.
	r.Body = io.NopCloser(bytes.NewReader(body))
	if err != nil {
		return true
	}
	vals, _ := url.ParseQuery(string(body))
	if vals.Get("pma_username") == "" {
		return true // not a login submission
	}
	u := auth.UserFrom(r.Context())
	var uid int64
	if u != nil {
		uid = u.ID
	}
	key := fmt.Sprintf("pma:%d:%s", uid, clientIP(r))
	if ok, wait := s.pmaLogin.allow(key); !ok {
		http.Error(w, "Too many phpMyAdmin login attempts. Try again in "+wait.String()+".", http.StatusTooManyRequests)
		return false
	}
	// Count every submission: we cannot observe phpMyAdmin's success/failure, so
	// we bound the raw attempt rate (generous threshold, then exponential
	// backoff — a legitimate user logs in well within it).
	s.pmaLogin.fail(key)
	return true
}

// postInstallPMA downloads, verifies and installs phpMyAdmin (admin-only; the
// route is wrapped in auth.RequireAdmin). It is synchronous — the download +
// checksum verify typically finishes well within the server write timeout.
func (s *Server) postInstallPMA(w http.ResponseWriter, r *http.Request) {
	if s.pma.Installed() {
		redirect(w, r, "/databases", "msg", "phpMyAdmin is already installed.")
		return
	}
	if err := s.pma.Install(r.Context()); err != nil {
		redirect(w, r, "/databases", "err", "phpMyAdmin install failed: "+s.opErr(r, err))
		return
	}
	redirect(w, r, "/databases", "msg", "phpMyAdmin installed. Open it from the button below.")
}
