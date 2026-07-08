// Package auth handles password hashing, cookie-backed sessions, and the HTTP
// middleware that protects the panel. Sessions are opaque random tokens stored
// server-side in SQLite, so there is no signed-cookie secret to leak.
package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/openpropanel/openpropanel/internal/store"
	"golang.org/x/crypto/bcrypt"
)

// CookieName is the session cookie name.
const CookieName = "openpropanel_session"

// SessionTTL is how long a login stays valid.
const SessionTTL = 12 * time.Hour

type ctxKey int

const userKey ctxKey = 0

// Manager wires auth operations to the store.
type Manager struct {
	store  *store.Store
	secure bool // set Secure flag on cookies (true in production/HTTPS)
}

// New builds a Manager. secure should be true when the panel is served over
// HTTPS so that session cookies are not sent over plaintext.
func New(s *store.Store, secure bool) *Manager {
	return &Manager{store: s, secure: secure}
}

// HashPassword returns a bcrypt hash suitable for storage.
func HashPassword(pw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(b), err
}

// Verify reports whether pw matches the stored bcrypt hash.
func Verify(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Login verifies credentials and, on success, creates a session and writes the
// cookie. It returns the authenticated user.
func (m *Manager) Login(w http.ResponseWriter, username, password string) (*store.User, error) {
	u, err := m.store.UserByUsername(username)
	if err != nil {
		// Run a dummy compare to blunt username-enumeration timing attacks.
		_ = Verify("$2a$10$invalidinvalidinvalidinvalidinvalidinvalidinvalidinva", password)
		return nil, errors.New("invalid username or password")
	}
	if !Verify(u.PasswordHash, password) {
		return nil, errors.New("invalid username or password")
	}
	token, err := newToken()
	if err != nil {
		return nil, err
	}
	expires := time.Now().Add(SessionTTL)
	if err := m.store.CreateSession(&store.Session{Token: token, UserID: u.ID, ExpiresAt: expires}); err != nil {
		return nil, err
	}
	m.setCookie(w, token, expires)
	return u, nil
}

// Logout clears the session on both the server and the client.
func (m *Manager) Logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(CookieName); err == nil {
		_ = m.store.DeleteSession(c.Value)
	}
	m.setCookie(w, "", time.Unix(0, 0))
}

func (m *Manager) setCookie(w http.ResponseWriter, value string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    value,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: http.SameSiteStrictMode,
	})
}

// Middleware authenticates the request and attaches the user to its context.
// Unauthenticated requests are redirected to /login.
func (m *Manager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(CookieName)
		if err != nil || c.Value == "" {
			redirectToLogin(w, r)
			return
		}
		u, err := m.store.SessionUser(c.Value)
		if err != nil {
			m.setCookie(w, "", time.Unix(0, 0))
			redirectToLogin(w, r)
			return
		}
		ctx := context.WithValue(r.Context(), userKey, u)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireAdmin wraps a handler so only admin accounts may reach it.
func RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := UserFrom(r.Context())
		if u == nil || u.Role != store.RoleAdmin {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// UserFrom retrieves the authenticated user from a request context, or nil.
func UserFrom(ctx context.Context) *store.User {
	u, _ := ctx.Value(userKey).(*store.User)
	return u
}

func redirectToLogin(w http.ResponseWriter, r *http.Request) {
	// For HTMX requests, instruct the client to do a full-page redirect rather
	// than swapping the login page into a fragment.
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/login")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// SameOrigin is a CSRF guard for state-changing requests. Because session
// cookies are SameSite=Strict this is defence-in-depth: we additionally reject
// a POST/DELETE/PUT only when the browser positively reports a DIFFERENT
// origin. An absent or opaque ("null") Origin is allowed: browsers send
// Origin: null for form submissions from a page loaded over a self-signed /
// untrusted certificate (the common case when reaching the panel by IP before
// a real cert is configured), and rejecting it would make login impossible.
// SameSite=Strict still prevents an actual cross-site request from ever
// carrying the session cookie, so this is safe.
func SameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		if origin := originHost(r); origin != "" && !strings.EqualFold(origin, "null") && !strings.EqualFold(origin, r.Host) {
			log.Printf("cross-origin %s %s rejected: origin=%q host=%q", r.Method, r.URL.Path, origin, r.Host)
			http.Error(w, "cross-origin request rejected", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func originHost(r *http.Request) string {
	if o := r.Header.Get("Origin"); o != "" {
		return stripScheme(o)
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		return stripScheme(ref)
	}
	return ""
}

func stripScheme(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	if i := strings.IndexAny(u, "/?#"); i >= 0 {
		u = u[:i]
	}
	return u
}
