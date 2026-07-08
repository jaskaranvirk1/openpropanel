package web

import (
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"
)

// loginLimiter throttles the login endpoint two ways: a per-source-IP
// exponential-backoff lockout after repeated failures (online brute-force), and
// a global bounded semaphore capping concurrent bcrypt comparisons so an
// unauthenticated flood of logins can't monopolise all CPU (bcrypt DoS).
type loginLimiter struct {
	mu       sync.Mutex
	attempts map[string]*ipState
	sem      chan struct{}
}

type ipState struct {
	fails        int
	blockedUntil time.Time
	last         time.Time
}

func newLoginLimiter() *loginLimiter {
	n := runtime.GOMAXPROCS(0)
	if n < 1 {
		n = 1
	}
	return &loginLimiter{
		attempts: make(map[string]*ipState),
		sem:      make(chan struct{}, n),
	}
}

const (
	loginFailThreshold = 5
	loginIdleReset     = 15 * time.Minute
)

// allow reports whether this IP may attempt a login now; if locked out it
// returns the remaining wait.
func (l *loginLimiter) allow(ip string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	st := l.attempts[ip]
	if st == nil {
		return true, 0
	}
	if now.Sub(st.last) > loginIdleReset {
		delete(l.attempts, ip) // stale — forget it
		return true, 0
	}
	if now.Before(st.blockedUntil) {
		return false, time.Until(st.blockedUntil).Round(time.Second)
	}
	return true, 0
}

// fail records a failed attempt and applies exponential backoff past the
// threshold (1s, 2s, 4s ... capped at ~1 minute).
func (l *loginLimiter) fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	st := l.attempts[ip]
	if st == nil {
		st = &ipState{}
		l.attempts[ip] = st
	}
	st.fails++
	st.last = time.Now()
	if st.fails >= loginFailThreshold {
		shift := st.fails - loginFailThreshold
		if shift > 6 {
			shift = 6
		}
		st.blockedUntil = time.Now().Add(time.Duration(1<<uint(shift)) * time.Second)
	}
	// Bound memory against IP-rotating attackers.
	if len(l.attempts) > 50000 {
		cutoff := time.Now().Add(-loginIdleReset)
		for k, v := range l.attempts {
			if v.last.Before(cutoff) {
				delete(l.attempts, k)
			}
		}
	}
}

// success clears an IP's failure state after a valid login.
func (l *loginLimiter) success(ip string) {
	l.mu.Lock()
	delete(l.attempts, ip)
	l.mu.Unlock()
}

// acquire bounds concurrent password verifications; release with the returned func.
func (l *loginLimiter) acquire() func() {
	l.sem <- struct{}{}
	return func() { <-l.sem }
}

func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// securityHeaders sets baseline hardening headers on every response.
//
// The strict Content-Security-Policy and X-Frame-Options are scoped to the
// panel's own pages. phpMyAdmin (served under /phpmyadmin/) ships its own
// hardened CSP/X-Frame-Options tuned to its assets; imposing the panel's
// policy there would break it, and emitting a second CSP header would have the
// browser intersect the two and break it anyway. For that subtree we still set
// the safe, non-conflicting headers (nosniff, referrer policy) and let
// phpMyAdmin govern framing/CSP.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		if !strings.HasPrefix(r.URL.Path, "/phpmyadmin/") {
			h.Set("X-Frame-Options", "DENY")
			// Self-contained UI: block loading any external resource (limits XSS
			// blast radius) and framing (clickjacking). Inline style/script are
			// needed for the meter widths and confirm() handlers.
			h.Set("Content-Security-Policy",
				"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "+
					"script-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		}
		next.ServeHTTP(w, r)
	})
}
