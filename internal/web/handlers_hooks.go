// GitHub push-to-deploy webhook. This is the panel's ONLY unauthenticated
// state-changing endpoint, so it is deliberately paranoid: per-repo HMAC
// secrets, constant-time signature checks, a uniform 404 for every rejection
// (no repo-id enumeration oracle), per-IP rate limiting on failures, and a
// bounded replay cache of delivery IDs. A valid push triggers the same
// coalescing background deploy the UI buttons use.

package web

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

// maxHookBody matches GitHub's documented 25 MB webhook payload cap; a smaller
// limit would silently drop legitimate busy-push deliveries (the whole body
// must be read to verify the HMAC).
const maxHookBody = 25 << 20

// verifyGitHubSignature checks an X-Hub-Signature-256 header against the
// HMAC-SHA256 of body under secret. The header must be exactly
// "sha256=" + 64 lowercase hex chars — malformed or truncated headers are
// rejected before any decoding, and the comparison is constant-time.
func verifyGitHubSignature(body []byte, secret, header string) bool {
	if secret == "" {
		return false
	}
	rest, ok := strings.CutPrefix(header, "sha256=")
	if !ok || len(rest) != sha256.Size*2 || strings.ToLower(rest) != rest {
		return false
	}
	got, err := hex.DecodeString(rest)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hmac.Equal(got, mac.Sum(nil))
}

// hookPayload extracts the event JSON from a webhook body. GitHub's webhook
// form DEFAULTS to application/x-www-form-urlencoded, which wraps the JSON in
// "payload=<urlencoded>"; tolerating it turns a below-the-fold GitHub setting
// into a non-issue instead of a silent never-deploys. The HMAC is always
// verified over the RAW body, never the decoded form.
func hookPayload(body []byte) []byte {
	if rest, ok := strings.CutPrefix(string(body), "payload="); ok {
		if decoded, err := url.QueryUnescape(rest); err == nil {
			return []byte(decoded)
		}
	}
	return body
}

// deliveryCache is a bounded FIFO set of recently-seen webhook delivery IDs —
// a captured signed delivery cannot be replayed to force deploy loops.
type deliveryCache struct {
	mu    sync.Mutex
	seen  map[string]bool
	order []string
	max   int
}

func newDeliveryCache(max int) *deliveryCache {
	return &deliveryCache{seen: make(map[string]bool, max), max: max}
}

// remember records id, reporting whether it was already present.
func (c *deliveryCache) remember(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen[id] {
		return true
	}
	c.seen[id] = true
	c.order = append(c.order, id)
	if len(c.order) > c.max {
		delete(c.seen, c.order[0])
		c.order = c.order[1:]
	}
	return false
}

// postGitHubHook handles POST /hooks/github/{id}. It sits OUTSIDE the auth
// middleware (GitHub cannot log in); auth.SameOrigin still passes it because
// server-to-server POSTs carry no Origin/Referer header. The HMAC secret IS
// the authentication.
func (s *Server) postGitHubHook(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if ok, _ := s.hookLimit.allow(ip); !ok {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	// Uniform rejection: unknown id, missing secret and bad signature are
	// indistinguishable from the outside.
	reject := func() {
		s.hookLimit.fail(ip)
		http.NotFound(w, r)
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		reject()
		return
	}
	// Refuse oversized deliveries BEFORE buffering, and penalize them like any
	// other rejection — otherwise >25MB posts would bypass the rate limiter
	// entirely while still costing a full read each.
	if r.ContentLength > maxHookBody {
		s.hookLimit.fail(ip)
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxHookBody))
	if err != nil {
		s.hookLimit.fail(ip)
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	repo, err := s.store.RepoByID(id)
	if err != nil || !verifyGitHubSignature(body, repo.WebhookSecret, r.Header.Get("X-Hub-Signature-256")) {
		reject()
		return
	}

	switch r.Header.Get("X-GitHub-Event") {
	case "ping":
		w.Write([]byte("pong"))
	case "push":
		if delivery := r.Header.Get("X-GitHub-Delivery"); delivery != "" && s.hookSeen.remember(delivery) {
			w.WriteHeader(http.StatusAccepted)
			w.Write([]byte("duplicate delivery ignored"))
			return
		}
		var ev struct {
			Ref string `json:"ref"`
		}
		if json.Unmarshal(hookPayload(body), &ev) != nil || ev.Ref == "" {
			// Self-diagnosing red delivery in GitHub's Recent Deliveries view.
			http.Error(w, "unrecognised payload — set the webhook Content type to application/json", http.StatusBadRequest)
			return
		}
		if ev.Ref != "refs/heads/"+repo.Branch {
			w.Write([]byte("ignored: push to " + ev.Ref + ", deploying only refs/heads/" + repo.Branch))
			return
		}
		if err := s.domains.StartDeploy(repo.ProjectSiteID); err != nil {
			http.Error(w, "project is not deployable", http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte("deploying"))
	default:
		w.Write([]byte("ignored event"))
	}
}
