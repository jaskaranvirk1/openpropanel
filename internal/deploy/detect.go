package deploy

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/openpropanel/openpropanel/internal/store"
)

// DetectApp inspects a fresh checkout and guesses how to serve it. It returns
// the doc-root subfolder relative to the checkout, the serving mode
// (php|static|spa), a human note for states needing operator action, and
// whether the result is safe to auto-map. Only fixed, known-safe subdir names
// are ever returned, so callers can hand them to the vhost layer directly.
//
// mapOK is false when we could NOT positively identify a servable entrypoint:
// auto-mapping such a checkout would serve raw source (README, configs,
// committed secrets) as the site — the operator must pick a folder instead.
func DetectApp(dir string) (subdir, mode, note string, mapOK bool) {
	has := func(parts ...string) bool {
		_, err := os.Stat(filepath.Join(append([]string{dir}, parts...)...))
		return err == nil
	}
	// PHP apps that need `composer install` will 500 until dependencies exist;
	// say so up front rather than letting "live" be a lie.
	composerNote := ""
	if has("composer.json") && !has("vendor") {
		composerNote = "composer.json found but no vendor/ — run composer install in the checkout (the panel does not run builds); the site will error until then."
	}
	switch {
	case has("public", "index.php"): // Laravel / Symfony layout
		return "public", store.WebModePHP, composerNote, true
	case has("index.php"):
		return "", store.WebModePHP, composerNote, true
	case has("dist", "index.html"): // Vite / Vue / Angular build output
		return "dist", store.WebModeSPA, "", true
	case has("build", "index.html"): // CRA build output
		return "build", store.WebModeSPA, "", true
	case has("out", "index.html"): // Next.js static export
		return "out", store.WebModeStatic, "", true
	case has("public", "index.html"):
		return "public", store.WebModeStatic, "", true
	case has("index.html"):
		return "", store.WebModeStatic, "", true
	case has("package.json"):
		return "", "", "This looks like a Node project without built output — run your build locally, commit/push the output folder, then pick it under “Folder in the repo”.", false
	}
	return "", "", strings.TrimSpace("Couldn't detect the app type — pick the folder to serve under “Folder in the repo”. " + composerNote), false
}

// UserError carries a user-safe, actionable message for a failed deploy step.
// Msg contains no command output, so the web layer may show it to any role;
// the underlying raw error is preserved for server-side logs via Unwrap.
type UserError struct {
	Msg string
	Raw error
}

func (e *UserError) Error() string { return e.Msg }
func (e *UserError) Unwrap() error { return e.Raw }

// Classify maps well-known git/ssh failure texts to actionable guidance.
// Unknown errors are returned unchanged (and must stay admin-only in the UI).
func Classify(err error) error {
	if err == nil {
		return nil
	}
	var ue *UserError
	if errors.As(err, &ue) {
		return err
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "Permission denied (publickey"):
		return &UserError{Msg: "GitHub rejected the connection — the deploy key has not been added yet. On GitHub open the repository → Settings → Deploy keys, add the key shown on this card, then deploy again.", Raw: err}
	case strings.Contains(s, "Repository not found"):
		return &UserError{Msg: "GitHub reports the repository was not found. For a private repository this usually means the deploy key was added to a DIFFERENT repository (or not at all) — check the key is on this exact repo, and the owner/name are right.", Raw: err}
	case strings.Contains(s, "Could not resolve hostname"), strings.Contains(s, "Connection timed out"), strings.Contains(s, "Connection refused"):
		return &UserError{Msg: "Could not reach github.com from this server — check the server's outbound network and DNS.", Raw: err}
	}
	return err
}

// BranchNotFound builds the friendly error for a branch that does not exist on
// the remote, listing what does.
func BranchNotFound(branch string, have []string) *UserError {
	msg := fmt.Sprintf("branch %q was not found in the repository", branch)
	if len(have) > 0 {
		const max = 8
		list := have
		if len(list) > max {
			list = list[:max]
		}
		msg += " — it has: " + strings.Join(list, ", ")
		if len(have) > max {
			msg += ", …"
		}
	}
	return &UserError{Msg: msg + ". Change the branch on the repository card and it will redeploy."}
}

// NewWebhookSecret returns a fresh random webhook HMAC key (32 hex chars).
func NewWebhookSecret() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
