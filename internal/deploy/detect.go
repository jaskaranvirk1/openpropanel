package deploy

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/openpropanel/openpropanel/internal/store"
)

var reAngularOut = regexp.MustCompile(`"outputPath"\s*:\s*"([^"]+)"`)

// DetectBuild inspects a subfolder for a framework that must be BUILT before it
// can be served, and suggests {mode, publishDir (output relative to the folder),
// buildCommand}. ok=false means "no known buildable framework here" (note may
// still carry guidance, e.g. for Next.js). It only READS manifest files; the
// returned publishDir is a form pre-fill and is re-validated by the caller before
// it ever reaches a doc root.
func DetectBuild(dir string) (mode, publishDir, buildCommand, note string, ok bool) {
	has := func(parts ...string) bool {
		_, e := os.Stat(filepath.Join(append([]string{dir}, parts...)...))
		return e == nil
	}
	read := func(name string) string {
		f, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			return ""
		}
		defer f.Close()
		// Read at most 1 MB: a manifest is tiny, and a tenant could commit a huge
		// (even sparse) file to OOM the root panel if we read it whole.
		b, _ := io.ReadAll(io.LimitReader(f, 1<<20))
		return string(b)
	}
	pkg := read("package.json")
	dep := func(name string) bool {
		return pkg != "" && regexp.MustCompile(`"`+regexp.QuoteMeta(name)+`"\s*:`).MatchString(pkg)
	}
	switch {
	case has("angular.json") || dep("@angular/core"):
		pub := "dist"
		if a := read("angular.json"); a != "" {
			if m := reAngularOut.FindStringSubmatch(a); m != nil {
				pub = m[1]
			}
		}
		return store.WebModeSPA, pub, "npm ci && npm run build", "Angular build. Angular 17+ nests output under /browser — verify the publish dir after the first build.", true
	case dep("react-scripts"):
		return store.WebModeSPA, "build", "npm ci && npm run build", "", true
	case dep("next"):
		return "", "", "", "Next.js needs a running Node server — use “Run an app” (reverse proxy) with a build + start command, unless next.config sets output:'export' (then serve the “out” folder).", false
	case dep("vite") || dep("@vue/cli-service"):
		return store.WebModeSPA, "dist", "npm ci && npm run build", "", true
	case pkg != "" && regexp.MustCompile(`"scripts"[\s\S]*?"build"\s*:`).MatchString(pkg):
		return store.WebModeSPA, "dist", "npm ci && npm run build", "Node build detected — check the output folder (often dist or build).", true
	case has("composer.json") && has("artisan"):
		return store.WebModePHP, "public", "composer install --no-dev --optimize-autoloader", "", true
	case has("composer.json"):
		pub := ""
		if has("public", "index.php") {
			pub = "public"
		}
		return store.WebModePHP, pub, "composer install", "", true
	}
	return "", "", "", "", false
}

// DetectFolder suggests how to serve a subfolder: mode + publishDir + buildCommand
// (empty = no build). It prefers a buildable framework (DetectBuild); failing
// that, it looks for committed output / an entrypoint. mode == "" means it could
// not tell — the operator must choose. Used for the Browse pre-fill and one-click
// activate.
func DetectFolder(dir string) (mode, publishDir, buildCommand, note string) {
	if m, pub, bc, n, ok := DetectBuild(dir); ok {
		return m, pub, bc, n
	} else {
		note = n // may be Next.js guidance
	}
	has := func(parts ...string) bool {
		_, e := os.Stat(filepath.Join(append([]string{dir}, parts...)...))
		return e == nil
	}
	switch {
	case has("public", "index.php"):
		return store.WebModePHP, "public", "", ""
	case has("index.php"):
		return store.WebModePHP, "", "", ""
	case has("dist", "index.html"):
		return store.WebModeSPA, "dist", "", ""
	case has("build", "index.html"):
		return store.WebModeSPA, "build", "", ""
	case has("out", "index.html"):
		return store.WebModeStatic, "out", "", ""
	case has("public", "index.html"):
		return store.WebModeStatic, "public", "", ""
	case has("index.html"):
		return store.WebModeStatic, "", "", ""
	}
	if note == "" {
		note = "Couldn't detect automatically — pick the serving mode, and if it needs building, set a build command + output folder."
	}
	return "", "", "", note
}

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
	case strings.Contains(s, "npm: command not found"), strings.Contains(s, "ng: not found"), strings.Contains(s, `"npm": executable file not found`), strings.Contains(s, "node: command not found"):
		return &UserError{Msg: "Node.js / npm is not installed on this server — run: dnf install -y nodejs — then deploy again.", Raw: err}
	case strings.Contains(s, "composer: command not found"), strings.Contains(s, `"composer": executable file not found`):
		return &UserError{Msg: "Composer is not installed on this server — install it (see getcomposer.org), then deploy again.", Raw: err}
	case strings.Contains(s, "executable file not found"):
		return &UserError{Msg: "git is not installed on this server — run: dnf install -y git — then deploy again.", Raw: err}
	case strings.Contains(s, "Permission denied (publickey"):
		return &UserError{Msg: "GitHub rejected the connection — the deploy key has not been added yet. On GitHub open the repository → Settings → Deploy keys, add the key shown on this card, then deploy again.", Raw: err}
	case strings.Contains(s, "Repository not found"):
		return &UserError{Msg: "GitHub reports the repository was not found. For a private repository this usually means the deploy key was added to a DIFFERENT repository (or not at all) — check the key is on this exact repo, and the owner/name are right.", Raw: err}
	case strings.Contains(s, "Could not resolve hostname"), strings.Contains(s, "Connection timed out"), strings.Contains(s, "Connection refused"):
		return &UserError{Msg: "Could not reach github.com from this server — check the server's outbound network and DNS.", Raw: err}
	case strings.Contains(s, "Host key verification failed"), strings.Contains(s, "host key is known"):
		return &UserError{Msg: "Could not verify github.com's identity against the pinned host keys — if GitHub recently rotated its SSH keys, update Open ProPanel to a release with the new keys.", Raw: err}
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
