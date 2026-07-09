package domains

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/openpropanel/openpropanel/internal/config"
	"github.com/openpropanel/openpropanel/internal/store"
)

func TestValidateDocRoot(t *testing.T) {
	base := t.TempDir()
	webroot := filepath.Join(base, "www")
	s := &Service{cfg: &config.Config{WebRoot: webroot}}

	// Admin (allowShared=true): anywhere under the web root is fine.
	if _, err := s.validateDocRoot(filepath.Join(webroot, "site", "dist", "browser"), nil, "site.com", true); err != nil {
		t.Errorf("a path under the web root should be allowed for admin, got: %v", err)
	}
	if _, err := s.validateDocRoot(filepath.Join(base, "etc", "passwd"), nil, "site.com", true); err == nil {
		t.Error("a path outside the web root must be rejected")
	}
	if _, err := s.validateDocRoot("relative/path", nil, "site.com", true); err == nil {
		t.Error("a relative path must be rejected")
	}
	if _, err := s.validateDocRoot(filepath.Join(webroot, "..", "secret"), nil, "site.com", true); err == nil {
		t.Error("traversal escaping the web root must be rejected")
	}
}

// The cross-tenant takeover guard: a non-admin (allowShared=false) may only aim
// a doc root at their own site's tree or their home — never another site's
// directory, and never the shared web root itself.
func TestValidateDocRootTenantScoping(t *testing.T) {
	base := t.TempDir()
	webroot := filepath.Join(base, "www")
	s := &Service{cfg: &config.Config{WebRoot: webroot}}

	if _, err := s.validateDocRoot(filepath.Join(webroot, "mine.com", "dist"), nil, "mine.com", false); err != nil {
		t.Errorf("a non-admin pointing at their OWN site tree should be allowed, got: %v", err)
	}
	if _, err := s.validateDocRoot(filepath.Join(webroot, "victim.com", "public_html"), nil, "mine.com", false); err == nil {
		t.Error("a non-admin must NOT be able to aim their doc root at another site's directory")
	}
	if _, err := s.validateDocRoot(webroot, nil, "mine.com", false); err == nil {
		t.Error("a non-admin must NOT be able to aim their doc root at the shared web root")
	}
}

// The vhost config-injection guard: paths carrying newlines or config
// metacharacters must be rejected before they can reach the (unescaped) vhost.
func TestValidateDocRootRejectsConfigMetachars(t *testing.T) {
	base := t.TempDir()
	webroot := filepath.Join(base, "www")
	s := &Service{cfg: &config.Config{WebRoot: webroot}}

	bad := []string{
		webroot + "/x\nlocation / { root /; }", // newline -> new nginx directive
		webroot + "/x;deny all",                // semicolon -> extra nginx directive
		webroot + `/x"><Directory />`,          // quote -> break out of apache <Directory>
		webroot + "/x{}",                       // nginx block braces
	}
	for _, p := range bad {
		if _, err := s.validateDocRoot(p, nil, "x.com", true); err == nil {
			t.Errorf("doc root with config metacharacters must be rejected: %q", p)
		}
	}
}

// SafeDocRoot must confine a non-admin's file-manager jail to the site's own
// tree even when the stored doc root points elsewhere (the open-time TOCTOU
// guard). Admin callers are unrestricted.
func TestSafeDocRoot(t *testing.T) {
	base := t.TempDir()
	webroot := filepath.Join(base, "www")
	mine := filepath.Join(webroot, "mine.com", "public_html")
	victim := filepath.Join(webroot, "victim.com", "public_html")
	for _, d := range []string{mine, victim} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	s := &Service{cfg: &config.Config{WebRoot: webroot}}

	ownSite := &store.Site{Domain: "mine.com", DocRoot: mine}
	if got, err := s.SafeDocRoot(ownSite, false); err != nil || got != mine {
		t.Errorf("a site's own tree should be allowed: got %q err %v", got, err)
	}
	// Stored doc root points into another site's tree (post-creation swap).
	escaped := &store.Site{Domain: "mine.com", DocRoot: victim}
	if _, err := s.SafeDocRoot(escaped, false); err == nil {
		t.Error("a doc root resolving into another site's tree must be rejected for a non-admin")
	}
	// Admins are trusted and unrestricted.
	if got, err := s.SafeDocRoot(escaped, true); err != nil || got != victim {
		t.Errorf("admin caller should be unrestricted: got %q err %v", got, err)
	}
}

func TestRepoSubPathRejectsConfigMetachars(t *testing.T) {
	checkout := filepath.Join(t.TempDir(), "repo")
	if _, _, err := repoSubPath(checkout, "frontend/dist"); err != nil {
		t.Errorf("an ordinary subdir should be allowed, got: %v", err)
	}
	for _, sub := range []string{"x\nlocation / {}", "x;deny", `x"y`, "x{}"} {
		if _, _, err := repoSubPath(checkout, sub); err == nil {
			t.Errorf("repo subdir with config metacharacters must be rejected: %q", sub)
		}
	}
}

// The critical data-loss guard: an operator-supplied (external) doc root must
// never be seeded with our landing page nor have its existing files touched.
func TestProvisionDocRootExternalIsUntouched(t *testing.T) {
	s := &Service{cfg: &config.Config{Dev: true}}
	dir := t.TempDir()
	marker := filepath.Join(dir, "app.js")
	if err := os.WriteFile(marker, []byte("mine"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.provisionDocRoot(dir, "demo.test", "", true); err != nil {
		t.Fatalf("provision external: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "index.html")); err == nil {
		t.Error("external doc root must NOT be seeded with index.html")
	}
	if b, _ := os.ReadFile(marker); string(b) != "mine" {
		t.Error("existing file in an external doc root was modified")
	}
	if fi, err := os.Stat(filepath.Join(dir, ".well-known", "acme-challenge")); err != nil || !fi.IsDir() {
		t.Error("acme-challenge dir should still be created inside an external doc root")
	}
}

func TestParentDomainIn(t *testing.T) {
	uni := map[string]bool{
		"thenorthculture.com":     true,
		"www.thenorthculture.com": true,
		"api.thenorthculture.com": true,
		"reptoapp.com":            true,
	}
	want := map[string]string{
		"api.thenorthculture.com": "thenorthculture.com",
		"www.thenorthculture.com": "thenorthculture.com",
		"thenorthculture.com":     "", // apex — no parent in the set
		"reptoapp.com":            "",
		"unknown.example.org":     "", // parent not tracked
	}
	for d, exp := range want {
		if got := parentDomainIn(d, uni); got != exp {
			t.Errorf("parentDomainIn(%q) = %q, want %q", d, got, exp)
		}
	}
	// The most specific (longest) parent wins for nested names.
	nested := map[string]bool{"example.com": true, "api.example.com": true}
	if got := parentDomainIn("v1.api.example.com", nested); got != "api.example.com" {
		t.Errorf("nested parent should be the longest match, got %q", got)
	}
}

func TestProvisionDocRootDefaultIsSeeded(t *testing.T) {
	s := &Service{cfg: &config.Config{Dev: true}}
	dir := filepath.Join(t.TempDir(), "public_html")
	if err := s.provisionDocRoot(dir, "demo.test", "", false); err != nil {
		t.Fatalf("provision default: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "index.html")); err != nil {
		t.Error("a default doc root should be seeded with a landing page")
	}
}
