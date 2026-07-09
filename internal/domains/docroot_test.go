package domains

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/openpropanel/openpropanel/internal/config"
)

func TestValidateDocRoot(t *testing.T) {
	base := t.TempDir()
	webroot := filepath.Join(base, "www")
	s := &Service{cfg: &config.Config{WebRoot: webroot}}

	if _, err := s.validateDocRoot(filepath.Join(webroot, "site", "dist", "browser"), nil); err != nil {
		t.Errorf("a path under the web root should be allowed, got: %v", err)
	}
	if _, err := s.validateDocRoot(filepath.Join(base, "etc", "passwd"), nil); err == nil {
		t.Error("a path outside the web root must be rejected")
	}
	if _, err := s.validateDocRoot("relative/path", nil); err == nil {
		t.Error("a relative path must be rejected")
	}
	if _, err := s.validateDocRoot(filepath.Join(webroot, "..", "secret"), nil); err == nil {
		t.Error("traversal escaping the web root must be rejected")
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
