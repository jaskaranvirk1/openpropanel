package deploy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openpropanel/openpropanel/internal/config"
	"golang.org/x/crypto/ssh"
)

func TestParseGitHubURL(t *testing.T) {
	ok := []struct{ in, owner, name string }{
		{"git@github.com:thenorthculture/site.git", "thenorthculture", "site"},
		{"https://github.com/thenorthculture/site", "thenorthculture", "site"},
		{"https://github.com/thenorthculture/site.git", "thenorthculture", "site"},
		{"ssh://git@github.com/acme/repo.git", "acme", "repo"},
		{"acme/repo", "acme", "repo"},
	}
	for _, c := range ok {
		o, n, err := ParseGitHubURL(c.in)
		if err != nil || o != c.owner || n != c.name {
			t.Errorf("ParseGitHubURL(%q) = %q/%q,%v want %q/%q", c.in, o, n, err, c.owner, c.name)
		}
	}
	bad := []string{
		"https://gitlab.com/a/b", // wrong host still parses owner/name only via prefix; but this yields gitlab.com/a/b -> 3 parts -> error
		"https://github.com/only-owner",
		"git@github.com:owner/repo/extra",
		"owner/../etc",
		"owner/re;po",
		"",
	}
	for _, c := range bad {
		if _, _, err := ParseGitHubURL(c); err == nil {
			t.Errorf("ParseGitHubURL(%q) should have failed", c)
		}
	}
}

func TestGenerateKeyProducesValidOpenSSHKeys(t *testing.T) {
	m := New(&config.Config{DataDir: t.TempDir()})
	pub, fp, err := m.GenerateKey(1)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if !strings.HasPrefix(pub, "ssh-ed25519 ") {
		t.Errorf("public line should be an ed25519 authorized key, got %q", pub)
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pub)); err != nil {
		t.Errorf("public line does not parse as an authorized key: %v", err)
	}
	if !strings.HasPrefix(fp, "SHA256:") {
		t.Errorf("fingerprint should be SHA256, got %q", fp)
	}
	// The private key must exist, be 0600, and parse.
	b, err := os.ReadFile(m.keyPath(1))
	if err != nil {
		t.Fatalf("read private key: %v", err)
	}
	if _, err := ssh.ParsePrivateKey(b); err != nil {
		t.Errorf("private key does not parse: %v", err)
	}
}

// The tenant runs git/ssh, so BOTH the deploy key and the pinned known_hosts
// must be staged somewhere the tenant can read — never only under the
// root-only data dir (ssh treats an unreadable known_hosts as empty and strict
// checking then refuses every connection).
func TestTenantKeyStagesKeyAndKnownHosts(t *testing.T) {
	m := New(&config.Config{DataDir: t.TempDir()})
	if _, _, err := m.GenerateKey(7); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	kp, kh, cleanup, err := m.tenantKey(7, 1000, 1000)
	if err != nil {
		t.Fatalf("tenantKey: %v", err)
	}
	defer cleanup()
	if filepath.Dir(kp) != filepath.Dir(kh) {
		t.Errorf("key %q and known_hosts %q should share one temp dir", kp, kh)
	}
	if strings.HasPrefix(kp, m.cfg.DataDir) {
		t.Errorf("staged material must live outside the root-only data dir, got %q", kp)
	}
	b, err := os.ReadFile(kh)
	if err != nil {
		t.Fatalf("read staged known_hosts: %v", err)
	}
	if string(b) != pinnedKnownHosts {
		t.Error("staged known_hosts must contain the pinned github.com host keys")
	}
	cleanup()
	if _, err := os.Stat(filepath.Dir(kp)); !os.IsNotExist(err) {
		t.Error("cleanup must remove the temp dir")
	}
}

func TestValidBranch(t *testing.T) {
	for _, b := range []string{"main", "release/1.2", "feature-x", "v1.0.0"} {
		if !ValidBranch(b) {
			t.Errorf("%q should be valid", b)
		}
	}
	for _, b := range []string{"", "-bad", "a b", "x;y", "$(x)"} {
		if ValidBranch(b) {
			t.Errorf("%q should be invalid", b)
		}
	}
}
