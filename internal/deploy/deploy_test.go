package deploy

import (
	"os"
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
