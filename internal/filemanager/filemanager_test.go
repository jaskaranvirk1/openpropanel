package filemanager

import (
	"os"
	"path/filepath"
	"testing"
)

// setup creates a jail root plus a sibling "outside" directory containing a
// secret file that must never be reachable through the jail.
func setup(t *testing.T) (root, outsideSecret string) {
	t.Helper()
	base := t.TempDir()
	root = filepath.Join(base, "jail")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	outsideSecret = filepath.Join(base, "secret.txt")
	if err := os.WriteFile(outsideSecret, []byte("TOPSECRET"), 0o644); err != nil {
		t.Fatal(err)
	}
	return root, outsideSecret
}

func TestTraversalIsContained(t *testing.T) {
	root, _ := setup(t)
	fs, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()

	// All of these must resolve back inside the jail (or error), never read the
	// sibling secret.
	for _, p := range []string{"../secret.txt", "../../secret.txt", "..\\..\\secret.txt", "/etc/passwd"} {
		if _, err := fs.ReadText(p); err == nil {
			t.Fatalf("expected traversal %q to be contained/rejected, but read succeeded", p)
		}
	}
}

func TestSymlinkEscapeRefused(t *testing.T) {
	root, outsideSecret := setup(t)

	// A symlink inside the jail pointing OUTSIDE it — the exact attack a hosting
	// user can set up via SSH/SFTP in their own docroot.
	link := filepath.Join(root, "escape")
	if err := os.Symlink(outsideSecret, link); err != nil {
		t.Skipf("cannot create symlinks on this host (%v) — os.Root enforces refusal on all platforms", err)
	}

	fs, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()

	// Read through the symlink must be refused (not return the secret).
	if content, err := fs.ReadText("escape"); err == nil {
		t.Fatalf("read through escaping symlink succeeded and returned %q — JAIL BREACH", content)
	}
	// Write through the symlink must be refused (not clobber the outside file).
	if err := fs.WriteText("escape", "PWNED"); err == nil {
		t.Fatal("write through escaping symlink succeeded — JAIL BREACH")
	}
	if b, _ := os.ReadFile(outsideSecret); string(b) != "TOPSECRET" {
		t.Fatalf("outside file was modified through the jail: %q", b)
	}

	// A symlinked directory used as an intermediate component must also fail.
	dirLink := filepath.Join(root, "outdir")
	if err := os.Symlink(filepath.Dir(outsideSecret), dirLink); err == nil {
		if err := fs.WriteText("outdir/planted", "x"); err == nil {
			t.Fatal("write via symlinked intermediate directory succeeded — JAIL BREACH")
		}
	}
}

func TestNormalOpsStayInJail(t *testing.T) {
	root, _ := setup(t)
	fs, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()

	if err := fs.Mkdir("sub"); err != nil {
		t.Fatal(err)
	}
	if err := fs.WriteText("sub/a.txt", "hello"); err != nil {
		t.Fatal(err)
	}
	got, err := fs.ReadText("sub/a.txt")
	if err != nil || got != "hello" {
		t.Fatalf("read back: %q err=%v", got, err)
	}
	if _, err := os.Stat(filepath.Join(root, "sub", "a.txt")); err != nil {
		t.Fatalf("file not written inside jail: %v", err)
	}
}
