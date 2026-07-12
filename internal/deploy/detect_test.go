package deploy

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/openpropanel/openpropanel/internal/store"
)

// checkout builds a temp dir containing the given relative files.
func checkout(t *testing.T, files ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, f := range files {
		p := filepath.Join(dir, filepath.FromSlash(f))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestDetectApp(t *testing.T) {
	cases := []struct {
		name   string
		files  []string
		subdir string
		mode   string
		mapOK  bool
	}{
		{"laravel", []string{"public/index.php", "artisan", "composer.json", "vendor/autoload.php"}, "public", store.WebModePHP, true},
		{"plain php", []string{"index.php"}, "", store.WebModePHP, true},
		{"vite build", []string{"dist/index.html", "package.json"}, "dist", store.WebModeSPA, true},
		{"cra build", []string{"build/index.html", "package.json"}, "build", store.WebModeSPA, true},
		{"next export", []string{"out/index.html", "package.json"}, "out", store.WebModeStatic, true},
		{"public html", []string{"public/index.html"}, "public", store.WebModeStatic, true},
		{"root html", []string{"index.html"}, "", store.WebModeStatic, true},
		{"unbuilt node", []string{"package.json", "src/main.ts"}, "", "", false},
		{"unknown", []string{"README.md"}, "", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			subdir, mode, note, mapOK := DetectApp(checkout(t, c.files...))
			if subdir != c.subdir || mode != c.mode || mapOK != c.mapOK {
				t.Errorf("DetectApp = (%q, %q, ok=%v), want (%q, %q, ok=%v)", subdir, mode, mapOK, c.subdir, c.mode, c.mapOK)
			}
			if !mapOK && note == "" {
				t.Error("a non-mappable result must carry an explanatory note")
			}
		})
	}
}

// Laravel without vendor/ serves but 500s — the note must warn about it.
func TestDetectAppComposerWithoutVendor(t *testing.T) {
	_, _, note, mapOK := DetectApp(checkout(t, "public/index.php", "composer.json"))
	if !mapOK {
		t.Fatal("laravel layout should still auto-map")
	}
	if !strings.Contains(note, "composer install") {
		t.Errorf("note should mention composer install, got %q", note)
	}
}

func TestParseBranches(t *testing.T) {
	out := "29932f3915935d773dc8d52c292cadd81c81071d\trefs/heads/main\n" +
		"b1946ac92492d2347c6235b4d2611184\trefs/heads/develop\n" +
		"deadbeef\trefs/heads/release/1.2\n" +
		"deadbeef\trefs/pull/1/head\n\n"
	got := parseBranches(out)
	want := []string{"main", "develop", "release/1.2"}
	if len(got) != len(want) {
		t.Fatalf("parseBranches = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("parseBranches = %v, want %v", got, want)
		}
	}
}

func TestNewWebhookSecret(t *testing.T) {
	a, err := NewWebhookSecret()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewWebhookSecret()
	if a == b {
		t.Error("secrets must be random")
	}
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(a) {
		t.Errorf("secret should be 32 hex chars, got %q", a)
	}
}

func TestClassify(t *testing.T) {
	err := Classify(errors.New("git@github.com: Permission denied (publickey)."))
	var ue *UserError
	if !errors.As(err, &ue) || !strings.Contains(ue.Msg, "Deploy keys") {
		t.Errorf("publickey failure should classify to deploy-key guidance, got %v", err)
	}
	// git missing entirely (minimal AlmaLinux) must self-diagnose in the UI.
	err = Classify(errors.New(`exec: "git": executable file not found in $PATH`))
	if !errors.As(err, &ue) || !strings.Contains(ue.Msg, "dnf install -y git") {
		t.Errorf("missing git should classify to an install hint, got %v", err)
	}
	if raw := Classify(errors.New("some unknown failure")); errors.As(raw, &ue) {
		t.Error("unknown errors must pass through unclassified")
	}
	// A UserError's raw cause must stay reachable for server-side logging.
	if ue == nil || Classify(err) != err {
		t.Error("classifying twice must be idempotent")
	}
}
