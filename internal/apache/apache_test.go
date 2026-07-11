package apache

import (
	"bytes"
	"strings"
	"testing"

	"github.com/openpropanel/openpropanel/internal/webserver"
)

func renderApache(t *testing.T, vh webserver.VHost) string {
	t.Helper()
	var b bytes.Buffer
	if err := vhostTmpl.Execute(&b, vh); err != nil {
		t.Fatalf("execute template: %v", err)
	}
	return b.String()
}

func TestApacheServingModes(t *testing.T) {
	base := webserver.VHost{Domain: "x.com", DocRoot: "/srv/x", PHPSocket: "/run/x.sock"}

	php := base
	php.Mode = "php"
	out := renderApache(t, php)
	if !strings.Contains(out, `SetHandler "proxy:unix:/run/x.sock`) {
		t.Error("php mode should wire the PHP-FPM handler")
	}
	if !strings.Contains(out, "DirectoryIndex index.php index.html") {
		t.Error("php mode should index index.php")
	}
	if strings.Contains(out, "FallbackResource") {
		t.Error("php mode should not add an SPA fallback")
	}

	spa := base
	spa.Mode = "spa"
	out = renderApache(t, spa)
	if !strings.Contains(out, "FallbackResource /index.html") {
		t.Error("spa mode should fall back to index.html")
	}
	if strings.Contains(out, "SetHandler") {
		t.Error("spa mode should not run PHP")
	}

	st := base
	st.Mode = "static"
	out = renderApache(t, st)
	if strings.Contains(out, "SetHandler") || strings.Contains(out, "FallbackResource") {
		t.Error("static mode should be plain files (no PHP, no SPA fallback)")
	}
	if !strings.Contains(out, "DirectoryIndex index.html") {
		t.Error("static mode should index index.html")
	}
}

// SymLinksIfOwnerMatch is the guard against a tenant symlinking their doc root
// into another tenant's files; "AllowOverride All" would let a tenant
// .htaccess re-enable FollowSymLinks and defeat it, so the override list must
// be an allowlist that cannot grant FollowSymLinks.
func TestApacheHtaccessCannotEnableFollowSymlinks(t *testing.T) {
	out := renderApache(t, webserver.VHost{Domain: "x.com", DocRoot: "/srv/x", Mode: "php"})
	if !strings.Contains(out, "Options -Indexes +SymLinksIfOwnerMatch") {
		t.Error("directory options must require symlink owner match")
	}
	if strings.Contains(out, "AllowOverride All") {
		t.Error("AllowOverride All lets .htaccess set Options +FollowSymLinks — must be an allowlist")
	}
	if !strings.Contains(out, "Options=Indexes,MultiViews,SymLinksIfOwnerMatch") {
		t.Error("override allowlist should permit only symlink-safe Options")
	}
}
