package nginx

import (
	"bytes"
	"strings"
	"testing"

	"github.com/openpropanel/openpropanel/internal/webserver"
)

func renderNginx(t *testing.T, vh webserver.VHost) string {
	t.Helper()
	var b bytes.Buffer
	if err := serverTmpl.Execute(&b, vh); err != nil {
		t.Fatalf("execute template: %v", err)
	}
	return b.String()
}

func TestNginxServingModes(t *testing.T) {
	base := webserver.VHost{Domain: "x.com", DocRoot: "/srv/x", PHPSocket: "/run/x.sock", SSL: true, CertFile: "/c", KeyFile: "/k"}

	php := base
	php.Mode = "php"
	out := renderNginx(t, php)
	if !strings.Contains(out, "fastcgi_pass unix:/run/x.sock") {
		t.Error("php mode should fastcgi_pass to the socket")
	}
	if !strings.Contains(out, "try_files $uri $uri/ /index.php?$query_string") {
		t.Error("php mode should route to index.php")
	}

	spa := base
	spa.Mode = "spa"
	out = renderNginx(t, spa)
	if !strings.Contains(out, "try_files $uri $uri/ /index.html") {
		t.Error("spa mode should fall back to index.html")
	}
	if strings.Contains(out, "fastcgi_pass") {
		t.Error("spa mode should not run PHP")
	}

	st := base
	st.Mode = "static"
	out = renderNginx(t, st)
	if !strings.Contains(out, "try_files $uri $uri/ =404") {
		t.Error("static mode should 404 unknown paths")
	}
	if strings.Contains(out, "fastcgi_pass") {
		t.Error("static mode should not run PHP")
	}
}

// Proxy mode forwards to the app's private unix socket; the ^~ ACME location
// out-ranks the proxy location so certbot keeps working.
func TestNginxProxyMode(t *testing.T) {
	sock := "/run/openpropanel-apps/app.com/app.sock"
	vh := webserver.VHost{Domain: "app.com", DocRoot: "/srv/app", Mode: "proxy", SocketPath: sock, SSL: true, CertFile: "/c", KeyFile: "/k"}
	out := renderNginx(t, vh)
	if !strings.Contains(out, "proxy_pass http://unix:"+sock+":/;") {
		t.Error("proxy mode should proxy_pass to the app's unix socket")
	}
	if !strings.Contains(out, "location ^~ /.well-known/acme-challenge/ {") {
		t.Error("proxy mode must keep the higher-priority ACME challenge location")
	}
	if strings.Contains(out, "fastcgi_pass") {
		t.Error("proxy mode should not run PHP")
	}
	if strings.Contains(out, "127.0.0.1") {
		t.Error("proxy target must be the unix socket, not a TCP port")
	}
}

// A tenant-owned symlink inside a doc root (e.g. a git checkout swapped for a
// link into another tenant's tree) must never be followed: both the :80 and
// :443 server blocks need disable_symlinks (mirrors Apache's
// SymLinksIfOwnerMatch).
func TestNginxRefusesForeignSymlinks(t *testing.T) {
	vh := webserver.VHost{Domain: "x.com", DocRoot: "/srv/x", Mode: "php", SSL: true, CertFile: "/c", KeyFile: "/k"}
	out := renderNginx(t, vh)
	if n := strings.Count(out, "disable_symlinks if_not_owner;"); n != 2 {
		t.Errorf("want disable_symlinks if_not_owner in both server blocks, found %d", n)
	}
	plain := webserver.VHost{Domain: "x.com", DocRoot: "/srv/x", Mode: "php"}
	if !strings.Contains(renderNginx(t, plain), "disable_symlinks if_not_owner;") {
		t.Error("non-SSL server block must also disable foreign symlinks")
	}
}
