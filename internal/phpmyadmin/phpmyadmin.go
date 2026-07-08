// Package phpmyadmin installs phpMyAdmin and serves it BEHIND the panel: the
// panel dispatches its PHP to php-fpm over FastCGI and serves its static assets
// directly, all under the /phpmyadmin URL path and gated by the panel's auth
// middleware (so only logged-in panel users can reach it). phpMyAdmin is
// installed into cfg.PMARoot/phpmyadmin and mounted at /phpmyadmin, so
// SCRIPT_NAME naturally carries the prefix and phpMyAdmin builds correct URLs
// without any rewriting.
//
// Isolation model: the FastCGI pool listens on a unix socket owned root:root
// mode 0600, so the root-run panel is its ONLY client — phpMyAdmin is never
// reachable except through an authenticated panel session. The pool runs as the
// unprivileged web-server user with a tight open_basedir, and users still have
// to authenticate to MariaDB with their own credentials (cookie auth), so
// MariaDB's own privilege model scopes each user to their own databases.
package phpmyadmin

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	osuser "os/user"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/openpropanel/openpropanel/internal/config"
	"github.com/openpropanel/openpropanel/internal/system"
	"github.com/yookoala/gofast"
)

// Version pins the phpMyAdmin release that Install downloads, and
// tarballSHA256 is the upstream SHA-256 of that exact release's
// all-languages tarball (from files.phpmyadmin.net/.../*.tar.gz.sha256).
// Pinning the hash means a tampered or corrupted download is rejected before a
// single file is unpacked — we never trust the mirror, only the bytes.
const (
	Version       = "5.2.3"
	tarballSHA256 = "12ba1c425fa4071abbd4e7668c9ebdeac0b0755a467a6d6d5026122bb47c102b"

	// Safety caps for the download/extract so a hostile mirror cannot exhaust
	// disk with an oversized or decompression-bomb archive.
	maxArchiveBytes = 100 << 20 // compressed tarball ceiling (~15MB expected)
	maxExtractBytes = 600 << 20 // total extracted bytes ceiling (~60MB expected)
)

// Manager installs and serves phpMyAdmin.
type Manager struct {
	cfg     *config.Config
	handler http.Handler
}

// New constructs a Manager and builds its HTTP handler up front (so serving is
// race-free — no lazy check-then-assign under concurrent requests).
func New(cfg *config.Config) *Manager {
	m := &Manager{cfg: cfg}
	m.handler = m.buildHandler()
	return m
}

// pmaSystemUser is the dedicated, unprivileged account the phpMyAdmin FPM pool
// runs as. It must be an identity NO tenant pool ever uses (tenant pools may run
// as the shared "apache" user), so a compromised tenant process cannot read
// phpMyAdmin's blowfish secret or session files.
const pmaSystemUser = "openpropanel-pma"

// Installed reports whether phpMyAdmin is present on disk.
func (m *Manager) Installed() bool {
	fi, err := os.Stat(filepath.Join(m.cfg.PhpMyAdminDir(), "index.php"))
	return err == nil && !fi.IsDir()
}

// Install downloads the pinned phpMyAdmin release, verifies its checksum,
// extracts it, writes a hardened config, and provisions its php-fpm pool. The
// download/verify/extract/config steps run everywhere (so the flow is
// testable), but the php-fpm pool + reload only happen on the real server.
func (m *Manager) Install(ctx context.Context) error {
	url := fmt.Sprintf(
		"https://files.phpmyadmin.net/phpMyAdmin/%s/phpMyAdmin-%s-all-languages.tar.gz",
		Version, Version)
	dir := m.cfg.PhpMyAdminDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	// Download to a temp file and verify the SHA-256 against the baked-in pin
	// BEFORE extracting anything.
	archive, err := os.CreateTemp("", "openpropanel-pma-*.tar.gz")
	if err != nil {
		return err
	}
	archivePath := archive.Name()
	_ = archive.Close()
	defer os.Remove(archivePath)

	if err := download(ctx, url, archivePath); err != nil {
		return fmt.Errorf("download phpMyAdmin: %w", err)
	}
	sum, err := sha256File(archivePath)
	if err != nil {
		return err
	}
	if !strings.EqualFold(sum, tarballSHA256) {
		return fmt.Errorf("phpMyAdmin %s checksum mismatch (got %s) — refusing to install", Version, sum)
	}
	if err := extractTarGz(archivePath, dir); err != nil {
		return fmt.Errorf("extract phpMyAdmin: %w", err)
	}
	// Remove the setup wizard entirely: it is a historically sensitive surface
	// (it can write config and probe servers) and is never needed once we ship a
	// finished config.inc.php. Handler() also hard-denies /setup as defence in
	// depth in case an old install predates this removal.
	_ = os.RemoveAll(filepath.Join(dir, "setup"))
	if err := m.writeConfig(); err != nil {
		return fmt.Errorf("write phpMyAdmin config: %w", err)
	}
	if err := m.writePool(ctx); err != nil {
		return fmt.Errorf("php-fpm pool: %w", err)
	}
	return nil
}

// Handler serves phpMyAdmin (static files directly, PHP via php-fpm). It must
// only be used on a host with the php-fpm pool running.
func (m *Manager) Handler() http.Handler { return m.handler }

func (m *Manager) buildHandler() http.Handler {
	root := m.cfg.PMARoot
	connFactory := gofast.SimpleConnFactory("unix", m.cfg.PMASocket())
	fcgi := gofast.NewHandler(
		gofast.NewPHPFS(root)(gofast.BasicSession),
		gofast.SimpleClientFactory(connFactory),
	)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := path.Clean("/" + strings.TrimPrefix(r.URL.Path, "/"))
		full := filepath.Join(root, filepath.FromSlash(clean))
		if !within(root, full) {
			http.NotFound(w, r)
			return
		}
		// Never serve the setup wizard, even if a stale install still has it on
		// disk. Match the "setup" path segment under the phpmyadmin app dir.
		if seg := strings.ToLower(clean); strings.Contains(seg+"/", "/phpmyadmin/setup/") {
			http.NotFound(w, r)
			return
		}
		if fi, err := os.Stat(full); err == nil && fi.IsDir() {
			// Directory → serve its index.php through FastCGI.
			r = r.Clone(r.Context())
			r.URL.Path = strings.TrimRight(clean, "/") + "/index.php"
		} else if err == nil && !strings.HasSuffix(clean, ".php") {
			// Existing non-PHP file → serve the static asset directly.
			http.ServeFile(w, r, full)
			return
		}
		fcgi.ServeHTTP(w, r)
	})
}

// writeConfig writes a hardened config.inc.php (cookie auth; users log in with
// their own MariaDB credentials). It is left alone if already present so the
// blowfish secret (and thus active sessions) survive a re-install.
func (m *Manager) writeConfig() error {
	dir := m.cfg.PhpMyAdminDir()
	tmp := filepath.Join(dir, "tmp")
	// 0700: the session/temp dir must not be world-writable on a shared host.
	// writePool then hands it to the pool user.
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		return err
	}
	confPath := filepath.Join(dir, "config.inc.php")
	if _, err := os.Stat(confPath); err == nil {
		return nil // keep existing config
	}
	secret, err := randomHex(32) // 64 hex chars — comfortably over phpMyAdmin's 32-char minimum
	if err != nil {
		return err
	}
	socket := "/var/lib/mysql/mysql.sock"
	conf := "<?php\n" +
		"declare(strict_types=1);\n" +
		"$cfg['blowfish_secret'] = '" + secret + "';\n" +
		"$i = 0;\n$i++;\n" +
		"$cfg['Servers'][$i]['auth_type'] = 'cookie';\n" +
		"$cfg['Servers'][$i]['host'] = 'localhost';\n" +
		"$cfg['Servers'][$i]['socket'] = '" + socket + "';\n" +
		"$cfg['Servers'][$i]['AllowNoPassword'] = false;\n" +
		// Block logging in as MariaDB root through the shared panel phpMyAdmin,
		// and never let a user point phpMyAdmin at an arbitrary DB host.
		"$cfg['Servers'][$i]['AllowRoot'] = false;\n" +
		"$cfg['AllowArbitraryServer'] = false;\n" +
		// Idle-logout after 30 min and never persist the login cookie to disk,
		// bounding the window in which a stolen cookie is useful.
		"$cfg['LoginCookieValidity'] = 1800;\n" +
		"$cfg['LoginCookieStore'] = 0;\n" +
		// Reduce fingerprinting / do not phone home.
		"$cfg['ShowServerInfo'] = false;\n" +
		"$cfg['VersionCheck'] = false;\n" +
		"$cfg['SendErrorReports'] = 'never';\n" +
		"$cfg['TempDir'] = '" + filepath.ToSlash(tmp) + "';\n"
	return os.WriteFile(confPath, []byte(conf), 0o640)
}

// writePool writes the dedicated php-fpm pool for phpMyAdmin and reloads FPM.
// No-op in dev (no php-fpm). It also fixes ownership so the unprivileged pool
// user can read config.inc.php and write sessions, without granting write
// access to phpMyAdmin's code or leaking the config to other tenants.
func (m *Manager) writePool(ctx context.Context) error {
	if m.cfg.Dev {
		return nil
	}
	// Run the pool as a DEDICATED unprivileged user (never the shared web-server
	// user that tenant pools may also run as), so no tenant process shares this
	// identity and can read the blowfish secret / session files.
	if err := m.ensurePMAUser(ctx); err != nil {
		return err
	}
	user := pmaSystemUser
	dir := m.cfg.PhpMyAdminDir()
	pool := fmt.Sprintf(`; Managed by Open ProPanel — do not edit by hand.
[openpropanel-pma]
user = %s
group = %s
listen = %s
; The panel (root) is the only client of this socket.
listen.owner = root
listen.group = root
listen.mode = 0600
pm = ondemand
pm.max_children = 5
pm.process_idle_timeout = 30s
; Jail the pool to phpMyAdmin's own tree. The MariaDB socket connection is not a
; filesystem operation, so it needs no open_basedir entry; keep /tmp OUT so the
; pool never touches the shared, world-writable temp dir.
php_admin_value[open_basedir] = %s
php_admin_value[session.save_path] = %s/tmp
php_admin_value[upload_tmp_dir] = %s/tmp
php_admin_value[session.gc_maxlifetime] = 1800
`, user, user, m.cfg.PMASocket(), dir, dir, dir)

	if err := os.WriteFile(filepath.Join(m.cfg.PHPFPMConfDir, "openpropanel-pma.conf"), []byte(pool), 0o644); err != nil {
		return err
	}

	// config.inc.php: keep it root-owned (so the pool user can never rewrite it
	// or phpMyAdmin's code) but readable by the pool group, mode 0640. The pool
	// user reads its blowfish secret; other tenants running as a different user
	// cannot.
	confPath := filepath.Join(dir, "config.inc.php")
	if u, err := osuser.Lookup(user); err == nil {
		if gid, err := strconv.Atoi(u.Gid); err == nil {
			_ = os.Chown(confPath, 0, gid) // root:<pma group>
			_ = os.Chmod(confPath, 0o640)
		}
	}
	// The temp/session dir must be writable by the pool user.
	chownTree(filepath.Join(dir, "tmp"), user)
	return system.ServiceAction(ctx, "reload", m.cfg.PHPFPMService)
}

// ensurePMAUser makes sure the dedicated, unprivileged pool account exists. It
// is created as a system account with no login and no home directory. If a
// non-service account with this name somehow already exists it is reused as-is.
func (m *Manager) ensurePMAUser(ctx context.Context) error {
	if _, err := osuser.Lookup(pmaSystemUser); err == nil {
		return nil
	}
	if _, err := system.Run(ctx, "useradd", "--system", "--no-create-home", "--shell", "/sbin/nologin", pmaSystemUser); err != nil {
		return fmt.Errorf("create phpMyAdmin service user %q: %w", pmaSystemUser, err)
	}
	return nil
}

func chownTree(pathStr, user string) {
	u, err := osuser.Lookup(user)
	if err != nil {
		return
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		return
	}
	_ = filepath.WalkDir(pathStr, func(p string, _ os.DirEntry, err error) error {
		if err == nil {
			_ = os.Chown(p, uid, gid)
		}
		return nil
	})
}

// download streams url to dest, capped at maxArchiveBytes.
func download(ctx context.Context, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d fetching %s", resp.StatusCode, url)
	}
	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	n, err := io.Copy(f, io.LimitReader(resp.Body, maxArchiveBytes+1))
	if err != nil {
		return err
	}
	if n > maxArchiveBytes {
		return fmt.Errorf("download exceeds %d bytes", maxArchiveBytes)
	}
	return nil
}

func sha256File(pathStr string) (string, error) {
	f, err := os.Open(pathStr)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// extractTarGz extracts a local .tar.gz into dest, stripping the archive's
// single top-level directory. It guards against path traversal (zip-slip) and
// caps the total extracted size (decompression bomb).
func extractTarGz(archivePath, dest string) error {
	af, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer af.Close()
	gz, err := gzip.NewReader(af)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	budget := int64(maxExtractBytes)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		rel := stripFirstComponent(hdr.Name)
		if rel == "" {
			continue
		}
		target := filepath.Join(dest, filepath.FromSlash(rel))
		if !within(dest, target) {
			continue // zip-slip guard
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			_ = os.MkdirAll(target, 0o755)
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
			if err != nil {
				return err
			}
			n, err := io.Copy(f, io.LimitReader(tr, budget+1))
			f.Close()
			if err != nil {
				return err
			}
			budget -= n
			if budget < 0 {
				return fmt.Errorf("archive exceeds %d bytes (possible decompression bomb)", maxExtractBytes)
			}
		}
	}
	return nil
}

func stripFirstComponent(name string) string {
	name = strings.TrimPrefix(filepath.ToSlash(name), "./")
	if i := strings.IndexByte(name, '/'); i >= 0 {
		return name[i+1:]
	}
	return ""
}

func within(root, p string) bool {
	root = filepath.Clean(root)
	p = filepath.Clean(p)
	return p == root || strings.HasPrefix(p, root+string(os.PathSeparator))
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
