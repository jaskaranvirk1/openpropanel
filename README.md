<div align="center">

# Open ProPanel

**A minimal, beautiful, open-source server control panel — a lightweight cPanel alternative.**

Single Go binary · Tailwind + HTMX UI · built for AlmaLinux / RHEL

</div>

---

Open ProPanel lets you manage a web server from a clean browser UI: add domains and
subdomains, auto-generate Apache virtual hosts, switch PHP versions per site,
and issue Let's Encrypt certificates — all with one click. The entire UI is
embedded in a single self-contained binary, so installation is one file plus a
systemd unit.

## Features (v1)

- **Dashboard** — live CPU, memory, disk and load, with start/stop/restart/reload for Apache, PHP-FPM, MariaDB and firewalld.
- **Domains** — add a domain and Open ProPanel creates the document root, an Apache vhost, and a dedicated PHP-FPM pool, then validates (`httpd -t`) and reloads.
- **Subdomains** — one-click, under any existing domain.
- **Auto SSL** — Let's Encrypt via `certbot` (HTTP-01 webroot); the vhost is rewritten to HTTPS with an automatic HTTP→HTTPS redirect. Renewal is handled by certbot's own timer.
- **Per-site PHP versions** — each site runs its own PHP-FPM pool (system PHP or Remi `php83`/`php82`/… auto-detected), isolated under the account's system user with a restrictive `open_basedir`.
- **Apache or Nginx** — pick either from Settings; switching regenerates every site's config, reprovisions php-fpm sockets, and swaps the service at runtime.
- **MariaDB** — create databases and database users (username-prefixed), grant/revoke access, reset passwords — all per account.
- **Multi-user** — admin accounts manage the server; user accounts own their own domains, databases and files, each isolated under its own Linux system user. Ownership is enforced on every action.
- **Secure by design** — bcrypt passwords, server-side sessions, `SameSite=Strict` cookies + same-origin CSRF guard, strict domain/identifier validation, nginx dotfile denial + HSTS, and a single audited command-execution choke-point (no shell string interpolation). Reviewed by adversarial multi-agent audits at each milestone.

## Architecture

```
cmd/openpropanel/main.go        entrypoint · first-run admin · graceful shutdown
internal/
  config/    AlmaLinux-aware paths (httpd, php-fpm) + dev fallback on non-Linux
  store/     SQLite via pure-Go modernc.org/sqlite — no CGO, so one static binary
  auth/      bcrypt + cookie sessions + auth/admin/CSRF middleware
  system/    the ONLY place that runs commands: systemctl, certbot, live stats
  apache/    vhost templating, httpd -t validation, graceful reload
  php/        per-site PHP-FPM pools + version detection/switching
  ssl/        certbot webroot issuance + cert tracking
  domains/   orchestration: docroot → pool → vhost → SSL → reload (+ rollback)
  web/        HTMX handlers + embedded Tailwind templates & static assets
packaging/   systemd unit · install.sh · RPM spec
```

Everything under `web/templates` and `web/static` (including the compiled
Tailwind CSS and HTMX) is compiled into the binary with `go:embed`.

## Requirements

- **Server:** AlmaLinux / RHEL 9 or 10 (or any systemd distro with `httpd`, `php-fpm`, `certbot`).
- **Build:** Go 1.23+ and Node (for the Tailwind CLI). Both are only needed to build; the shipped binary needs neither.

> A control panel manages system services, so it must run **on the server** with
> privileges. You can develop the UI on any OS (see below), but the Apache/PHP/SSL
> features only take effect on the Linux host.

## Quick start — local development (Windows / macOS / Linux)

On a non-Linux host Open ProPanel runs in **dev mode**: it keeps all state inside a
local `./data` directory and *simulates* system changes (it writes real vhost /
pool / cert files under `./data` so you can inspect them, but never touches the
host).

```bash
# build the CSS and a host binary, then run
make run                 # -> http://localhost:2087
# ...or without make:
npx tailwindcss@3 -i css/input.css -o internal/web/static/app.css --minify
go run ./cmd/openpropanel -listen :2087
```

The first run prints an `admin` password (also saved to
`data/initial-admin-password.txt`). Log in and explore.

## Install on a server (AlmaLinux / RHEL)

Open ProPanel ships as **one static, dependency-free binary** with the whole UI
embedded, so the target server needs no build tools — just the binary.

**Option A — one command (recommended).** Downloads the prebuilt binary for the
server's architecture, installs the runtime deps, and starts the service:

```bash
curl -fsSL https://raw.githubusercontent.com/openpropanel/openpropanel/main/scripts/get.sh | sudo bash
```

**Option B — RPM:**

```bash
sudo dnf install ./openpropanel-*.rpm      # from a GitHub release
sudo systemctl enable --now openpropanel
```

**Option C — from source (needs Go + Node):**

```bash
git clone https://github.com/openpropanel/openpropanel.git && cd openpropanel
make install            # cross-builds the binary, installs deps + service
```

Either way the installer drops the binary at `/usr/local/bin/openpropanel`, installs
the systemd unit, opens the firewall (80, 443, 2087), and starts the service.

Get the first-run admin password from `journalctl -u openpropanel` or
`/var/lib/openpropanel/initial-admin-password.txt`, then browse to
`http://<server-ip>:2087`.

## Configuration

`/etc/openpropanel/config.json` (all keys optional; sensible AlmaLinux defaults):

```json
{
  "listen_addr": ":2087",
  "web_root": "/var/www",
  "apache_vhost_dir": "/etc/httpd/conf.d",
  "php_fpm_conf_dir": "/etc/php-fpm.d",
  "apache_service": "httpd",
  "acme_email": "you@example.com"
}
```

`acme_email` (also settable in **Settings**) is required before enabling SSL.

## Panel HTTPS

The panel serves **HTTPS by default** in production. On first boot it generates
a self-signed certificate under `/var/lib/openpropanel/tls`; you can upgrade to a
real, browser-trusted certificate two ways:

- **Let's Encrypt (automatic):** in **Settings → Panel HTTPS**, enter the
  hostname you reach the panel at (e.g. `panel.yourdomain.com`) and click *Get
  certificate*. Open ProPanel answers the HTTP-01 challenge through Apache and points
  the panel at the issued cert. Renewals (via certbot's timer) are picked up
  **live** — the cert is hot-reloaded, no restart. Requires the hostname to
  resolve to this server with port 80 reachable.
- **Bring your own:** set `tls_cert` / `tls_key` in the config to your PEM files.

> Note: `openssl` is not a separate option — a self-signed cert *is* what
> `openssl req -x509` produces. Open ProPanel generates the equivalent internally; the
> only way to remove the browser warning is a CA-signed cert (the two options above).

## Security notes — read before exposing it

- The service runs **privileged** (it edits system config and controls
  services). Treat access to it as equivalent to root on the box — keep port
  2087 firewalled to trusted IPs even though it is HTTPS.
- Change the generated admin password immediately.
- Use a real certificate (above) before relying on it over the public internet.

## Building & releasing

The binary is CGO-free, so it cross-compiles to any Linux arch from any host:

```bash
make dist        # -> dist/openpropanel_linux_{amd64,arm64}.tar.gz + checksums.txt
```

Cutting a versioned release is automated with GoReleaser + GitHub Actions —
push a tag and CI builds the binaries, `.tar.gz` archives, an `.rpm`, and
checksums, and publishes them to a GitHub release:

```bash
git tag v0.1.0 && git push origin v0.1.0
```

The `scripts/get.sh` one-liner then installs that release on any server. To host
the binaries yourself instead of GitHub, point the installer at your own URL:
`PROPANEL_BASE_URL=https://dl.example.com curl -fsSL .../get.sh | sudo bash`.

## Roadmap

- [x] Built-in HTTPS for the panel (self-signed + automatic Let's Encrypt, hot-reloading)
- [x] System-user provisioning (`useradd`/`userdel`) for per-tenant isolation
- [x] MariaDB database & user management (databases, users, grants)
- [x] Nginx support — switch between Apache and Nginx at runtime
- [ ] Disk/CPU quotas per account
- [ ] File manager, cron editor, firewall UI
- [ ] DNS zones, backups, one-click app installs
- [ ] Nginx-in-front-of-Apache reverse-proxy mode

## License

MIT — see [LICENSE](LICENSE).
