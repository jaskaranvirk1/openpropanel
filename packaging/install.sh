#!/usr/bin/env bash
#
# Open ProPanel installer for AlmaLinux / RHEL 9 & 10.
#
# Run as root from the directory that contains the built binary (bin/openpropanel)
# and this packaging/ folder:
#
#     sudo ./packaging/install.sh
#
# It installs the runtime dependencies (Apache, PHP-FPM, certbot), the Open ProPanel
# binary and systemd unit, opens the firewall, sets the required SELinux
# booleans, and starts the service.

set -euo pipefail

PANEL_PORT="${PANEL_PORT:-9443}"
BIN_DEST="/usr/local/bin/openpropanel"
CONF_DIR="/etc/openpropanel"
UNIT_DEST="/etc/systemd/system/openpropanel.service"

log()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m warning:\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m error:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "please run as root (sudo)"

# Resolve paths relative to this script so it works from anywhere.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

# Locate the built binary.
BIN_SRC=""
for candidate in "$REPO_DIR/bin/openpropanel" "$REPO_DIR/openpropanel" "$SCRIPT_DIR/openpropanel"; do
    [ -x "$candidate" ] && BIN_SRC="$candidate" && break
done
[ -n "$BIN_SRC" ] || die "built binary not found — run 'make build' first (produces bin/openpropanel)"

log "Checking runtime dependencies (installing only what is missing)"
# MariaDB installed by default (Databases + phpMyAdmin); PROPANEL_NO_DB=1 to skip.
# git + openssh-clients power "Deploy from GitHub" (clone/fetch as the tenant).
REQUIRED="httpd mod_ssl php-fpm certbot firewalld git openssh-clients"
[ "${PROPANEL_NO_DB:-0}" = "1" ] || REQUIRED="$REQUIRED mariadb-server"
missing=""
for pkg in $REQUIRED; do
    rpm -q "$pkg" >/dev/null 2>&1 || missing="$missing $pkg"
done
missing="$(echo $missing)" # trim
if [ -n "$missing" ]; then
    log "Installing missing packages:$missing"
    case " $missing " in *" certbot "*) dnf install -y epel-release >/dev/null 2>&1 || true ;; esac
    dnf install -y $missing || warn "could not install:$missing (install manually if a feature needs it)"
else
    log "All runtime dependencies already present — skipping install"
fi

log "Enabling web/PHP services"
systemctl enable --now php-fpm   || warn "php-fpm not available"
systemctl enable --now httpd     || warn "httpd not available"

# Reverse-proxy hosting (Run an app) needs mod_proxy_http + mod_headers. They
# ship enabled in the httpd RPM, but a hardened base image may have dropped them.
if command -v httpd >/dev/null 2>&1; then
    mods="$(httpd -M 2>/dev/null || true)"
    for m in proxy_module proxy_http_module headers_module; do
        case "$mods" in
            *"$m"*) ;;
            *) warn "Apache module $m is not loaded — 'Run an app' (reverse proxy) needs it. Enable it in /etc/httpd/conf.modules.d/ and reload httpd." ;;
        esac
    done
fi
systemctl enable --now firewalld || warn "firewalld not available; skipping firewall config"
if [ "${PROPANEL_NO_DB:-0}" != "1" ]; then
    systemctl enable --now mariadb || warn "MariaDB installed but not started — check: systemctl status mariadb"
fi

log "Installing Open ProPanel binary -> $BIN_DEST"
install -m 0755 "$BIN_SRC" "$BIN_DEST"

# Terminal git helper: inside a site's checkout (owned by the site's non-root
# user), plain `git pull`/`status`/`log` from an admin shell would trip git's
# "dubious ownership" guard, and forcing it as root would leave root-owned files
# that break the panel's next deploy. This drop-in makes git transparently run as
# the checkout's owner — only for repos owned by ANOTHER non-root user; your own
# root-owned repos are untouched. Remove the file to disable.
log "Installing the terminal git helper (/etc/profile.d/openpropanel-git.sh)"
install -d -m 0755 /etc/profile.d
cat > /etc/profile.d/openpropanel-git.sh <<'EOF'
# Managed by Open ProPanel. Runs git as the checkout's owner inside site repos so
# `git pull` works from an admin shell (no sudo/-C, no "dubious ownership"). Only
# repos owned by another non-root user are delegated; delete this file to disable.
git() {
    _opp_top=$(command git -c safe.directory='*' rev-parse --show-toplevel 2>/dev/null) || { command git "$@"; return; }
    _opp_owner=$(stat -c '%U' "$_opp_top" 2>/dev/null)
    if [ -n "$_opp_owner" ] && [ "$_opp_owner" != "root" ] && [ "$_opp_owner" != "$(id -un)" ] && command -v sudo >/dev/null 2>&1; then
        sudo -u "$_opp_owner" -H -- git "$@"
    else
        command git "$@"
    fi
}
EOF
chmod 0644 /etc/profile.d/openpropanel-git.sh

log "Creating config at $CONF_DIR"
mkdir -p "$CONF_DIR"
CONF="$CONF_DIR/config.json"
if [ ! -f "$CONF" ]; then
    cat > "$CONF" <<JSON
{
  "listen_addr": ":${PANEL_PORT}",
  "acme_email": ""
}
JSON
    chmod 600 "$CONF"
else
    # Upgrade: migrate the retired 2087 default and adopt the config's port so the
    # firewall + banner match what the panel actually listens on.
    if grep -q '":2087"' "$CONF"; then
        sed -i 's/":2087"/":9443"/' "$CONF"
        firewall-cmd --permanent --remove-port=2087/tcp >/dev/null 2>&1 || true
        log "Migrated panel port 2087 -> 9443 in $CONF"
    fi
    cfgport="$(sed -nE 's/.*"listen_addr"[[:space:]]*:[[:space:]]*"[^"]*:([0-9]+)".*/\1/p' "$CONF" | head -1)"
    if [ -n "$cfgport" ]; then PANEL_PORT="$cfgport"; fi
fi
# Cockpit-style TLS drop-in: put panel.crt + panel.key here to serve a real cert.
mkdir -p "$CONF_DIR/certs"
chmod 700 "$CONF_DIR/certs"

log "Installing systemd unit"
install -m 0644 "$SCRIPT_DIR/openpropanel.service" "$UNIT_DEST"
systemctl daemon-reload

if command -v firewall-cmd >/dev/null 2>&1; then
    log "Configuring firewall (http, https, panel port)"
    if [ -d /etc/firewalld/services ]; then
        cat > /etc/firewalld/services/openpropanel.xml <<XML
<?xml version="1.0" encoding="utf-8"?>
<service>
  <short>Open ProPanel</short>
  <description>Open ProPanel web control panel.</description>
  <port protocol="tcp" port="${PANEL_PORT}"/>
</service>
XML
    fi
    firewall-cmd --add-service=http  --permanent >/dev/null 2>&1 || true
    firewall-cmd --add-service=https --permanent >/dev/null 2>&1 || true
    # PROPANEL_OPEN: all (default) reachable from anywhere; ip = your IP only; none = closed.
    case "${PROPANEL_OPEN:-all}" in
        none|closed) log "Panel port ${PANEL_PORT} left CLOSED — reach it via an SSH tunnel" ;;
        ip|ssh|ssh-ip)
            ipsrc="$(echo "${SSH_CONNECTION:-}" | awk '{print $1}')"
            [ -z "$ipsrc" ] && ipsrc="$(echo "${SSH_CLIENT:-}" | awk '{print $1}')"
            if [ -n "$ipsrc" ]; then
                firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=${ipsrc}/32 port port=${PANEL_PORT} protocol=tcp accept" >/dev/null 2>&1 || true
            else
                warn "PROPANEL_OPEN=ip but couldn't detect your SSH client IP — leaving ${PANEL_PORT} CLOSED"
            fi ;;
        *) firewall-cmd --add-port="${PANEL_PORT}/tcp" --permanent >/dev/null 2>&1 || true ;;
    esac
    firewall-cmd --reload >/dev/null 2>&1 || true
fi

# Reverse-proxy apps: the run root holds one per-app dir each, in which a tenant
# app creates its unix socket. It lives on tmpfs (/run), so systemd-tmpfiles must
# recreate it every boot before any app unit starts.
log "Provisioning the reverse-proxy app run root"
install -d -m 0755 /etc/tmpfiles.d
cat > /etc/tmpfiles.d/openpropanel.conf <<'EOF'
# Managed by Open ProPanel — run root for reverse-proxied app sockets.
d /run/openpropanel-apps 0755 root root -
EOF
systemd-tmpfiles --create /etc/tmpfiles.d/openpropanel.conf >/dev/null 2>&1 || \
    install -d -m 0755 -o root -g root /run/openpropanel-apps

if command -v restorecon >/dev/null 2>&1; then
    log "Ensuring SELinux file context on the web root + app sockets"
    # Apache <-> PHP-FPM over the /run/php-fpm unix socket is permitted by
    # default under enforcing SELinux, so no boolean is required. We only make
    # sure the web root is labelled so httpd may read it (matters if it was
    # relocated from the default /var/www).
    if command -v semanage >/dev/null 2>&1; then
        semanage fcontext -a -t httpd_sys_content_t '/var/www(/.*)?' 2>/dev/null || true
        # Label the app-socket tree httpd_var_run_t so httpd/nginx (httpd_t) may
        # connect(2) to the tenant-created sockets, like /run/php-fpm.
        semanage fcontext -a -t httpd_var_run_t '/run/openpropanel-apps(/.*)?' 2>/dev/null || true
    fi
    restorecon -R /var/www 2>/dev/null || true
    restorecon -R /run/openpropanel-apps 2>/dev/null || true
fi

log "Starting Open ProPanel"
systemctl enable openpropanel >/dev/null 2>&1 || true
systemctl restart openpropanel   # restart so a re-run applies the new binary/config

# Wait for first-run to generate the random admin credentials, then read them.
# Reads are guarded with '|| true' so a slow first boot cannot abort under set -e.
CREDS="/var/lib/openpropanel/initial-admin-password.txt"
for _ in $(seq 1 30); do [ -s "$CREDS" ] && break; sleep 0.5; done
USERNAME="$(awk -F': ' '/^username:/{print $2}' "$CREDS" 2>/dev/null || true)"
PASSWORD="$(awk -F': ' '/^password:/{print $2}' "$CREDS" 2>/dev/null || true)"
PUB_IP="$(curl -fsS --max-time 4 https://api.ipify.org 2>/dev/null || true)"

# Preflight health check so any environment problem is visible right away.
echo
"$BIN_DEST" doctor 2>/dev/null || true

echo
echo "=================================================================="
echo "  Open ProPanel is installed and running."
echo "=================================================================="
echo "  Access from anywhere:"
[ -n "$PUB_IP" ] && echo "     https://${PUB_IP}:${PANEL_PORT}" || echo "     https://<server-ip>:${PANEL_PORT}"
echo
echo "  Username:  ${USERNAME:-(unchanged from first install)}"
echo "  Password:  ${PASSWORD:-(unchanged from first install)}"
if [ -z "$PASSWORD" ]; then
    echo "             Lost it? Reset with:  ${BIN_DEST} reset-password"
else
    echo "  (Change the password right after your first login.)"
fi
echo "------------------------------------------------------------------"
echo "  * HTTPS is self-signed by default — click through the browser warning."
echo "    For a trusted cert: point a domain here and use Settings -> Panel"
echo "    HTTPS, or drop panel.crt + panel.key into ${CONF_DIR}/certs/."
echo "  * Panel port ${PANEL_PORT} is open to the internet; restrict to your IP with a"
echo "    firewalld rich-rule if you prefer."
echo "=================================================================="
echo
