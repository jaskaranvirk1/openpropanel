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

PANEL_PORT="${PANEL_PORT:-2087}"
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

log "Installing runtime dependencies via dnf"
dnf install -y epel-release || warn "epel-release may already be present"
dnf install -y httpd mod_ssl php php-fpm certbot firewalld

log "Enabling mod_proxy_fcgi + web/PHP services"
systemctl enable --now php-fpm
systemctl enable --now httpd
systemctl enable --now firewalld || warn "firewalld not available; skipping firewall config"

log "Installing Open ProPanel binary -> $BIN_DEST"
install -m 0755 "$BIN_SRC" "$BIN_DEST"

log "Creating config at $CONF_DIR"
mkdir -p "$CONF_DIR"
if [ ! -f "$CONF_DIR/config.json" ]; then
    cat > "$CONF_DIR/config.json" <<JSON
{
  "listen_addr": ":${PANEL_PORT}",
  "acme_email": ""
}
JSON
    chmod 600 "$CONF_DIR/config.json"
fi

log "Installing systemd unit"
install -m 0644 "$SCRIPT_DIR/openpropanel.service" "$UNIT_DEST"
systemctl daemon-reload

if command -v firewall-cmd >/dev/null 2>&1; then
    log "Opening firewall (http, https, ${PANEL_PORT}/tcp)"
    firewall-cmd --add-service=http  --permanent  >/dev/null || true
    firewall-cmd --add-service=https --permanent  >/dev/null || true
    firewall-cmd --add-port="${PANEL_PORT}/tcp" --permanent >/dev/null || true
    firewall-cmd --reload >/dev/null || true
fi

if command -v restorecon >/dev/null 2>&1; then
    log "Ensuring SELinux file context on the web root"
    # Apache <-> PHP-FPM over the /run/php-fpm unix socket is permitted by
    # default under enforcing SELinux, so no boolean is required. We only make
    # sure the web root is labelled so httpd may read it (matters if it was
    # relocated from the default /var/www).
    if command -v semanage >/dev/null 2>&1; then
        semanage fcontext -a -t httpd_sys_content_t '/var/www(/.*)?' 2>/dev/null || true
    fi
    restorecon -R /var/www 2>/dev/null || true
fi

log "Starting Open ProPanel"
systemctl enable --now openpropanel

# Wait for first-run to generate the random admin credentials, then read them.
CREDS="/var/lib/openpropanel/initial-admin-password.txt"
for _ in $(seq 1 20); do [ -s "$CREDS" ] && break; sleep 0.5; done
USERNAME="$(awk -F': ' '/^username:/{print $2}' "$CREDS" 2>/dev/null)"
PASSWORD="$(awk -F': ' '/^password:/{print $2}' "$CREDS" 2>/dev/null)"
LAN_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
PUB_IP="$(curl -fsS --max-time 4 https://api.ipify.org 2>/dev/null || true)"

echo
echo "=================================================================="
echo " Open ProPanel installed successfully!"
echo "=================================================================="
[ -n "$PUB_IP" ] && echo " Panel URL (external): https://${PUB_IP}:${PANEL_PORT}"
[ -n "$LAN_IP" ] && echo " Panel URL (internal): https://${LAN_IP}:${PANEL_PORT}"
echo " Username:             ${USERNAME:-admin}"
echo " Password:             ${PASSWORD:-see: journalctl -u openpropanel}"
echo "=================================================================="
echo " * Opened by IP, the panel uses a self-signed HTTPS cert (Let's Encrypt"
echo "   can't issue for bare IPs) — accept the browser warning. Point a domain"
echo "   at it for a free Let's Encrypt cert under Settings -> Panel HTTPS."
echo " * You can change the username/password after logging in."
echo " * Keep port ${PANEL_PORT} firewalled to trusted IPs (it runs as root)."
echo "=================================================================="
echo
