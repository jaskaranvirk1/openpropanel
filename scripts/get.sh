#!/usr/bin/env bash
#
# Open ProPanel one-command installer.
#
#   curl -fsSL https://raw.githubusercontent.com/jaskaranvirk1/openpropanel/main/scripts/get.sh | sudo bash
#
# Downloads the prebuilt Open ProPanel binary for this server's architecture from the
# GitHub release, installs the runtime dependencies (Apache, PHP-FPM, certbot),
# sets up the systemd service + firewall, and starts it. The target server needs
# NO build tools — Open ProPanel ships as a single self-contained binary.
#
# Environment overrides:
#   PROPANEL_VERSION   release tag to install (default: latest)
#   PROPANEL_REPO      GitHub owner/repo (default: jaskaranvirk1/openpropanel)
#   PROPANEL_BASE_URL  download binaries from this base URL instead of GitHub
#   PANEL_PORT         panel port (default: 2087)

set -euo pipefail

REPO="${PROPANEL_REPO:-jaskaranvirk1/openpropanel}"
VERSION="${PROPANEL_VERSION:-latest}"
BASE_URL="${PROPANEL_BASE_URL:-}"
PANEL_PORT="${PANEL_PORT:-2087}"
BIN_DEST="/usr/local/bin/openpropanel"
CONF_DIR="/etc/openpropanel"
UNIT_DEST="/etc/systemd/system/openpropanel.service"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

log()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m warning:\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m error:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "please run as root (pipe to 'sudo bash')"

# --- detect architecture -----------------------------------------------------
case "$(uname -m)" in
    x86_64|amd64)  ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) die "unsupported architecture: $(uname -m)" ;;
esac

# --- detect package manager (RHEL family expected) ---------------------------
if command -v dnf >/dev/null 2>&1; then
    PKG="dnf"
elif command -v yum >/dev/null 2>&1; then
    PKG="yum"
else
    warn "no dnf/yum found — Open ProPanel targets AlmaLinux/RHEL. Installing the binary"
    warn "only; you must install httpd, php-fpm and certbot yourself."
    PKG=""
fi

ASSET="openpropanel_linux_${ARCH}.tar.gz"
if [ -n "$BASE_URL" ]; then
    URL="${BASE_URL%/}/${ASSET}"
elif [ "$VERSION" = "latest" ]; then
    URL="https://github.com/${REPO}/releases/latest/download/${ASSET}"
else
    URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}"
fi

# --- download + unpack -------------------------------------------------------
log "Downloading Open ProPanel (${ARCH}) from ${URL}"
if ! curl -fsSL "$URL" -o "$TMP/openpropanel.tar.gz"; then
    die "download failed — check PROPANEL_VERSION/PROPANEL_REPO or the release exists"
fi
tar -xzf "$TMP/openpropanel.tar.gz" -C "$TMP"
[ -f "$TMP/openpropanel" ] || die "archive did not contain the openpropanel binary"

# --- runtime dependencies ----------------------------------------------------
if [ -n "$PKG" ]; then
    log "Installing runtime dependencies"
    $PKG install -y epel-release >/dev/null 2>&1 || true
    $PKG install -y httpd mod_ssl php php-fpm certbot firewalld
    systemctl enable --now php-fpm  >/dev/null 2>&1 || true
    systemctl enable --now httpd    >/dev/null 2>&1 || true
    systemctl enable --now firewalld >/dev/null 2>&1 || true
fi

# --- install binary + unit ---------------------------------------------------
log "Installing binary -> ${BIN_DEST}"
install -m 0755 "$TMP/openpropanel" "$BIN_DEST"

if [ -f "$TMP/openpropanel.service" ]; then
    install -m 0644 "$TMP/openpropanel.service" "$UNIT_DEST"
else
    cat > "$UNIT_DEST" <<UNIT
[Unit]
Description=Open ProPanel server control panel
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=${BIN_DEST} --config ${CONF_DIR}/config.json
Restart=on-failure
RestartSec=5
StateDirectory=openpropanel
StateDirectoryMode=0700
[Install]
WantedBy=multi-user.target
UNIT
fi

mkdir -p "$CONF_DIR"
if [ ! -f "$CONF_DIR/config.json" ]; then
    printf '{\n  "listen_addr": ":%s",\n  "acme_email": ""\n}\n' "$PANEL_PORT" > "$CONF_DIR/config.json"
    chmod 600 "$CONF_DIR/config.json"
fi

# --- firewall + SELinux ------------------------------------------------------
if command -v firewall-cmd >/dev/null 2>&1; then
    log "Opening firewall (http, https, ${PANEL_PORT})"
    firewall-cmd --add-service=http  --permanent >/dev/null 2>&1 || true
    firewall-cmd --add-service=https --permanent >/dev/null 2>&1 || true
    firewall-cmd --add-port="${PANEL_PORT}/tcp" --permanent >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
fi
if command -v restorecon >/dev/null 2>&1; then
    restorecon -R /var/www >/dev/null 2>&1 || true
fi

# --- start -------------------------------------------------------------------
log "Starting Open ProPanel"
systemctl daemon-reload
systemctl enable --now openpropanel

# Wait for first-run to generate the random admin credentials, then read them.
CREDS="/var/lib/openpropanel/initial-admin-password.txt"
for _ in $(seq 1 20); do [ -s "$CREDS" ] && break; sleep 0.5; done
USERNAME="$(awk -F': ' '/^username:/{print $2}' "$CREDS" 2>/dev/null)"
PASSWORD="$(awk -F': ' '/^password:/{print $2}' "$CREDS" 2>/dev/null)"

LAN_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
PUB_IP="$(curl -fsS --max-time 4 https://api.ipify.org 2>/dev/null || curl -fsS --max-time 4 https://ifconfig.me 2>/dev/null || true)"
VER="$("$BIN_DEST" --version 2>/dev/null | awk '{print $2}')"

echo
echo "=================================================================="
echo " Open ProPanel ${VER} installed successfully!"
echo "=================================================================="
[ -n "$PUB_IP" ] && echo " Panel URL (external): https://${PUB_IP}:${PANEL_PORT}"
[ -n "$LAN_IP" ] && echo " Panel URL (internal): https://${LAN_IP}:${PANEL_PORT}"
echo " Username:             ${USERNAME:-admin}"
echo " Password:             ${PASSWORD:-see: journalctl -u openpropanel}"
echo "=================================================================="
echo " * HTTPS uses a self-signed cert — accept the browser warning (or get a"
echo "   trusted one under Settings -> Panel HTTPS)."
echo " * You can change the username/password after logging in."
echo " * Keep port ${PANEL_PORT} firewalled to trusted IPs (it runs as root)."
echo "=================================================================="
echo
