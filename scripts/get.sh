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
    case "$BASE_URL" in
        https://*) ;;
        *) die "PROPANEL_BASE_URL must be https://" ;;
    esac
    URL="${BASE_URL%/}/${ASSET}"
    SUMS_URL="${BASE_URL%/}/checksums.txt"
elif [ "$VERSION" = "latest" ]; then
    URL="https://github.com/${REPO}/releases/latest/download/${ASSET}"
    SUMS_URL="https://github.com/${REPO}/releases/latest/download/checksums.txt"
else
    URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}"
    SUMS_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"
fi

# --- download + verify + unpack ---------------------------------------------
log "Downloading Open ProPanel (${ARCH}) from ${URL}"
if ! curl -fsSL "$URL" -o "$TMP/${ASSET}"; then
    die "download failed — check PROPANEL_VERSION/PROPANEL_REPO or that the release exists"
fi
# Verify the tarball against the release checksums.txt before trusting it.
if curl -fsSL "$SUMS_URL" -o "$TMP/checksums.txt"; then
    if command -v sha256sum >/dev/null 2>&1; then
        ( cd "$TMP" && grep " ${ASSET}\$" checksums.txt | sha256sum -c - >/dev/null 2>&1 ) \
            || die "checksum verification FAILED for ${ASSET} — refusing to install"
        log "Checksum verified"
    fi
else
    die "could not fetch checksums.txt to verify the download — refusing to install"
fi
tar -xzf "$TMP/${ASSET}" -C "$TMP"
[ -f "$TMP/openpropanel" ] || die "archive did not contain the openpropanel binary"

# --- runtime dependencies (install ONLY what is missing) ---------------------
# Check each package with rpm first and install only the ones not already
# present. This avoids aborting when a package is already installed but hidden
# by an exclude= rule (e.g. PHP provided via the Remi module) and never
# reinstalls something the server already has.
if [ -n "$PKG" ]; then
    missing=""
    for pkg in httpd mod_ssl php-fpm certbot firewalld; do
        rpm -q "$pkg" >/dev/null 2>&1 || missing="$missing $pkg"
    done
    missing="$(echo $missing)" # trim
    if [ -n "$missing" ]; then
        log "Installing missing runtime dependencies:$missing"
        # certbot lives in EPEL; pull that in only if we actually need packages.
        case " $missing " in *" certbot "*) $PKG install -y epel-release >/dev/null 2>&1 || true ;; esac
        $PKG install -y $missing || warn "could not install:$missing (install manually if a feature needs it)"
    else
        log "All runtime dependencies already present — skipping install"
    fi
    for svc in php-fpm httpd firewalld; do
        systemctl enable --now "$svc" >/dev/null 2>&1 || true
    done
fi

# --- install binary + unit ---------------------------------------------------
log "Installing binary -> ${BIN_DEST}"
install -m 0755 "$TMP/openpropanel" "$BIN_DEST"

if [ -f "$TMP/openpropanel.service" ]; then
    install -m 0644 "$TMP/openpropanel.service" "$UNIT_DEST"
elif curl -fsSL "https://raw.githubusercontent.com/${REPO}/main/packaging/openpropanel.service" -o "$UNIT_DEST" 2>/dev/null; then
    # The prebuilt archive didn't include the unit — fetch the hardened one
    # from the repo rather than falling back to a minimal, unhardened unit.
    chmod 0644 "$UNIT_DEST"
    log "Installed hardened systemd unit from the repository"
else
    warn "using a minimal systemd unit (could not fetch the hardened one)"
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
# Open http/https (needed for hosted sites + Let's Encrypt) but DO NOT expose the
# root-privileged panel port to the whole internet — the admin restricts it to
# their own IP (instructions printed at the end).
if command -v firewall-cmd >/dev/null 2>&1; then
    log "Opening firewall (http, https)"
    firewall-cmd --add-service=http  --permanent >/dev/null 2>&1 || true
    firewall-cmd --add-service=https --permanent >/dev/null 2>&1 || true
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
echo " * Opened by IP, the panel uses a self-signed cert (Let's Encrypt can't"
echo "   issue for bare IPs) — accept the browser warning. Point a domain at it"
echo "   and get a free Let's Encrypt cert under Settings -> Panel HTTPS."
echo "   (Your hosted sites always get Let's Encrypt certificates.)"
echo " * You can change the username/password after logging in."
echo " * The panel port ${PANEL_PORT} is NOT open in the firewall (it runs as root)."
echo "   Open it only to YOUR IP:"
echo "     firewall-cmd --permanent --add-rich-rule='rule family=ipv4 \\"
echo "       source address=YOUR.IP/32 port port=${PANEL_PORT} protocol=tcp accept'"
echo "     firewall-cmd --reload"
echo "=================================================================="
echo
