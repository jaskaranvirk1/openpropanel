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
#   PANEL_PORT         panel port (default: 9443)
#   PROPANEL_OPEN      panel-port firewall exposure: all (default) | ip | none

set -euo pipefail

REPO="${PROPANEL_REPO:-jaskaranvirk1/openpropanel}"
VERSION="${PROPANEL_VERSION:-latest}"
BASE_URL="${PROPANEL_BASE_URL:-}"
PANEL_PORT="${PANEL_PORT:-9443}"
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
    # MariaDB is installed by default so the Databases + phpMyAdmin features work
    # out of the box; set PROPANEL_NO_DB=1 to skip it (add it later anytime).
    REQUIRED="httpd mod_ssl php-fpm certbot firewalld"
    [ "${PROPANEL_NO_DB:-0}" = "1" ] || REQUIRED="$REQUIRED mariadb-server"
    missing=""
    for pkg in $REQUIRED; do
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
    if [ "${PROPANEL_NO_DB:-0}" != "1" ]; then
        systemctl enable --now mariadb >/dev/null 2>&1 || warn "MariaDB installed but not started — check: systemctl status mariadb"
    fi
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
CONF="$CONF_DIR/config.json"
if [ ! -f "$CONF" ]; then
    # Fresh install: write config with the chosen port.
    printf '{\n  "listen_addr": ":%s",\n  "acme_email": ""\n}\n' "$PANEL_PORT" > "$CONF"
    chmod 600 "$CONF"
else
    # Upgrade: reconcile so the firewall + banner ALWAYS match the port the panel
    # actually listens on (this is what caused the listening-vs-firewall mismatch).
    # Migrate the retired 2087 default to 9443, then adopt whatever port is in the
    # config as the effective PANEL_PORT.
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

# --- firewall + SELinux ------------------------------------------------------
# Open http/https (for hosted sites + Let's Encrypt) and, by default, the panel
# port so it is reachable from anywhere. Override with PROPANEL_OPEN=ip (only
# your SSH client IP) or PROPANEL_OPEN=none (closed; reach it via an SSH tunnel).
if command -v firewall-cmd >/dev/null 2>&1; then
    log "Configuring firewall"
    # Named firewalld service so the port can also be managed with:
    #   firewall-cmd --add-service=openpropanel
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
    # PROPANEL_OPEN: all (default) opens the panel port to the internet so it is
    # reachable from anywhere; ip restricts it to your SSH client IP; none keeps
    # it closed (reach it via an SSH tunnel).
    case "${PROPANEL_OPEN:-all}" in
        none|closed)
            log "Panel port ${PANEL_PORT} left CLOSED (PROPANEL_OPEN=none) — reach it via an SSH tunnel"
            ;;
        ip|ssh|ssh-ip)
            ipsrc="$(echo "${SSH_CONNECTION:-}" | awk '{print $1}')"
            [ -z "$ipsrc" ] && ipsrc="$(echo "${SSH_CLIENT:-}" | awk '{print $1}')"
            if [ -n "$ipsrc" ]; then
                log "Opening panel port ${PANEL_PORT} to your IP only (${ipsrc})"
                firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=${ipsrc}/32 port port=${PANEL_PORT} protocol=tcp accept" >/dev/null 2>&1 || true
            else
                warn "PROPANEL_OPEN=ip but couldn't detect your SSH client IP (sudo may strip it) — leaving ${PANEL_PORT} CLOSED; open it manually or re-run as root without sudo"
            fi
            ;;
        *)
            log "Opening panel port ${PANEL_PORT} to the internet (reachable from anywhere)"
            firewall-cmd --add-port="${PANEL_PORT}/tcp" --permanent >/dev/null 2>&1 || true
            ;;
    esac
    firewall-cmd --reload >/dev/null 2>&1 || true
fi
if command -v restorecon >/dev/null 2>&1; then
    restorecon -R /var/www >/dev/null 2>&1 || true
fi

# --- start -------------------------------------------------------------------
log "Starting Open ProPanel"
systemctl daemon-reload
systemctl enable openpropanel >/dev/null 2>&1 || true
# 'restart' (not just enable --now) so a re-run/upgrade actually applies the new
# binary and any migrated config, instead of leaving the old process running.
systemctl restart openpropanel

# Wait for first-run to generate the random admin credentials, then read them.
# The reads are guarded with '|| true' so a slow/failed first boot (creds file
# not yet written) can never abort the installer under 'set -e' — the banner and
# its ${VAR:-fallback} messages must always print.
CREDS="/var/lib/openpropanel/initial-admin-password.txt"
for _ in $(seq 1 30); do [ -s "$CREDS" ] && break; sleep 0.5; done
USERNAME="$(awk -F': ' '/^username:/{print $2}' "$CREDS" 2>/dev/null || true)"
PASSWORD="$(awk -F': ' '/^password:/{print $2}' "$CREDS" 2>/dev/null || true)"
PUB_IP="$(curl -fsS --max-time 4 https://api.ipify.org 2>/dev/null || curl -fsS --max-time 4 https://ifconfig.me 2>/dev/null || true)"
VER="$("$BIN_DEST" --version 2>/dev/null | awk '{print $2}' || true)"

# Preflight health check so any environment problem is visible right away.
echo
"$BIN_DEST" doctor 2>/dev/null || true

echo
echo "=================================================================="
echo "  Open ProPanel ${VER} is installed and running."
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
echo "  * HTTPS is self-signed by default — your browser will warn once;"
echo "    click through to continue. For a trusted padlock: point a domain"
echo "    here and use Settings -> Panel HTTPS, or drop panel.crt + panel.key"
echo "    into ${CONF_DIR}/certs/."
echo "  * The panel port ${PANEL_PORT} is open to the internet. To restrict it to"
echo "    your IP later:  firewall-cmd --permanent --remove-port=${PANEL_PORT}/tcp &&"
echo "    firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=YOUR.IP/32 port port=${PANEL_PORT} protocol=tcp accept' && firewall-cmd --reload"
echo "=================================================================="
echo
