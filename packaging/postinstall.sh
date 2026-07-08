#!/bin/sh
# nfpm post-install scriptlet for the Open ProPanel .rpm.
set -e

systemctl daemon-reload 2>/dev/null || true

if [ ! -f /etc/openpropanel/config.json ]; then
    mkdir -p /etc/openpropanel
    printf '{\n  "listen_addr": ":2087",\n  "acme_email": ""\n}\n' > /etc/openpropanel/config.json
    chmod 600 /etc/openpropanel/config.json
fi

echo "Open ProPanel installed. Start it with:  systemctl enable --now openpropanel"
echo "First-run admin password:  journalctl -u openpropanel  (or /var/lib/openpropanel/initial-admin-password.txt)"
