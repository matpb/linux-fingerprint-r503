#!/usr/bin/env bash
# uninstall.sh — revert install.sh and put upstream fprintd back.
#
# Run with: sudo bash dist/uninstall.sh

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "must be run as root: sudo bash $0" >&2
    exit 1
fi

echo ">>> stopping + disabling r503d.service"
systemctl stop r503d.service 2>/dev/null || true
systemctl disable r503d.service 2>/dev/null || true

echo ">>> removing r503d.service unit + binary + D-Bus override"
rm -f /etc/systemd/system/r503d.service
rm -f /usr/local/bin/r503d
rm -f /usr/local/share/dbus-1/system-services/net.reactivated.Fprint.service

echo ">>> systemctl daemon-reload"
systemctl daemon-reload

echo ">>> unmasking fprintd.service"
systemctl unmask fprintd.service

echo ">>> restarting dbus-broker so it picks up the original service file"
systemctl restart dbus-broker.service 2>/dev/null || systemctl restart dbus.service

echo
echo "DONE. /var/lib/r503d/users.json preserved (rm manually if you want a clean slate)."
