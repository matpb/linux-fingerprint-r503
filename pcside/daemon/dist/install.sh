#!/usr/bin/env bash
# install.sh — one-shot installer for r503d.
#
# Run with: sudo bash dist/install.sh
#
# Replaces fprintd on this system with r503d. Reversible — see uninstall.sh.
# Idempotent — safe to re-run after a rebuild.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "must be run as root: sudo bash $0" >&2
    exit 1
fi

DIST_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$(cd -- "$DIST_DIR/.." && pwd)"
BINARY="$BUILD_DIR/target/release/r503d"

if [[ ! -x "$BINARY" ]]; then
    echo "missing release binary at $BINARY — run 'cargo build --release' first" >&2
    exit 1
fi

echo ">>> [1/9] installing r503d binary -> /usr/local/bin/r503d"
install -m 0755 -o root -g root "$BINARY" /usr/local/bin/r503d

echo ">>> [2/9] creating /var/lib/r503d state dir"
install -d -m 0700 -o root -g root /var/lib/r503d

# Note: this installer does NOT seed /var/lib/r503d/users.json from any
# session-bus testing state. Previously it copied
# ~$SUDO_USER/.local/state/r503d/users.json over when no system file existed,
# which is an unvalidated promotion of dev mappings to system truth (audit
# §P1-5). If you genuinely want to carry session-mode enrollments forward,
# `cp` the file explicitly and double-check the usernames against
# `getpwnam` before re-pairing.

echo ">>> [3/9] installing udev rule -> /etc/udev/rules.d/70-r503.rules"
install -m 0644 -o root -g root "$DIST_DIR/70-r503.rules" /etc/udev/rules.d/70-r503.rules
udevadm control --reload
udevadm trigger --subsystem-match=tty
sleep 1
if [[ -L /dev/r503 ]]; then
    echo "    /dev/r503 -> $(readlink -f /dev/r503)"
else
    echo "    (no /dev/r503 yet — no Arduino plugged in, or VID/PID not covered by the rule;"
    echo "     daemon will fall back to scanning /dev/ttyACM* and /dev/ttyUSB*)"
fi

echo ">>> [4/9] installing systemd unit -> /etc/systemd/system/r503d.service"
install -m 0644 -o root -g root "$DIST_DIR/r503d.service" /etc/systemd/system/r503d.service

echo ">>> [5/9] overriding D-Bus autolaunch -> /usr/local/share/dbus-1/system-services/"
install -d -m 0755 /usr/local/share/dbus-1/system-services
install -m 0644 -o root -g root "$DIST_DIR/net.reactivated.Fprint.service" \
    /usr/local/share/dbus-1/system-services/net.reactivated.Fprint.service

echo ">>> [6/10] installing polkit policy -> /usr/share/polkit-1/actions/"
install -d -m 0755 /usr/share/polkit-1/actions
install -m 0644 -o root -g root "$DIST_DIR/net.reactivated.fprint.device.r503d.policy" \
    /usr/share/polkit-1/actions/net.reactivated.fprint.device.r503d.policy

echo ">>> [7/10] installing D-Bus system bus policy -> /etc/dbus-1/system.d/"
install -m 0644 -o root -g root "$DIST_DIR/net.reactivated.Fprint.conf" \
    /etc/dbus-1/system.d/net.reactivated.Fprint.conf
# Tell the bus to reread its system policies. dbus-broker supports reload;
# fall through to a full restart for old dbus-daemon hosts or if reload
# isn't supported.
systemctl reload dbus-broker.service 2>/dev/null \
    || systemctl reload dbus.service 2>/dev/null \
    || systemctl restart dbus-broker.service 2>/dev/null \
    || systemctl restart dbus.service

echo ">>> [8/10] systemctl daemon-reload"
systemctl daemon-reload

echo ">>> [9/10] stopping + masking fprintd.service"
systemctl stop fprintd.service 2>/dev/null || true
systemctl mask fprintd.service

echo ">>> [10/10] enabling + starting r503d.service"
systemctl enable r503d.service
systemctl restart r503d.service

sleep 2
echo
echo "===== r503d.service status ====="
systemctl status r503d.service --no-pager -l | head -20 || true
echo
echo "===== verifying bus ownership ====="
busctl --system list 2>/dev/null | grep -i fprint || echo "(no fprint name on system bus — daemon may have failed to claim it)"
echo
echo "DONE. To test: fprintd-list mat   (then) fprintd-verify mat"
echo "To revert: sudo bash $DIST_DIR/uninstall.sh"
