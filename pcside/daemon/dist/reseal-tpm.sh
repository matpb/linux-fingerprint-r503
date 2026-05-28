#!/usr/bin/env bash
# reseal-tpm.sh — recovery ceremony for SPEC §13.12 TPM seal failures.
#
# Run with: sudo bash dist/reseal-tpm.sh
#
# When the daemon refuses to start with "TPM-sealed key present but could
# not be unsealed", the Secure Boot policy (PCR7) baked into the seal at
# pairing time no longer matches the current boot state. The old MAC key is
# unrecoverable. Recovery:
#
#   1. Stop r503d.
#   2. Wipe the Nano EEPROM (firmware/r503fp_wipe/) so it forgets the lost key.
#   3. Re-upload the main firmware.
#   4. Re-pair with a fresh key, sealed to current PCR7.
#   5. Start r503d.
#
# Fingers stay enrolled — R503 templates live on the sensor's own flash,
# not on the Nano.

set -euo pipefail

# --pcrs <list>  optional PCR list (default 7). Passed through to
#                r503d --reseal-tpm. Use 7,11 to additionally bind UKI
#                (kernel+initrd) measurement, etc. SPEC §13.12.
PCRS=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --pcrs)
            PCRS="$2"
            shift 2
            ;;
        --pcrs=*)
            PCRS="${1#*=}"
            shift
            ;;
        -h|--help)
            sed -n '2,18p' "$0" | sed 's/^# *//'
            echo
            echo "Usage: sudo bash $0 [--pcrs <list>]"
            exit 0
            ;;
        *)
            echo "unknown arg: $1" >&2
            exit 1
            ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "must be run as root: sudo bash $0" >&2
    exit 1
fi

DIST_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$DIST_DIR/../.." && pwd)"
FW_DIR="$REPO_ROOT/firmware"

WIPE_SKETCH="$FW_DIR/r503fp_wipe"
MAIN_SKETCH="$FW_DIR/r503fp"
FQBN="${ARDUINO_FQBN:-arduino:avr:nano:cpu=atmega328}"
PORT="${R503_PORT:-/dev/r503}"

# arduino-cli is typically installed in the invoking user's $HOME/.local/bin,
# not on root's PATH. Try a couple of plausible locations before giving up.
find_arduino_cli() {
    if [[ -n "${ARDUINO_CLI:-}" && -x "$ARDUINO_CLI" ]]; then
        echo "$ARDUINO_CLI"; return
    fi
    if command -v arduino-cli >/dev/null 2>&1; then
        command -v arduino-cli; return
    fi
    if [[ -n "${SUDO_USER:-}" ]]; then
        local user_home
        user_home="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
        if [[ -x "$user_home/.local/bin/arduino-cli" ]]; then
            echo "$user_home/.local/bin/arduino-cli"; return
        fi
    fi
    return 1
}

ARDUINO_CLI_BIN="$(find_arduino_cli)" || {
    echo "ERROR: arduino-cli not found." >&2
    echo "Set ARDUINO_CLI=/full/path/to/arduino-cli and re-run." >&2
    exit 1
}

if [[ ! -d "$WIPE_SKETCH" ]]; then
    echo "ERROR: missing wipe sketch at $WIPE_SKETCH" >&2
    exit 1
fi
if [[ ! -d "$MAIN_SKETCH" ]]; then
    echo "ERROR: missing main firmware at $MAIN_SKETCH" >&2
    exit 1
fi

# If /dev/r503 isn't there (udev rule not yet installed, or VID/PID outside the
# rule), fall back to /dev/ttyACM0. The arduino-cli reflash needs a real path.
if [[ ! -e "$PORT" ]]; then
    if [[ -e /dev/ttyACM0 ]]; then
        echo "    /dev/r503 absent; using /dev/ttyACM0"
        PORT=/dev/ttyACM0
    else
        echo "ERROR: no Nano serial port found (tried $PORT and /dev/ttyACM0)" >&2
        exit 1
    fi
fi

echo ">>> [1/7] stopping r503d.service"
systemctl stop r503d.service 2>/dev/null || true

echo ">>> [2/7] uploading wipe sketch ($WIPE_SKETCH) to $PORT"
"$ARDUINO_CLI_BIN" compile --fqbn "$FQBN" "$WIPE_SKETCH"
"$ARDUINO_CLI_BIN" upload  --fqbn "$FQBN" --port "$PORT" "$WIPE_SKETCH"

# The wipe sketch zeroes EEPROM, then blinks the on-board LED to signal done.
# Give it a couple of seconds to finish before we reflash on top.
sleep 3

echo ">>> [3/7] re-uploading main firmware ($MAIN_SKETCH) to $PORT"
"$ARDUINO_CLI_BIN" compile --fqbn "$FQBN" "$MAIN_SKETCH"
"$ARDUINO_CLI_BIN" upload  --fqbn "$FQBN" --port "$PORT" "$MAIN_SKETCH"

# Main firmware reboots; wait for the boot banner to settle.
sleep 2

echo ">>> [4/7] creating allow-pair gate /etc/r503d/allow-pair"
install -d -m 0755 -o root -g root /etc/r503d
: > /etc/r503d/allow-pair
chmod 0644 /etc/r503d/allow-pair

if ! command -v r503d >/dev/null 2>&1; then
    echo "ERROR: r503d not on PATH; install it (sudo bash dist/install.sh) first" >&2
    exit 1
fi

if [[ -n "$PCRS" ]]; then
    echo ">>> [5/7] running r503d --reseal-tpm --seal-tpm-pcrs $PCRS"
    r503d --reseal-tpm --port "$PORT" --seal-tpm-pcrs "$PCRS"
else
    echo ">>> [5/7] running r503d --reseal-tpm (generates new key, seals to PCR7)"
    r503d --reseal-tpm --port "$PORT"
fi

echo ">>> [6/7] starting r503d.service"
systemctl start r503d.service

sleep 1
echo ">>> [7/7] status"
systemctl status r503d.service --no-pager -l | head -15 || true

echo
echo "DONE. Verify with: fprintd-verify $SUDO_USER"
echo "(Enrolled fingers were preserved — templates live on the R503 sensor flash, not the Nano.)"
