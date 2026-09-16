#!/usr/bin/env bash
# r503d-alert.sh — best-effort desktop alert, run as root by r503d-alert.service.
# Never fails the calling unit: always exits 0.
set -u
PATH=/usr/bin:/bin:/usr/local/bin

MSG="${1:-r503d fingerprint daemon has failed — auth has fallen back to password}"

systemd-cat -t r503d-alert -p alert <<<"$MSG" || logger -t r503d-alert -p auth.alert -- "$MSG" || true

sent=0
while IFS= read -r line; do
    [ -z "$line" ] && continue
    session_id=$(awk '{print $1}' <<<"$line")
    session_type=$(loginctl show-session "$session_id" -p Type --value 2>/dev/null || true)
    session_state=$(loginctl show-session "$session_id" -p State --value 2>/dev/null || true)
    session_uid=$(loginctl show-session "$session_id" -p User --value 2>/dev/null || true)

    case "$session_type" in
        wayland|x11) ;;
        *) continue ;;
    esac
    [ "$session_state" = "active" ] || continue
    [ -n "$session_uid" ] || continue

    session_user=$(getent passwd "$session_uid" | cut -d: -f1)
    [ -n "$session_user" ] || continue

    bus_addr="unix:path=/run/user/${session_uid}/bus"

    if runuser -u "$session_user" -- env DBUS_SESSION_BUS_ADDRESS="$bus_addr" \
        notify-send -u critical "Fingerprint reader down" "$MSG" 2>/dev/null; then
        sent=$((sent + 1))
    fi
done < <(loginctl list-sessions --no-legend 2>/dev/null)

if [ "$sent" -eq 0 ]; then
    systemd-cat -t r503d-alert -p notice <<<"r503d-alert: no active graphical session to notify" || true
fi

exit 0
