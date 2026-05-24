#!/usr/bin/env python3
"""Single-connection smoke test for r503d running on the SESSION bus.

Drives the full Claim -> ListEnrolledFingers -> VerifyStart -> wait for signals
-> VerifyStop -> Release flow against the daemon, the way pam_fprintd would.
"""
import sys
import time

import dbus
import dbus.mainloop.glib
from gi.repository import GLib

BUS_NAME = "net.reactivated.Fprint"
MANAGER_PATH = "/net/reactivated/Fprint/Manager"
DEVICE_PATH = "/net/reactivated/Fprint/Device/0"
DEVICE_IFACE = "net.reactivated.Fprint.Device"


def main(verify_finger: str = "right-thumb") -> int:
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SessionBus()

    manager = bus.get_object(BUS_NAME, MANAGER_PATH)
    default_path = manager.GetDefaultDevice(
        dbus_interface="net.reactivated.Fprint.Manager"
    )
    print(f"[manager] default device = {default_path}")

    device_obj = bus.get_object(BUS_NAME, default_path)
    device = dbus.Interface(device_obj, dbus_interface=DEVICE_IFACE)

    loop = GLib.MainLoop()
    result: dict = {}

    def on_verify_finger_selected(name):
        print(f"[signal] VerifyFingerSelected: {name}")
        result["selected"] = str(name)

    def on_verify_status(status, done):
        print(f"[signal] VerifyStatus: {status} done={done}")
        result.setdefault("statuses", []).append((str(status), bool(done)))
        if done:
            GLib.idle_add(loop.quit)

    device_obj.connect_to_signal(
        "VerifyFingerSelected", on_verify_finger_selected, dbus_interface=DEVICE_IFACE
    )
    device_obj.connect_to_signal(
        "VerifyStatus", on_verify_status, dbus_interface=DEVICE_IFACE
    )

    print("[client] Claim('mat')")
    device.Claim("mat")

    # Always tear down — otherwise an exception mid-flow leaves the daemon
    # holding our claim and the next run fails with AlreadyInUse.
    try:
        print("[client] ListEnrolledFingers('mat')")
        fingers = device.ListEnrolledFingers("mat")
        print(f"           => {[str(f) for f in fingers]}")

        print(f"[client] VerifyStart('{verify_finger}')")
        print("=" * 60)
        print(f">>> PLACE YOUR {verify_finger.upper()} ON THE R503 NOW <<<")
        print("=" * 60)
        device.VerifyStart(verify_finger)

        # 30s safety timeout to break the loop even if sensor keeps retrying.
        GLib.timeout_add_seconds(30, lambda: (loop.quit(), False)[1])
        loop.run()

        try:
            print("[client] VerifyStop()")
            device.VerifyStop()
        except dbus.DBusException as e:
            print(f"[client] VerifyStop ignored: {e.get_dbus_name()}")
    finally:
        try:
            print("[client] Release()")
            device.Release()
        except dbus.DBusException as e:
            print(f"[client] Release ignored: {e.get_dbus_name()}")

    print("=" * 60)
    print(f"selected_finger = {result.get('selected')!r}")
    print(f"status_sequence = {result.get('statuses', [])}")
    final = result.get("statuses", [])
    if final and final[-1][0] == "verify-match":
        print("RESULT: ✅ verify-match")
        return 0
    elif final and final[-1][0] == "verify-no-match":
        print("RESULT: ❌ verify-no-match")
        return 1
    else:
        print("RESULT: ⚠  inconclusive (no terminal status)")
        return 2


if __name__ == "__main__":
    finger = sys.argv[1] if len(sys.argv) > 1 else "right-thumb"
    try:
        sys.exit(main(finger))
    except dbus.DBusException as e:
        # Daemon rejected the call — print the error nicely instead of dumping
        # a Python traceback. Common cases: InvalidFingername, NoEnrolledPrints,
        # AlreadyInUse.
        print(f"\nRESULT: ✗ {e.get_dbus_name()}: {e.get_dbus_message()}",
              file=sys.stderr)
        sys.exit(3)
