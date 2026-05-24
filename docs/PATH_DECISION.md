# Path Decision: libfprint integration for R503-over-USB-serial

**Date:** 2026-05-24
**Status:** Recommendation made; awaiting Mat's sign-off before implementing
**Spike inputs:** libfprint upstream git tip (cloned to `/tmp/libfprint`), installed `libfprint-1.94.7` + `fprintd-1.94.5` + `fprintd-pam-1.94.5` on Fedora 44

## TL;DR — Recommendation: **Path C (Python fprintd-replacement daemon)**

C is ~3× less work than A or B, ships zero custom C, doesn't require maintaining a forked system package, and reuses the working `r503ctl.py`. It costs us libfprint compatibility (other libfprint frontends won't see our device) — but the only frontends that matter on Mat's box (`fprintd-enroll`, `fprintd-verify`, `pam_fprintd`) go through fprintd's D-Bus surface, which we can fully replace.

## The three paths

### Path A — libfprint serial driver via `FP_DEVICE_TYPE_UDEV`

libfprint *does* have a non-USB transport (`FP_DEVICE_TYPE_UDEV`), used by `elanspi.c` for embedded SPI/HID sensors. The probe walks udev's `spidev` and `hidraw` subsystems and hands the matched driver a `/dev/...` path via `fpi_device_get_udev_data()`.

**Blocker:** `FpiDeviceUdevSubtypeFlags` only supports `SPIDEV` and `HIDRAW` (`libfprint/fpi-device.h:33-37`). There is **no `TTY` subtype**. To match `/dev/ttyACM*` we would have to patch core libfprint:

1. Add `FPI_DEVICE_UDEV_SUBTYPE_TTY` to the enum.
2. Add a third `g_udev_client_query_by_subsystem(udev_client, "tty")` block in `fp-context.c:471-560`, with parent-USB-attribute matching (since CDC-ACM devices' parent is a USB interface with our Arduino's VID:PID).
3. Add `fpi-udev-data-tty` property to `FpUdevDevice`.
4. Write `libfprint/drivers/r503.c` (~400 LOC C, GLib/GObject, async SSM state machines).
5. Build a custom Fedora RPM that replaces system `libfprint`, OR upstream the patches (slow — libfprint releases every ~6 months).
6. Re-patch on every libfprint update.

**Estimate:** 15–25 hours including the C learning curve for libfprint's SSM idioms. Ongoing maintenance burden every libfprint release.

### Path B — libfprint USB driver via `libgusb` matching the Arduino's VID:PID

Skip the tty layer entirely. The Arduino Uno R3 has VID:PID `2341:0043` — a stable, unique USB ID we could register a `FP_DEVICE_TYPE_USB` driver against. libfprint's USB transport gives us libgusb bulk endpoints, which is essentially raw access to the CDC-ACM bulk IN/OUT pipes. We can speak the same ASCII protocol over those endpoints (CDC-ACM is just bulk transfers with line-coding control on the side).

**Blockers:**
- The kernel's `cdc-acm` driver claims the interface as soon as the Uno is plugged in. libgusb's `claim_interface()` will fail. We'd need a udev rule that detaches `cdc-acm` for this specific VID:PID — possible but means the Arduino can no longer be used for serial debugging while plugged in (a problem when iterating on firmware).
- Same C complexity as Path A (FpDeviceClass, SSM, GLib) — minus the upstream patch.
- Still requires maintaining a fork of libfprint, since the driver must compile into `libfprint-2.so`.

**Estimate:** 12–20 hours. Slightly less than A but inherits the `cdc-acm` fight, which is more fragile day-to-day.

### Path C — Python daemon replacing fprintd

fprintd is a D-Bus service owning the well-known name `net.reactivated.Fprint`, exposing two interfaces (`Manager`, `Device`) consumed by `pam_fprintd.so` and the `fprintd-{enroll,verify,list,delete}` CLI. The system D-Bus policy (`/usr/share/dbus-1/system.d/net.reactivated.Fprint.conf`) only requires root to own the name and lets anyone call Manager/Device methods.

Replace fprintd with a Python daemon that:
1. Stops + masks `fprintd.service`.
2. Owns `net.reactivated.Fprint` (via `dbus-next` or `pydbus`, run as root).
3. Implements the Manager + Device surface — small, well-documented (~10 methods, ~5 signals).
4. Wraps `r503ctl.py` for the actual sensor work.
5. Persists per-user → sensor-slot mappings in a small file under `/var/lib/r503d/`. The R503 already does enrollment *and* matching on-sensor, so libfprint's image-processing pipeline is irrelevant; our "template" can be an opaque `{"slot": N}` blob.

**Blockers:** none structural. Two ergonomic risks:
- pam_fprintd may make small assumptions about the `EnrollStatus` signal sequence we'd have to reverse-engineer empirically. Mitigation: run fprintd in debug mode first (the drop-in at `/etc/systemd/system/fprintd.service.d/debug.conf` is already there) against the virtual driver, capture the conversation, mirror it.
- The Polkit policy fprintd ships affects whether unprivileged users can enroll. We inherit or replace.

**Estimate:** 4–8 hours to MVP (`fprintd-verify` works against our daemon), +2–4 hours to wire up `pam_fprintd` + KDE Plasma screen lock + SDDM.

## Decision matrix

| Criterion              | A (libfprint serial) | B (libfprint USB)  | C (Python daemon)   |
| ---------------------- | -------------------- | ------------------ | ------------------- |
| Reuses `r503ctl.py`    | No (re-port to C)    | No (re-port to C)  | **Yes**             |
| Language               | C + GLib + meson     | C + GLib + meson   | **Python**          |
| Touches system libs    | Yes — fork libfprint | Yes — fork libfprint | **No**            |
| Fights `cdc-acm`       | No                   | Yes (udev evict)   | **No**              |
| Upstream-friendly      | Yes (good patch)     | Marginal           | N/A — orthogonal    |
| Maint. burden          | High (every release) | High (every release) | **Low**           |
| Effort to MVP          | 15–25 h              | 12–20 h            | **4–8 h**           |
| Other libfprint apps see device | Yes         | Yes                | No (none on Mat's box) |

## Rationale for picking C

1. **Asymmetric effort.** C captures 95% of the user-visible benefit (login + lock + sudo with the finger) at 30% of the cost of A or B.
2. **The R503 does matching on-sensor.** libfprint's value-add is its image processing + matcher. We don't need either — the sensor returns `OK match=<slot> confidence=<n>` over ASCII. fprintd becomes pure D-Bus orchestration, which is what Python is good at.
3. **No fork, no rebase, no rebuild.** Path A and B require shipping a patched `libfprint-2.so` to Mat's system and reapplying patches every Fedora libfprint update (3-4× per year). Path C is a normal systemd service.
4. **Iteration speed.** Mat already has `r503ctl.py` working. Adding D-Bus on top is incremental; rewriting it in C as a libfprint driver is starting over.
5. **Fallback is preserved.** If Path C hits a wall with pam_fprintd compatibility, we can still pivot to A or B with everything we've learned. The reverse isn't true.

## What we lose with C

- Other libfprint consumers (GNOME Settings' fingerprint UI, KDE's `kcm_fingerprint`, etc.) won't see our device. On Mat's box this is a non-issue — KDE Plasma 6's fingerprint settings call into fprintd's D-Bus surface, which we own. Same for any GNOME tool. The *only* thing we'd miss is `fprintd-list` style tooling that introspects libfprint directly without going through fprintd, and that's vanishingly rare.
- Sharing the driver upstream is harder. But the R503-on-Arduino setup is so niche that upstream adoption was never realistic anyway — most users buying a Grow R503 would integrate it differently (Raspberry Pi GPIO, ESPHome, etc.).

## Implementation outline if Path C is approved

1. **Init the repo as git** (`git init && git add . && git commit -m "initial bench prototype"`) — currently uncommitted.
2. **Spike pam_fprintd's D-Bus conversation** — enable fprintd debug logging, run `fprintd-verify` against the libfprint virtual device (`FP_VIRTUAL_DEVICE=/tmp/sock`), capture the full method-call sequence. ~30 min.
3. **Scaffold `pcside/daemon/r503d.py`** — `dbus-next` (async, Pythonic, supports system bus, mature). Define `net.reactivated.Fprint.Manager` + `Device` skeletons. ~1 h.
4. **Wire `r503ctl.py` library API as the backend** — open `/dev/ttyACM0` once at daemon start, expose `enroll(slot)`, `verify()`, `delete(slot)`, `info()` to the D-Bus handlers. ~1 h.
5. **Persist per-user slot mapping** — `/var/lib/r503d/users.json` (`{"mat": [{"finger": "right-thumb", "slot": 0}, ...]}`). ~30 min.
6. **systemd unit + D-Bus service file** — `r503d.service` (replaces `fprintd.service`), `/usr/share/dbus-1/system-services/net.reactivated.Fprint.service` repointed. Stop + mask system fprintd. ~30 min.
7. **Validate `fprintd-enroll mat` and `fprintd-verify`** end-to-end. ~1 h debug.
8. **PAM wiring** via `authselect` (Fedora's PAM stack manager) — `authselect select sssd with-fingerprint`, or hand-edit `/etc/pam.d/sudo` etc. ~30 min.
9. **KDE screen lock test** — `loginctl lock-session`, place finger, confirm unlock. ~15 min.
10. **SDDM login test** — log out, place finger at SDDM, confirm login. ~15 min.

Total: **5–8 hours of focused work**, mostly Python + systemd + PAM, very little novel debugging.

## Open questions for Mat

1. **OK with replacing the system fprintd entirely** (stop + mask the unit, hijack the bus name), or do you want to keep fprintd around for a future "real" USB fingerprint reader? — Recommendation: replace. We can always re-enable fprintd later by `systemctl unmask fprintd && systemctl restart dbus`.
2. **OK with storing per-user → sensor-slot mapping in a JSON file under `/var/lib/r503d/`**, or do you want this wired into something more durable (sqlite, the user's home dir)? — Recommendation: JSON. The sensor is the source of truth; this file is a thin label.
3. **Confidence threshold** — accept any `confidence >= 50`, or be stricter? — Recommendation: `>= 50` to start, expose as a config knob in `/etc/r503d.conf`.
