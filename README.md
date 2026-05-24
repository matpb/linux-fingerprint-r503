# linux-fingerprint-r503 — fingerprint login for Linux using a Grow R503 + Arduino

A from-parts USB fingerprint reader for Linux desktops. Total parts cost
under $15. Drop-in replacement for upstream `fprintd` — PAM, KDE Settings,
GNOME Settings, `fprintd-verify`, `sudo` with finger, screen-unlock with
finger all work.

```
   ┌──────────┐   UART    ┌─────────────┐   USB-CDC   ┌──────────────────┐
   │  Grow    │  57600 8N1│  Arduino    │  /dev/r503  │  r503d daemon    │
   │  R503    │◀─────────▶│  (firmware) │◀──────────▶│  net.reactivated │
   │  sensor  │  3.3V TTL │             │  ASCII      │  .Fprint on D-Bus│
   └──────────┘           └─────────────┘  protocol   └──────────────────┘
                                                              │
                                                              ▼
                                                       PAM, KDE, GNOME,
                                                       fprintd-verify, …
```

## Why

Hardware USB fingerprint readers for Linux are scarce, expensive, and the
ones that exist (Validity, Synaptics, etc.) are reverse-engineered through
unstable libfprint drivers that break with vendor firmware updates. The
Grow R503's protocol is **public**, the Arduino side is your own code,
and the libfprint compatibility layer is just D-Bus.

You also end up with a fingerprint reader you can read the source of, top
to bottom.

## Bill of materials

| Part | Notes | Approx cost |
|------|-------|------|
| Grow R503 capacitive fingerprint sensor | The round one with the RGB ring | ~$10 |
| Arduino Uno R3 / Nano / Mega / any ATmega328 board | Anything that runs SoftwareSerial | $5–$25 |
| 4–6 jumper wires | Dupont / breadboard | trivial |

That's it. **No level shifter, no voltage divider** — see [`SPEC.md` §3.1](SPEC.md)
for why (the R503's RX line is 5V-tolerant in practice; the datasheet lies).

## Wiring

```
R503             Arduino (Uno R3 / Nano / etc.)
----             ------------------------------
Red (VCC)        3V3
White (3.3VT)    3V3                  (touch-IC supply; shares rail with red)
Black (GND)      GND
Yellow (TXD)     D2  ── SoftwareSerial RX
Brown (RXD)      D3  ── SoftwareSerial TX   (direct — no divider!)
Blue (WAKEUP)    D4                          (optional; not used by firmware yet)
```

If your R503 ships with the JST-SH connector, snip a 6-pin JST-SH-to-Dupont
pigtail to break the wires out. Brown is sometimes green depending on the
seller — verify against the wire that goes into the RXD pin of the JST
header, not the colour.

## Build & install

Tested on Fedora 44 KDE; should work on any systemd-based distro with
`fprintd`, `pam_fprintd`, and Rust toolchain.

### 1. Flash the firmware

Open `firmware/r503fp/r503fp.ino` in the Arduino IDE and upload. Or with
`arduino-cli`:

```bash
arduino-cli compile --fqbn arduino:avr:uno firmware/r503fp/
arduino-cli upload  --fqbn arduino:avr:uno --port /dev/ttyACM0 firmware/r503fp/
```

The firmware uses `Adafruit_Fingerprint`. The IDE will offer to install it
on first compile.

### 2. Build the daemon

Requires Rust 1.95+.

```bash
cd pcside/daemon
cargo build --release
```

### 3. Install

```bash
sudo bash pcside/daemon/dist/install.sh
```

That script:

- installs `target/release/r503d` to `/usr/local/bin/r503d`
- writes the udev rule that exposes the Arduino as `/dev/r503`
- installs the systemd unit (`/etc/systemd/system/r503d.service`)
- overrides the D-Bus autolaunch entry for `net.reactivated.Fprint`
- stops and masks upstream `fprintd.service`
- starts `r503d.service`

It's idempotent — re-run it after every `cargo build --release` to
redeploy the new binary.

### 4. Enroll & verify

```bash
# Enroll a finger (use KDE Settings → Users → Fingerprint Auth for a GUI):
fprintd-enroll mat

# Verify:
fprintd-verify mat

# sudo with finger:
sudo whoami
```

Both KDE Settings (Plasma 6) and GNOME Control Center's user-account
fingerprint dialogs drive `r503d` exactly as they drive upstream `fprintd`.

### Uninstall

```bash
sudo bash pcside/daemon/dist/uninstall.sh
```

Reverts everything, unmasks `fprintd`, leaves `/var/lib/r503d/users.json`
in place in case you want to reinstall later.

## How it works

The Arduino runs a small ASCII-protocol firmware (`firmware/r503fp/`)
that talks the R503's native R30x ("Sync Word") binary protocol on its
UART side and exchanges line-oriented text commands with the host over
USB-CDC: `ping`, `info`, `enroll N`, `verify`, `delete N`, `clear`,
`led off`. Full protocol in [`SPEC.md` §5](SPEC.md).

The Rust daemon (`r503d`) speaks D-Bus on `net.reactivated.Fprint` — bit-for-bit
the same interface upstream `fprintd` exposes — so every `fprintd` client
works unmodified. A JSON sidecar at `/var/lib/r503d/users.json` maps
(user, finger) to slot indices in the R503's internal flash.

Layout:

```
firmware/r503fp/r503fp.ino   Arduino firmware (ASCII protocol over USB-CDC)
pcside/daemon/               Rust daemon (the fprintd replacement)
pcside/daemon/dist/          udev rule, systemd unit, install scripts
docs/                        Decision logs + troubleshooting
SPEC.md                      Full architecture + protocol spec
```

## Limitations

- **Single-user.** The daemon trusts every D-Bus caller. Don't expose
  this on a shared workstation. Add polkit if you need that.
- **One reader.** The daemon exposes a single Device object on D-Bus.
  Multi-reader setups need an extension to the Manager.
- **No `PropertiesChanged` emit** for the `finger-present` / `finger-needed`
  hint properties. Every common fprintd client (PAM, KDE Settings, GNOME)
  drives off `EnrollStatus` / `VerifyStatus` signals (which are emitted),
  not those polled hints — but a strict client that does
  `Get + PropertiesChanged` will see stale values.

## Troubleshooting

```bash
# Daemon logs:
sudo journalctl -u r503d.service -f

# Confirm the sensor enumerates correctly:
ls -l /dev/r503
busctl --system call net.reactivated.Fprint /net/reactivated/Fprint/Device/0 \
    net.reactivated.Fprint.Device ListEnrolledFingers s ""

# Confirm fprintd is masked and r503d owns the bus name:
systemctl is-enabled fprintd  # should print "masked"
busctl --system list | grep -i fprint
```

If the daemon won't start or the sensor never responds, the most common
fix is the wiring — see [`SPEC.md` §3](SPEC.md), particularly the
**"no voltage divider"** note in §3.1. There's a more detailed runbook
in [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md).

## License

MIT — see [LICENSE](LICENSE).

## Credits

- [Adafruit_Fingerprint](https://github.com/adafruit/Adafruit-Fingerprint-Sensor-Library)
  — Arduino-side R30x protocol implementation.
- [zbus](https://github.com/dbus2/zbus),
  [serialport-rs](https://github.com/serialport/serialport-rs),
  [tokio](https://tokio.rs/) — the Rust D-Bus / serial / async stack.
- The `fprintd` project — for designing a clean D-Bus interface that
  this daemon could implement against without ever reading
  `libfprint`'s source.
