# Firmware

Arduino sketches for the R503 + Nano bridge.

## Sketches

- **`r503fp/`** — production firmware. Implements the v2 authenticated wire
  protocol (SPEC §13): SipHash-2-4 MAC over every command and response, monotonic
  counter persisted to EEPROM, TOFU pairing. Banner is `R503FP READY fw=1.1 paired=<bool>`.
- **`r503fp_wipe/`** — one-shot emergency EEPROM wipe. Use when you've lost the
  host-side key file (`/var/lib/r503d/key`). Flash this, wait for the LED to
  start blinking, then flash `r503fp/` back and re-pair via `r503d --pair`.
  See the sketch header for the full recovery procedure.
- **`r503fp_stub/`** — minimal echo-OK firmware. No R503 wiring required.
  Used historically for the §6.4 Path A/B/C spike and is occasionally useful
  for verifying USB enumeration.
- **`r503fp_ping/`** / **`r503fp_loopback/`** / **`r503fp_listen/`** /
  **`r503fp_baudsweep/`** / **`r503fp_rawdump/`** / **`r503fp_touchwake/`** /
  **`r503fp_txspam/`** / **`r503fp_clean/`** — diagnostic sketches from the
  initial R503 bring-up. Useful when debugging hardware wiring or sensor
  responsiveness; not used at runtime.
- **`r503fp_prod/`** — early prototype of `r503fp/`; superseded.

## Toolchain

`arduino-cli` driven, no IDE required.

```bash
# One-time setup:
arduino-cli core install arduino:avr
arduino-cli lib install "Adafruit Fingerprint Sensor Library"
```

## Build + flash

The right `cpu=` variant depends on which bootloader is burned on your Nano.

| Bootloader | Baud rate | FQBN variant | Common origin |
|---|---|---|---|
| Optiboot (modern) | 115200 | `arduino:avr:nano:cpu=atmega328` | Most current Elegoo / Sunfounder / WAVGAT Nano clones, official Arduino Nano "Every" |
| ATmegaBOOT (legacy) | 57600 | `arduino:avr:nano:cpu=atmega328old` | Older Nano clones, some refurbished units |

If you don't know which yours is, try `atmega328` first — modern clones are
overwhelmingly the common case. If you see `avrdude: stk500_recv(): programmer is not responding`
or `not in sync: resp=0x7e`, swap to `atmega328old` and try again.

```bash
# Compile
arduino-cli compile --fqbn arduino:avr:nano:cpu=atmega328 firmware/r503fp/

# Find the port (CH340 clones enumerate as ttyUSB; FTDI / Arduino-genuine as ttyACM)
arduino-cli board list

# Flash (replace /dev/ttyUSB0 with whatever showed up)
arduino-cli upload \
  --fqbn arduino:avr:nano:cpu=atmega328 \
  --port /dev/ttyUSB0 \
  firmware/r503fp/
```

If `upload` complains about permission denied on `/dev/ttyUSB0`, either log
out and back in (to pick up the `dialout` group membership) or prefix with
`sudo`. The daemon's installer at `pcside/daemon/dist/install.sh` adds a
udev rule that creates `/dev/r503` as a stable symlink — once installed,
use `--port /dev/r503` regardless of which `ttyUSB*` the kernel picked.

**Note:** that same udev rule locks the device node to `root:root 0600`
(security audit 2026-05-28 / H1), so the `dialout`-group shortcut no longer
applies to `/dev/r503` once the daemon is installed — flashing or opening a
serial monitor on it requires `sudo` (and stopping `r503d` first, since the
daemon holds the port exclusively with `TIOCEXCL`).

**EEPROM persists across reflash.** The 16-byte key + counter ring + format
marker live in the ATmega328P's 1 KB EEPROM, which `arduino-cli upload`
does not touch. A paired Nano stays paired after you reflash `r503fp/`.
To clear pairing without the host key, use `r503fp_wipe/`.

## Serial monitor

```bash
tio -b 115200 /dev/r503

# Type `ping` and press Enter — expect `OK pong`.
# Type `status`           — expect `OK paired=<bool> counter=<N> fmt=2 fw=1.1`.
```

Both of those work even on a paired Nano without sending a MAC; everything
else requires the daemon's framed wire format (SPEC §13.3) or an unpaired
Nano. The framed commands look like `C 42 verify 0 M 9f3a1c4d2b7e5601` —
you wouldn't usually type those by hand. Stop `r503d` first if you want
exclusive access to the port for manual prodding.
