# R503 + Arduino Nano → Linux Fingerprint Login — Project Specification (v2)

**Target platform:** Fedora Workstation / KDE Spin, KDE Plasma desktop, x86_64
**Hardware:** Grow R503 capacitive fingerprint sensor + Arduino Nano (ATmega328P) bridge
**Goal:** A working desktop fingerprint reader for KDE Plasma — using parts on hand and a publicly documented sensor, with the work split cleanly into firmware, PC-side tooling, libfprint integration, and desktop wiring.

This is the spec v2. It supersedes v1 (Serounder/TE-FPA2 reverse-engineering plan). The architecture is now:

```
   ┌────────────┐   UART   ┌─────────────┐   USB-CDC   ┌──────────────────┐
   │            │  57600   │             │  /ttyACM0   │                  │
   │   R503     │◀────────▶│ Arduino     │◀──────────▶│   Linux host     │
   │   sensor   │  3.3V    │ Nano        │  serial     │   (Fedora KDE)   │
   │            │          │ (firmware)  │             │   libfprint,     │
   └────────────┘          └─────────────┘             │   fprintd, PAM   │
                                                      └──────────────────┘
```

The Nano speaks the R503's native R30x protocol downstream, and a custom ASCII protocol upstream. The PC-side libfprint driver (or, fallback, a userspace daemon) speaks that ASCII protocol and exposes the result to `fprintd` and PAM.

---

## 1. Why This Architecture

The original plan (reverse-engineer a Windows fingerprint dongle) had two big unknowns: the device's USB protocol, and whether the device's chipset was hostile (signed firmware, session crypto). Both unknowns required substantial sunk cost before we'd know if the project was even viable.

This architecture eliminates both:

- The **R503 protocol is public.** The R30x "Sync Word" protocol is documented and has mature Arduino/Python libraries (Adafruit_Fingerprint, R30X-Fingerprint-Sensor-Library, pyfingerprint).
- The **PC↔Arduino protocol is our own.** We design it. There's no reverse engineering — there's just engineering.

The cost of this approach is that we're walking a path no libfprint driver has walked before (UART-backed device behind a USB-CDC bridge), and the physical artifact is "sensor module + Arduino on a desk" rather than "tiny USB nub in a port." Both are acceptable trades.

---

## 2. Bill of Materials

**On hand (per user):**
- Arduino Nano (ATmega328P, CH340 or FT232 USB-serial chip) — at least one to dedicate
- Arduino Uno R3 — backup; identical MCU, same firmware works
- Dupont jumper wires, breadboard, miscellaneous parts

**Ordered:**
- Grow R503 capacitive fingerprint sensor (round, ~28mm, RGB LED ring)

**Likely needed, confirm against parts bin:**
- 2× resistors for a voltage divider on the Nano TX → R503 RX line (1kΩ and 2kΩ work cleanly to drop 5V to 3.3V), **or** a logic level converter board, **or** a 3.3V Arduino variant
- 6-pin JST-SH-to-Dupont pigtail **if** the R503 ships with the JST connector rather than bare flying leads (varies by seller)
- USB-A-to-Mini-B or USB-A-to-Micro-B cable (depends on Nano variant — check before Saturday)

**Nice to have, not blocking:**
- A small project box or 3D-printed enclosure for the R503 + Nano
- A short piece of double-sided tape to anchor the unit to the desk

---

## 3. R503 Pinout and Wiring

The R503 has six wires. Color codes are standard across most sellers but **verify against the datasheet that came with the unit** — counterfeit modules occasionally rewire colors.

**Corrected pinout per the actual Grow R503 datasheet** (verified empirically 2026-05-24 with Mat's unit):

| Wire color | Function | Connect to |
|---|---|---|
| Red | VCC (3.3V, sensor main power / V_main) | Uno/Nano `3V3` pin |
| Black | GND | `GND` |
| Yellow | TXD (sensor → MCU, 3.3V TTL output) | `D2` (SoftwareSerial RX) |
| Brown (sometimes green per seller) | RXD (MCU → sensor, **5V-tolerant in practice**) | `D3` (SoftwareSerial TX) **— direct, no divider** |
| Blue | WAKEUP (finger detection — **active-LOW**: idle 3.3V, finger 0V) | `D4` (digital input, optional) |
| White | 3.3VT (touch induction power, DC 3-6V, 5µA, autonomous always-on touch IC supply) | `3V3` pin (shares rail with red) |

### 3.1 No voltage divider on the TX line — connect directly

**The R503's RX input is 5V-tolerant in practice, despite the datasheet specifying "3.3V TTL logic level".** Earlier versions of this spec called for a 1kΩ/2kΩ divider to drop 5V to 3.3V. That divider WILL NOT WORK with this sensor — the R503's RX has an internal pullup strong enough to fight the divider, leaving the line stuck above the LOW threshold so the sensor never registers valid UART start bits.

**Symptom of the divider problem:** sensor sends `0x55` handshake on power-up (proving TX is alive) but never responds to any command. Easy to misdiagnose as a dead MCU.

**Fix:** connect brown (or green) **directly** to the Uno/Nano TX pin. No resistors in path. Matches how every working R503 + Arduino tutorial wires it.

The sensor's TX (yellow → `D2`) is 3.3V TTL out, comfortably above Uno's ~2.5V HIGH threshold, so it's read correctly without shifting.

### 3.2 Why SoftwareSerial on D2/D3 and not the Nano's hardware UART

The Nano's hardware UART (D0/D1) is shared with the USB-to-serial chip. If you use D0/D1 for the R503, every byte you print to `Serial` on the PC side leaks into the R503's mouth, and every byte from the R503 leaks into your console. Use `SoftwareSerial` on D2/D3 for the sensor, and keep the hardware `Serial` (USB) reserved for talking to the PC.

The R503's default baud is 57600. SoftwareSerial on a 16MHz Nano handles 57600 reliably; if you see corruption, drop the sensor to 9600 with a one-time `setBaud` command.

---

## 4. Arduino Firmware

### 4.1 Library choice
Use **Adafruit_Fingerprint** as the base. It works with the R503 (and all R30x-family modules) out of the box, has documented examples, and abstracts the binary packet protocol so you can focus on the PC-side protocol.

Install via Arduino IDE: `Sketch → Include Library → Manage Libraries → "Adafruit Fingerprint Sensor Library"`.

### 4.2 Firmware responsibilities

1. Initialize SoftwareSerial at 57600 to R503; verify password and read sensor parameters.
2. Initialize hardware Serial at 115200 to PC; print a banner `R503FP READY fw=0.1 capacity=200`.
3. Read newline-terminated ASCII commands from `Serial`.
4. Dispatch each command, write a single-line ASCII response.
5. Drive the R503 RGB LED to give the user visual feedback: pulsing blue while waiting for finger, solid green on match, red on no-match, purple during enrollment.
6. Optionally: use the touch-detect pin (D4) to short-circuit the "no finger present" case without polling the sensor every loop.

### 4.3 Firmware state machine (sketch)

```
IDLE ─── command in ───► EXECUTING ─── result/error ───► IDLE
                              │
                              ├── enroll: multi-pass capture, write to slot
                              ├── verify: single capture, match against slot N
                              ├── identify: single capture, search all slots
                              ├── delete: erase slot N
                              ├── clear: erase all
                              ├── count / list / info: pure metadata
                              └── led: pure side effect
```

No nested state. Each command runs to completion before the next is accepted. If a command needs more than ~10 seconds (enroll typically does), the firmware emits intermediate status lines (`PROGRESS place_finger`, `PROGRESS remove_finger`, `PROGRESS place_again`) so the PC side doesn't think we've hung.

### 4.4 Approximate code budget
~400 lines of Arduino C++. Single `.ino` file is fine for v1. Refactor to multiple files only if it grows past 600 lines.

---

## 5. PC↔Arduino Protocol

ASCII, line-oriented, 115200 8N1 over USB-CDC. Easy to debug by hand with `screen /dev/ttyACM0 115200` or `minicom -D /dev/ttyACM0 -b 115200`.

### 5.1 Conventions

- Every command is one line, terminated `\n`.
- Every response is one or more lines. Final line is either `OK` (optionally `OK <data>`) or `ERR <code> <human-readable>`.
- Multi-step operations emit `PROGRESS <event>` lines between command and final response.
- Tokens are space-separated. No quoting needed because all fields are integers or short identifiers.
- All lowercase commands. Responses uppercase first token.

### 5.2 Command list (v1)

| Command | Description | Success response | Failure response |
|---|---|---|---|
| `info` | Identify firmware + sensor | `OK fw=0.1 capacity=200 enrolled=3 serial=...` | `ERR sensor_unreachable` |
| `count` | Number of enrolled fingers | `OK count=3` | — |
| `list` | List occupied slots | `OK slots=0,2,5` | — |
| `enroll <slot>` | Enroll finger into slot N (0..199) | `PROGRESS place_finger`<br>`PROGRESS remove_finger`<br>`PROGRESS place_again`<br>`OK enrolled=N` | `ERR slot_in_use` / `ERR timeout` / `ERR poor_quality` / `ERR mismatch` |
| `verify <slot>` | Capture finger, match against slot N | `PROGRESS place_finger`<br>`OK match=N confidence=87` | `ERR no_match` / `ERR timeout` |
| `identify` | Capture finger, match against all slots | `PROGRESS place_finger`<br>`OK match=N confidence=87` | `ERR no_match` / `ERR timeout` |
| `delete <slot>` | Erase one slot | `OK deleted=N` | `ERR slot_empty` |
| `clear` | Erase all slots (confirmation required) | (after `clear confirm`): `OK cleared` | `ERR confirmation_required` |
| `led <r> <g> <b> <mode>` | Set LED color and pattern | `OK` | `ERR bad_mode` |
| `cancel` | Abort current operation | `OK cancelled` or `OK idle` | — |
| `reset` | Soft-reset Arduino + sensor | (banner) | — |

### 5.3 Timeouts
The PC side must allow up to ~30 seconds for `enroll` to complete, and ~10 seconds for `verify` / `identify`. The Arduino enforces an internal timeout of 8 seconds per capture stage and emits `ERR timeout` if no finger appears.

### 5.4 Error codes (exhaustive for v1)
`sensor_unreachable`, `slot_in_use`, `slot_empty`, `timeout`, `poor_quality`, `mismatch`, `no_match`, `bad_mode`, `bad_args`, `unknown_command`, `confirmation_required`, `busy`.

---

## 6. PC-Side Architecture

Three plausible integration paths. We commit to **Path A** for v1, with B and C as fallbacks if A blocks.

### 6.1 Path A — libfprint driver that opens `/dev/ttyACM*` directly
A custom libfprint driver class that, on probe, scans `/dev/serial/by-id/` for a device whose `iProduct` string matches `R503FP` (we set this via the Arduino's USB descriptor if possible; if not, we match on the CH340's generic ID and rely on the firmware banner). On open, it sends `info` and verifies the banner. Subsequent enroll/verify/identify map directly to ASCII commands.

**Pro:** Simplest. No kernel module ejection, no udev fights. Reuses the existing libfprint stack from `fprintd` upward.
**Con:** No precedent in libfprint for serial-backed drivers. Risk that some part of the driver lifecycle assumes a USB device handle.

### 6.2 Path B — libfprint driver using libgusb on the raw USB device
A udev rule prevents `cdc-acm` from binding to the Nano's USB ID. The libfprint driver then opens the raw USB interface via `libgusb` (which libfprint already uses), reads/writes the bulk endpoints, and the ASCII protocol runs on top.

**Pro:** Matches the existing libfprint house style; upstream-friendly.
**Con:** More work (udev rule, raw USB handling) and the Arduino's USB chip enumeration may be uncooperative.

### 6.3 Path C — Standalone daemon mimicking fprintd
Write `r503d`, a Python daemon that opens `/dev/ttyACM*`, speaks the ASCII protocol, and exposes the same D-Bus interface as fprintd (`net.reactivated.Fprint`). PAM and KDE Plasma talk to it as if it were fprintd.

**Pro:** No libfprint changes at all. Easy to prototype in Python.
**Con:** Need to either reimplement enough of the fprintd D-Bus surface that consumers don't notice, or sit alongside fprintd and steal its bus name (collision-prone). Maintenance burden long-term.

### 6.4 The "spike" that decides the path
Before committing to A, B, or C, the agent runs a **30-minute spike**:

1. Wire and flash the Arduino with a stub firmware that just echoes `OK` to any command.
2. Plug it in. Confirm it appears as `/dev/ttyACM0` (or `ttyUSB0` depending on the Nano variant).
3. Open the libfprint source tree. Search for any driver that uses anything other than `libgusb` (look for `open`, `read` on file descriptors in driver code, not just `fpi_usb_transfer_*`).
4. If something usable exists or the driver init lifecycle has a non-USB hook, commit to Path A.
5. If not, immediately fall to Path C for v1 (Python daemon), and treat Path B as a v2 upstreaming effort.

---

## 7. fprintd, PAM, KDE Integration

Same as v1 spec, unchanged. If Path A or B succeeds, this layer is free.

- `fprintd` ≥ 1.94 from Fedora repos; `fprintd-enroll`, `fprintd-verify`, `fprintd-identify` as test commands.
- PAM configured via `authselect select sssd with-fingerprint`.
- KDE Plasma's System Settings → Users → Fingerprint Authentication should detect the new device once `fprintd` knows about it. `/etc/pam.d/kde-fingerprint` is already shipped by Fedora KDE.

If Path C is taken (Python daemon), this layer requires more glue — specifically, either making the daemon implement enough of the fprintd D-Bus interface that PAM's `pam_fprintd.so` works against it, or writing a small custom PAM module (`pam_r503.so`) that talks to the daemon directly. Doable but real work.

---

## 8. Testing Strategy by Layer

The build proceeds bottom-up. Each layer is verified before moving up.

### 8.1 Layer 0 — Bench test
- Power the R503 from a USB-serial adapter or the Nano's 3V3 pin.
- LED ring lights up briefly on power.
- If no LED: check polarity, check that 3V3 is actually 3.3V (not floating or 5V on the wrong pin).

### 8.2 Layer 1 — Arduino firmware standalone
- Flash firmware.
- Open Arduino IDE Serial Monitor at 115200.
- Type `info`, get banner.
- Type `enroll 0`, follow LED prompts with a finger.
- Type `verify 0`, place finger, get `OK match=0 confidence=...`.
- Pass criterion: 10 consecutive successful verifies with the same finger.

### 8.3 Layer 2 — PC-side Python prototype
A small Python script using `pyserial` that drives the ASCII protocol. Used to:
- Validate every command and every error path.
- Stress-test (1000-iteration enroll/delete loop).
- Measure end-to-end latency from finger touch to `OK match` response (should be under ~1 second).

### 8.4 Layer 3 — Path A/B/C implementation
Whichever path was chosen at the §6.4 spike. Same functional tests as v1 spec §7.1.

### 8.5 Layer 4 — Desktop integration
- `fprintd-enroll` end-to-end.
- `sudo` accepts finger.
- KDE screen lock accepts finger.
- SDDM login accepts finger.

---

## 9. Weekend Plan

A pessimistic schedule for two full days, with buffer for surprises.

### Saturday morning (3 hours): hardware
- Unbox R503, verify pinout against datasheet
- Build voltage divider, wire to Nano
- Confirm LED ring lights on power
- Flash a minimal "ping the sensor" sketch from Adafruit examples, confirm communication
- Layer 0 + Layer 1 partial done

### Saturday afternoon (3-4 hours): firmware
- Implement the full ASCII command protocol in firmware
- Test every command from Serial Monitor
- Enroll your own right index, verify, delete, repeat
- Layer 1 done

### Saturday evening (optional, 1-2 hours): Python prototype
- Write the pyserial script
- 1000-iteration stress test, watch for any flakiness
- Layer 2 done

### Sunday morning (2-3 hours): the spike
- Read libfprint source for serial/non-USB driver precedent
- Decide Path A vs B vs C
- Lay out the driver/daemon scaffolding

### Sunday afternoon (3-4 hours): integration
- Implement the chosen path
- Get `fprintd-enroll` working
- Wire up PAM via authselect
- Test `sudo`, KDE screen lock, SDDM

### Sunday evening (1 hour): documentation
- README in the project repo: install instructions, wiring diagram, troubleshooting
- Commit the Arduino sketch + PC-side driver/daemon
- Take a photo of the working setup

If Sunday afternoon goes badly (Path A turns out to be impossible and Path C is a bigger build than expected), the project ends Sunday at "Python script + Arduino, working at the CLI, not yet integrated with PAM" — which is still a real success state. KDE integration becomes a weekday evening task.

---

## 10. Repository Layout

```
linux-fingerprint-r503/
├── README.md
├── SPEC.md                          # This document
├── LICENSE                          # LGPL-2.1-or-later
├── firmware/
│   ├── r503fp.ino                   # Arduino sketch
│   ├── platformio.ini               # Optional, for PlatformIO build
│   └── README.md
├── pcside/
│   ├── prototype/
│   │   └── r503ctl.py               # pyserial-based command-line tool
│   ├── libfprint-driver/            # Path A or B
│   │   ├── r503.c
│   │   ├── r503.h
│   │   └── meson.build
│   └── daemon/                      # Path C fallback
│       └── r503d.py
├── docs/
│   ├── WIRING.md                    # ASCII + photos
│   ├── PROTOCOL.md                  # PC↔Arduino ASCII protocol
│   └── TROUBLESHOOTING.md
└── enclosure/                       # optional, 3D-print files
    └── r503-nano-case.scad
```

---

## 11. Open Questions and Risks

### 11.1 Does libfprint accept a non-USB driver? (Path A viability)
Decided at the §6.4 spike, Sunday morning. Risk: if no, fallback to Path C is more work.

### 11.2 Can we set a unique USB identifier on the Nano?
Clones with CH340 chips have a fixed VID:PID and no writable iProduct string. If true, our udev/probe logic has to match on serial number (often unique) or rely on the firmware banner check post-open. Workable but slightly fragile. A Nano variant with the ATmega16U2 (genuine Arduino) or a Pro Micro (ATmega32U4 native USB) allows custom descriptors and is the clean v2 upgrade.

### 11.3 SoftwareSerial reliability at 57600
SoftwareSerial on a 16MHz ATmega328P is documented to work up to 115200 but has reported flakiness at higher baud rates. If the R503 communication is unstable, drop its baud to 9600 with a one-time `setBaud` command (R503 retains baud in flash) and proceed.

### 11.4 Capacitive sensor lifespan on a desk
The R503 is rated for ~1 million touches. At 50 logins/day that's ~55 years. Not a concern.

### 11.5 Security model
The R503 stores templates internally and only emits match/no-match. Templates never leave the sensor. The PC ↔ Arduino link is plaintext over USB-CDC — anyone with physical access to the cable could spoof a `OK match=0` response. For a single-user desktop this is fine; for any threat model that includes "attacker has physical access to my hardware while I'm not at the desk," signed responses between Nano and PC would be a v2 hardening task.

### 11.6 Multi-user
The R503 has 200 slots. The PC-side driver needs to maintain a `slot → username` mapping somewhere (e.g. `/var/lib/r503/slots.json`). Single-user is trivial; multi-user is a layer-3 design question, not blocking for the weekend.

---

## 12. v2 Ideas (Out of Scope for This Weekend)

- Migrate Nano → Pro Micro or RP2040 with native USB and custom VID:PID/iProduct, removing the CH340 ambiguity.
- Custom PCB integrating R503 socket + microcontroller + USB-C in a 40mm round puck the size of the sensor.
- Encrypted PC ↔ MCU channel (ed25519 challenge-response, key burned into MCU at first pairing).
- WebAuthn / FIDO2 surface so the device can also be used as a second factor for web logins.
- 3D-printed enclosure with magnetic desk mount.

---

## 13. Glossary

- **R503** — Grow's capacitive fingerprint sensor module with onboard matching and a programmable RGB LED ring. Speaks the R30x "Sync Word" UART protocol.
- **R30x protocol** — Public binary packet protocol used by Grow's optical and capacitive fingerprint modules. Documented in publicly available datasheets and implemented in Adafruit_Fingerprint and similar libraries.
- **SoftwareSerial** — Arduino library that bit-bangs a UART on any digital pin, freeing the hardware UART for USB.
- **CDC-ACM** — USB Communications Device Class, Abstract Control Model. The standard way a microcontroller presents itself as a serial port to a host OS.
- **libfprint** — userspace C library that is the foundation of fingerprint support on Linux.
- **fprintd** — D-Bus daemon wrapping libfprint.
- **pam_fprintd** — PAM module that talks to fprintd; how `sudo` / `login` / KDE consume fingerprints.
- **authselect** — Fedora's tool for managing PAM stacks declaratively.
- **udev** — Linux device manager; the layer that decides which driver claims a hot-plugged device.

---

**End of spec v2. Plan, build, document. Then weekday-evening polish.**
