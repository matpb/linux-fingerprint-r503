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
The R503 stores templates internally and only emits match/no-match. Templates never leave the sensor. The PC ↔ Arduino link in v1 is plaintext over USB-CDC — anyone with physical access to the cable, or any local process that can open `/dev/r503`, can spoof an `OK match=0` response. v1 ships that way as an explicit hobbyist tradeoff. §13 specifies the v2 authenticated channel (SipHash-2-4 MACs, monotonic counters, TOFU pairing) that closes those holes.

### 11.6 Multi-user
The R503 has 200 slots. The PC-side driver needs to maintain a `slot → username` mapping somewhere (e.g. `/var/lib/r503/slots.json`). Single-user is trivial; multi-user is a layer-3 design question, not blocking for the weekend.

---

## 12. v2 Ideas (Out of Scope for This Weekend)

- Migrate Nano → Pro Micro or RP2040 with native USB and custom VID:PID/iProduct, removing the CH340 ambiguity.
- Custom PCB integrating R503 socket + microcontroller + USB-C in a 40mm round puck the size of the sensor.
- WebAuthn / FIDO2 surface so the device can also be used as a second factor for web logins.
- 3D-printed enclosure with magnetic desk mount.

---

## 13. Authenticated Wire Protocol (v2)

v1 ships with a plaintext ASCII protocol over USB-CDC. This section specifies the v2 upgrade that authenticates every frame in both directions with a shared key, blocks replay, and survives hardware swap. Forward-only; no compatibility window with v1 (rationale in §13.8).

### 13.1 Threat model

**Defends against:**
- **Hot-swap / evil maid** — attacker physically unplugs the real Nano and plugs in a hostile unit that always returns `OK match=...`. The replacement does not know the host key; its frames fail MAC verify.
- **In-process MITM on `/dev/r503`** — any local user who somehow opens the serial device (mis-set ACL, supplementary group leak, kernel bug) cannot inject forged match responses. ACL on the device node becomes defense in depth, not the only layer.
- **Replay** — a captured `OK match=0` frame from a legitimate verify cannot be replayed in a future session. Monotonic counters enforced on both ends.

**Does NOT defend against:**
- A host compromised at root: attacker reads the key from `/var/lib/r503d/key`, MAC is moot.
- Side-channel attacks against the R503 sensor itself, including template extraction over the R30x UART. The sensor speaks R30x with no auth; that is out of scope, and Adafruit_Fingerprint exposes the same surface to anyone with bench access.
- Physical attack on the Nano with kit (logic analyzer on the I/O bus, EEPROM readback via ISP, decap). With time and money, the key comes out.
- Compromise of fprintd, PAM, the kernel, or anything downstream of r503d.

We are targeting "attacker with five minutes and a spare Nano", not nation-state.

### 13.2 Crypto primitive

**SipHash-2-4** with a 128-bit shared key, producing a 64-bit MAC.

- ~500 bytes of AVR flash, ~30 µs per MAC for typical frame sizes on a 16 MHz ATmega328P.
- Designed for short-message authentication on constrained devices. Not a hash — a keyed PRF.
- 64-bit MAC is sized for an interactive protocol with bounded throughput (~1 command/sec). Online forgery requires ~2⁶³ attempts on average; at line rate that exceeds the heat death of the sun.

Rejected:
- **HMAC-SHA256** — 3-4 KB flash and ~1.5 ms per MAC on AVR. Overkill for the threat model and a tight fit alongside Adafruit_Fingerprint + SoftwareSerial in the existing firmware footprint.
- **Ascon-Mac** (NIST LWC winner) — ~800 bytes flash, also fine. SipHash chosen for the longer deployment history, simpler audit, and slightly smaller code budget.

### 13.3 Frame format

Stays ASCII, line-oriented, screen-debuggable. Each frame gets a counter prefix and a hex MAC suffix.

**Command (host → Nano):**
```
C <cmd_counter> <command-line> M <mac_hex>
```
- `cmd_counter` — monotonic 64-bit unsigned, decimal-encoded. Host bumps by 1 per command.
- `command-line` — verbatim v1 command (e.g. `verify 0`).
- `mac_hex` — 16 hex chars = 8 bytes = SipHash-2-4(key, `"CMD " || cmd_counter || " " || command-line`).

**Response (Nano → host)** — every line emitted in response, including `PROGRESS`:
```
R <cmd_counter> <resp_seq> <response-line> M <mac_hex>
```
- `cmd_counter` — echo of the originating command's counter. Binds this response to that specific command. Defeats replay of an old `OK` frame into a future session.
- `resp_seq` — 0-based within the command's response stream. Bumps each line. The terminal `OK`/`ERR` ends the stream.
- `mac_hex` — SipHash-2-4(key, `"RSP " || cmd_counter || " " || resp_seq || " " || response-line`).

**Examples on the wire (key omitted):**
```
C 42 verify 0 M 9f3a1c4d2b7e5601
R 42 0 PROGRESS place_finger M 1a2b3c4d5e6f7081
R 42 1 OK match=0 confidence=168 M deadbeef01020304
```

**Unsolicited Nano emissions** (boot banner, async touch-wake notifications) use `cmd_counter=0` and an independent boot-counter as `resp_seq`. The daemon treats `cmd_counter=0` frames as advisory only — they cannot trigger PAM verdicts, only log events. A boot banner re-triggers session re-handshake (see §13.5).

### 13.4 Counter rules

- Host's `cmd_counter` is monotonic per pairing. Persisted to `/var/lib/r503d/state.json` after each command sent. Crash mid-command advances the counter on next boot — a small range may be "skipped" but the invariant holds.
- Nano persists `last_seen_cmd_counter` in EEPROM. Each command is rejected unless `incoming > last_seen`. `last_seen` is updated only after successful MAC verify.
- **EEPROM wear** — ATmega328P EEPROM rated 100k writes per cell. Store the counter as a 16-cell rotating log: 16 × 100k = 1.6M counter bumps ≈ 88 years at 50 logins/day. Implementation: 16-byte ring of `(8-byte counter, 1-byte CRC)` records, written round-robin, picked at boot by largest valid counter.
- 64-bit counter wraps in geological time. Don't worry about it.

### 13.5 Pairing (TOFU)

**Initial pairing:**

1. Nano EEPROM either contains a `PAIRED` magic word + key, or is blank.
2. On boot, Nano emits a banner with `paired=true|false`.
3. If `paired=false`, the daemon checks for explicit opt-in: presence of `/etc/r503d/allow-pair` **or** invocation as `r503d --pair`. Without opt-in, the daemon logs a warning and refuses to pair. This prevents an attacker who races to the desk with their own Nano from auto-pairing before Mat.
4. Daemon generates a 128-bit key via `getrandom(2)`, sends the unauthenticated `pair <key_hex>` command. Nano accepts `pair` **only** when unpaired.
5. Nano writes magic + key to EEPROM, replies `OK paired`, then reboots into the paired state.
6. Daemon writes the key to `/var/lib/r503d/key` (mode `0600`, root:root) and removes `/etc/r503d/allow-pair`.
7. Subsequent commands carry MACs.

**Re-pairing (key compromised, hardware swap, host rebuild):**

- **Authenticated re-pair** — host issues an authenticated `unpair` command (MAC proves it knows the current key). Nano clears EEPROM, reboots into unpaired state. Initial pairing dance runs again with a fresh key. Primary path for the "host still has the key but wants to rotate it" case.
- **Reflash-to-wipe** — escape hatch for "host lost the key entirely". Ship a separate `firmware/r503fp_wipe/` sketch that clears EEPROM on boot and halts. Flash it once with `arduino-cli` over the existing USB cable (no box opening, no hardware access), then flash the real firmware. Nano boots unpaired, normal TOFU pairing runs.

Re-pair without one of those paths is impossible. An evil-maid attacker with a fresh Nano cannot pair because they lack host-side opt-in (root-owned), and they cannot wipe an existing pairing without either the current key or physical USB access PLUS root on the host to re-pair. The reflash-to-wipe escape hatch itself is not an attack vector: even if an attacker reflashes the Nano via USB, they cannot re-pair without root on the host (`/etc/r503d/allow-pair` is root-owned, `r503d --pair` is a root-only CLI), and an attacker with host root has already won by other means.

### 13.6 Host-side key storage

- Path: `/var/lib/r503d/key`
- Format: 32 hex chars + newline.
- Permissions: `0600 root:root`.
- Backup: written to `/var/lib/r503d/key.bak` (mode `0400`) at pairing time to survive accidental `rm` of the live file. Daemon falls through to `.bak` if the live file is missing.
- Deliberately separate from `/etc/r503d/` so config can be world-readable without leaking the key.

### 13.7 Failure modes

| Failure | Detection | Recovery |
|---|---|---|
| MAC mismatch on incoming command | Nano replies `ERR mac_invalid` (unauthenticated error frame, no MAC) | Daemon logs, retries once; persistent failure surfaces as `sensor_unreachable` to fprintd |
| Counter regression (replay) | Nano: `incoming <= last_seen` → `ERR replay` | Same as above |
| MAC mismatch on incoming response | Daemon drops frame, logs, treats stream as `no_match` | Re-prompt user; persistent failure marks sensor unhealthy |
| Host counter file lost (FS damage) | Daemon start: no state file | Refuse to operate; `r503d --resync` queries Nano via an authenticated `status` read, sets local counter to `last_seen + 1` |
| Nano EEPROM corrupted (counter ring CRCs all fail) | Boot self-check fails | Banner: `degraded=true`; daemon refuses verifies; user runs physical re-pair |
| Host loses key file (no backup) | Daemon start: clear error | Physical re-pair (D7 jumper) |
| Nano-side `last_seen` ahead of host (host restored from backup) | First command: `ERR replay` | `r503d --resync` fast-forwards local counter |

### 13.8 Migration from v1 plaintext

Hard cutover, no compatibility window. Reasons:

- A "downgrade to plaintext" capability is itself an attack vector — strip it from the protocol entirely.
- v1 is a hobbyist prototype with one known deployment (Mat's desk). Preserving an installed base is not a real cost.
- Firmware v2 and daemon v2 ship together. Mixed versions detect the mismatch on first banner (`fw=1.0` vs daemon's expected ≥ `1.0`) and refuse to operate with a clear error pointing at the upgrade procedure.

Firmware version bumps `fw=0.3` → `fw=1.0` to mark the protocol break. Daemon Cargo version bumps to `1.0.0` simultaneously.

### 13.9 Code budget

- **Firmware**: ~350 LOC added. SipHash-2-4 impl ~120, framing wrapper ~80, EEPROM ring + pairing state machine ~150. No new external libraries — SipHash is small enough to inline.
- **Daemon (Rust)**: ~400 LOC added. Framing wrapper ~100, pairing CLI subcommand ~150, state file IO ~80, error handling ~70. New crate deps: `siphasher` (or hand-rolled in 60 LOC for audit clarity), `rand_core` for the key. `serde_json` already pulled.
- **Tests**: ~200 LOC daemon-side (property tests for frame round-trip + replay rejection + MAC tamper); ~50 LOC firmware-side via `pcside/r503ctl.py` with a `--key` mode.

### 13.10 Testing strategy

1. **Unit** — SipHash-2-4 reference vectors from the paper, both firmware and daemon.
2. **Frame round-trip** — daemon-side property test: random key, random commands, encode/decode/verify.
3. **Replay rejection** — daemon re-sends a known-good frame; firmware must reply `ERR replay`.
4. **MAC tamper** — flip one bit each of MAC, counter, command body, `resp_seq`; each variant must yield `ERR mac_invalid`.
5. **Pairing race** — without `/etc/r503d/allow-pair`, an unpaired Nano + fresh daemon must refuse to pair.
6. **Full re-pair cycle** — unpair → pair, confirm new key is independent of old (compare `getrandom` output, confirm old key is rejected).
7. **Counter persistence** — power-cycle Nano mid-session, confirm `last_seen` survives, confirm a replay of the last pre-cycle frame fails.
8. **EEPROM wear simulation** — sacrificial Nano, scripted 100k+ cycles, confirm no single cell exceeds its rated limit (read-back validation against an external EEPROM dump).
9. **End-to-end** — full PAM `sudo` flow on the authenticated channel; confirm round-trip latency overhead < 10 ms vs v1 baseline.

---

## 14. Glossary

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
