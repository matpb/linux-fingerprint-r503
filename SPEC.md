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
The R503 stores templates internally and only emits match/no-match. Templates never leave the sensor. The PC ↔ Arduino link in v1 was plaintext over USB-CDC — anyone with physical access to the cable, or any local process that can open `/dev/r503`, could spoof an `OK match=0` response. v1 shipped that way as an explicit early-deployment tradeoff. §13 specifies the v2 authenticated channel (SipHash-2-4 MACs, monotonic counters, TOFU pairing) that closes those holes; v2 is the only path on `fw=1.0+`.

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

**Status: implemented in `fw=1.0` / `r503d 1.0.0`.** Replaces the v1 plaintext ASCII protocol with shared-key authentication over the same USB-CDC line. All commands and responses are MAC-tagged with SipHash-2-4; replay is blocked by monotonic counters on both ends. Forward-only — no compatibility window with v1 (rationale in §13.8).

**Crypto posture.** Primitive: SipHash-2-4 (Aumasson & Bernstein, 2012). 128-bit shared key, 64-bit MAC, domain-separated MAC inputs (§13.2). Two independent implementations: hand-rolled C++ on the AVR (~80 LOC, KAT-verified against the published Aumasson vectors + boot-time on-device self-test that halts the firmware with a distinctive LED strobe on mismatch) and hand-rolled Rust on the host. The Rust impl is cross-validated bit-for-bit against the third-party [`siphasher`](https://crates.io/crates/siphasher) crate on 1024 random `(key, msg)` vectors (`tests/crossimpl_siphash.rs`). MAC comparison on the host uses `subtle::ConstantTimeEq`; firmware uses an unconditional XOR-OR over all 8 bytes. The wire parser is property-fuzzed in stable Rust on every CI run (`tests/fuzz_framing_smoke.rs`, ~135 000 inputs covering random bytes, ASCII-printable, mutated valid frames, and round-trip invariants); a `cargo fuzz` libFuzzer target lives at `pcside/daemon/fuzz/` for nightly users running long-corpus passes. `cargo audit` runs in CI against the RustSec advisory database and currently flags no advisories. The full multi-pass review (5 layers, 10 findings addressed, evidence reproducible) is in [`docs/REVIEW-2026-05-28.md`](docs/REVIEW-2026-05-28.md). The threat model is intentionally bounded (§13.1): evil-maid with a spare Nano + hostile local process. Attackers explicitly out-of-scope are listed in §13.1 (host root, hardware lab, side-channel against the AVR). A second, adversarial audit on 2026-05-28 re-entered the codebase hostile (privilege-escalation, spoofing, impersonation), then validated every finding against source and committed a fix per confirmed claim — it tightened the host-side DAC boundary (device-node permissions, key-file and JSON-file load guards) and a firmware body-length edge. Report and per-claim validation: [`docs/SECURITY-AUDIT-2026-05-28.html`](docs/SECURITY-AUDIT-2026-05-28.html) + [`docs/SECURITY-AUDIT-2026-05-28-VALIDATION.html`](docs/SECURITY-AUDIT-2026-05-28-VALIDATION.html).

### 13.1 Threat model

**What we defend against:**

| Attack | Defense |
|---|---|
| Hot-swap / evil maid: attacker unplugs the real Nano and inserts a hostile unit programmed to always return `OK match=...` | The hostile unit doesn't know the host key; every frame fails MAC verify and is rejected as `framing_rejected` by the daemon (which surfaces as `sensor_unreachable` to fprintd) |
| In-process MITM on `/dev/r503`: any local user who can open the serial device (mis-set ACL, supplementary group leak, kernel bug) tries to inject `OK match=0` | Two layers: (1) the device node is `root:root 0600` via `dist/70-r503.rules` and the daemon opens the port with `TIOCEXCL` (exclusive), so a non-root process can't open it at all — this closes the default `0660 root:dialout` access path; (2) even if it could open it, it has no key, so every injected frame fails MAC verify. Layer 1 was added in the 2026-05-28 audit (finding H1); layer 2 is the original design. |
| Replay of captured response frames: attacker records a real `OK match=0` and tries to feed it back during a later verify | Response MAC is keyed on both the command counter and a per-response sequence number. A frame for command #42 is rejected during command #43 (counter mismatch); a frame for `seq=1` is rejected when `seq=0` is expected (seq mismatch) |
| Replay of captured command frames: attacker records `C 42 verify 0 M ...` and tries to resend it | Firmware rejects with `ERR replay` whenever `incoming_counter <= last_seen`; `last_seen` is persisted in EEPROM and survives reboot |
| Tampering with any frame field (counter, body, seq, MAC) | SipHash-2-4 is computed over a domain-separated input string covering all fields; bit-flips anywhere cause MAC verify to fail. Comparison is constant-time (XOR-OR loop) so timing channels don't leak which byte differed |

**What we explicitly do NOT defend against:**

- **Host root compromise.** Attacker reads the key from `/var/lib/r503d/key` (`0600 root:root`) and forges any frame. If they have root, biometrics are moot anyway — they can disable PAM, dump process memory, or just edit `/etc/passwd`.
- **Sensor-side compromise.** The R503 speaks the public R30x "Sync Word" protocol over UART with no authentication. Anyone with bench access to the R503's TX/RX wires can extract templates, replay match signals, or impersonate the sensor end-to-end. This is a property of the R30x chip family, not something we can fix in firmware.
- **Confidentiality.** Frames are not encrypted, only authenticated. We don't encrypt because no secrets cross the wire — templates never leave the R503, and the only response payloads are `match=N confidence=M` or short error strings. An attacker recording the link learns which slot matched, not the template.
- **Physical attack on the Nano.** EEPROM readback via ISP (~30 seconds with a $20 programmer), decap + microprobe (~$10k and a lab), or simple chip replacement reveals the key. The ATmega328P has no tamper resistance, no secure boot, no signed flash. Mitigation: tamper-evident sticker on the case so you notice the box was opened. Not implemented in this project.
- **Firmware reflash via the Arduino bootloader.** Anyone with USB access and `arduino-cli` can flash arbitrary firmware. The bootloader has no signing. A malicious firmware could exfiltrate the key on first boot. But: re-pairing requires `/etc/r503d/allow-pair` (root-owned) or `r503d --pair` (root-only CLI), so a reflashed Nano can't be brought into the daemon's trust without root on the host — which is already game over per the first bullet.
- **Side-channel attacks on the SipHash implementation itself.** Power analysis, EM emanations, and other physical side channels can recover the key from a running Nano in a controlled lab setting. Same physical-access caveat as above.
- **Downstream compromise.** fprintd, PAM, the kernel, the system bus — anything below `r503d` in the trust chain is assumed trusted. If those are compromised, the authenticated channel still works correctly but the answer it returns gets ignored.

We're targeting **"evil maid with five minutes, a spare Nano, and a USB cable"** — not nation-state, not hardware lab.

### 13.2 Cryptographic choices

**Primitive: SipHash-2-4** (Aumasson & Bernstein, 2012).

- 128-bit key, 64-bit MAC output.
- ~80 LOC C++ on AVR, ~150 LOC Rust on the daemon (both hand-rolled to keep the audit surface small — cross-verified against the canonical reference vectors and against each other on 31 random inputs).
- ~500 bytes of AVR flash, microseconds per MAC for our frame sizes.
- Designed for short-message authentication on constrained devices. Not a hash — a keyed PRF.

**Key size: 128 bits.** Matches the SipHash spec exactly. Generated by `getrandom(2)` on the host (the kernel CSPRNG; on Linux this draws from `/dev/urandom`, seeded from hardware entropy).

**MAC size: 64 bits.** SipHash-2-4's native output. Online forgery requires ~2⁶³ attempts on average; even at line rate (115200 baud ÷ ~80-byte frames ÷ Nano processing latency ≈ a few hundred commands/sec ceiling) that's longer than the universe has existed. Offline attacks need the key, which lives in EEPROM and `/var/lib/r503d/key`.

**Constant-time MAC comparison.** Both firmware (`framing.h::verify_command_frame`) and daemon (`framing.rs::verify_command`/`verify_response`) compare expected and claimed MACs by XOR-OR over all bytes, never branching mid-loop on a per-byte difference. No early exit. No timing channel leaks which byte mismatched.

**Domain separation in MAC inputs.** Commands and responses use distinct prefixes so a recorded response frame can't be replayed as a command (or vice versa) even if the visible payload happens to collide:

- Command MAC input: `"CMD " || decimal(counter) || " " || cmd_line`
- Response MAC input: `"RSP " || decimal(counter) || " " || decimal(seq) || " " || body_line`

**Algorithms rejected and why:**

- **HMAC-SHA256.** ~3-4 KB AVR flash, ~1.5 ms per MAC. Works but overkill given the threat model and tight against Adafruit_Fingerprint + SoftwareSerial in the existing firmware footprint. The bigger MAC (256 bits) buys nothing because the bottleneck is the host's per-second rate-limit, not MAC space.
- **Ascon-Mac** (NIST LWC winner, 2023). ~800 bytes flash, also fine. SipHash chosen for the longer deployment history (~13 years in HashDoS-resistant hash tables, well battle-tested) and slightly smaller code budget. Honest assessment: Ascon would also be a reasonable choice.
- **AEAD constructions** (Ascon-AEAD, ChaCha20-Poly1305). Provide confidentiality we don't need (§13.1). Would add nonce-management complexity without benefit.

### 13.3 Frame format

All wire frames are ASCII, line-oriented (terminated by `\n`), screen-debuggable. `screen /dev/r503 115200` lets you watch the protocol in real time.

**Command (host → Nano):**
```
C <cmd_counter> <command_line> M <mac_hex>
```
- `cmd_counter` — monotonic 64-bit unsigned, decimal-encoded.
- `command_line` — verbatim v1-style ASCII command (e.g. `verify 0`, `info`, `enroll 5`).
- `mac_hex` — 16 hex chars = 8 bytes = `SipHash24(key, "CMD " || cmd_counter || " " || command_line)`, serialized little-endian.

**Response (Nano → host)** — emitted by the firmware for every line a handler produces, including intermediate `PROGRESS` lines:
```
R <cmd_counter> <resp_seq> <body_line> M <mac_hex>
```
- `cmd_counter` — echo of the originating command's counter; binds the response to that specific command.
- `resp_seq` — 0-based within the command's response stream. Increments per line. The terminal `OK ...` / `ERR ...` ends the stream.
- `mac_hex` — `SipHash24(key, "RSP " || cmd_counter || " " || resp_seq || " " || body_line)`.

**Examples on the wire (key omitted, MACs faked):**
```
C 42 verify 0 M 9f3a1c4d2b7e5601
R 42 0 PROGRESS place_finger M 1a2b3c4d5e6f7081
R 42 1 OK match=0 confidence=168 M deadbeef01020304
```

**Always-unframed allowlist.** Two commands work without framing in any pairing state, because the daemon needs them before the framed channel is usable:

- `ping` → `OK pong`. Used by the daemon's sync handshake on serial open / reopen. Not security-relevant (no state mutation, no PAM verdict).
- `status` → `OK paired=<bool> counter=<N> fmt=<V> fw=<X>`. Used by the daemon to discover whether the Nano is paired before deciding whether to frame subsequent commands. Read-only, no PAM impact.

In addition, `pair <key_hex>` is accepted unframed but **only when the Nano is unpaired** (firmware enforces). This is the bootstrap step — there's no key to MAC with yet.

Every other command requires framing on a paired Nano. Unframed traffic to a paired Nano (other than the three above) gets rejected with `ERR mac_required`.

**Boot banner** is plain unframed text: `R503FP READY fw=1.0 paired=<true|false>`. Followed (only if the R503 sensor is responsive) by the unframed `info` line. The daemon's open-time sync handshake drains both before sending its first framed command. The banner is intentionally unframed — at boot the daemon hasn't loaded its key yet, and the banner is advisory anyway (paired state is also exposed authoritatively via `status`).

### 13.4 Counter rules

**Host's `cmd_counter`** lives in `/var/lib/r503d/state.json` as `{"next_cmd_counter": N}`:

- Persisted atomically via `tmp + fsync + rename`, mode `0600 root:root`.
- Bumped BEFORE the command goes on the wire. This ordering is deliberate: a crash between bump and send means the host's next start uses a higher counter — the Nano sees a gap, accepts the higher value, and we lose one counter slot. A crash AFTER send is even safer (Nano already accepted, daemon's persisted value matches what was sent). The dangerous order — send first, then persist — is avoided because it would let a crash-and-restart reuse a counter (replay).

**Nano's `last_seen_cmd_counter`** lives in EEPROM as a 16-cell wear-leveled ring:

- Each cell: 8 bytes counter (little-endian) + 2 bytes CRC-16-CCITT over the counter bytes.
- 10-byte cells × 16 = 160 bytes of EEPROM (offset 32..191 per `firmware/r503fp/eeprom.h`).
- On boot, scan all cells; the largest valid-CRC cell is `last_seen`. Empty/blank cells (all `0xFF`) fail CRC check and are ignored.
- On each accepted framed command, write the new counter to the NEXT cell in the ring (cyclic). Any single cell only takes 1/16 of the writes.
- The Nano updates `last_seen` AFTER MAC verify + counter check pass, BEFORE the command handler runs. This guarantees that even a crash mid-handler doesn't let the same counter be re-accepted on next boot.

**EEPROM endurance math.** ATmega328P EEPROM is rated 100,000 write cycles per cell. The ring distributes writes: 16 cells × 100,000 = 1,600,000 total command-counter advances before any single cell wears out. Per typical use:

| Usage profile | Framed commands/day | Years until first cell exhaustion |
|---|---:|---:|
| Light (5 sudo/screen-unlock per day) | ~15 | ~290 |
| Moderate (20/day) | ~60 | ~73 |
| Heavy (50/day) | ~150 | ~29 |

The 64-bit counter itself wraps in geological time; not a concern.

**False-positive CRC matches.** Per-cell, the chance of bit-rot producing a spuriously valid CRC is 1/65,536 (CRC-16). With 16 cells the union bound puts the boot-time "wrong cell mistaken for valid" probability at ~1/4096 — only relevant if EEPROM cells actually decay (multi-decade timescales for ATmega328P at room temperature). Detected mismatches would manifest as a counter regression, blocked by `ERR replay`; the daemon would surface it and the user re-pairs.

### 13.5 Pairing (TOFU)

**Initial pairing:**

1. Nano EEPROM either contains the `R503FPv2` magic + format-version `0x02` + 16-byte key (paired state), or doesn't (unpaired). Boot banner advertises the state as `paired=<true|false>`.
2. The daemon checks for explicit opt-in: either `/etc/r503d/allow-pair` exists, or the operator invoked `r503d --pair`. Without one of those, `r503d --pair` exits with a clear error pointing at the opt-in procedure. **This gate exists to defeat an attacker who races to your desk with their own Nano: they can't auto-pair because creating `/etc/r503d/allow-pair` requires root.**
3. Daemon queries `status` (unframed) to confirm the Nano is unpaired. If already paired, refuses to over-write — re-pair requires explicit `--unpair` first or reflash-to-wipe.
4. Daemon generates a 128-bit key via `getrandom(2)`, sends `pair <key_hex>` (unframed — no key yet to MAC with). The Nano accepts `pair` only when unpaired.
5. Nano writes magic + format version + key + blank counter ring to EEPROM, responds `OK paired`.
6. Daemon re-queries `status` to confirm persistence (defensive — should always succeed).
7. Daemon writes the key to `/var/lib/r503d/key` (`0600 root:root`) and `/var/lib/r503d/key.bak` (`0400 root:root`), initializes `/var/lib/r503d/state.json` with `{"next_cmd_counter": 1}`, removes `/etc/r503d/allow-pair`.
8. Subsequent commands carry MACs.

**Re-pairing (key rotation, planned hardware swap, host rebuild):**

- **Authenticated re-pair** — `r503d --unpair`. Loads the host key, sends a framed `unpair` command (the MAC proves we know the current key; the key itself is not transmitted). Nano clears EEPROM, responds `OK unpaired`. Daemon then deletes host key + state files. Primary path when the host still has the key.

- **Reflash-to-wipe** — `firmware/r503fp_wipe/` is a one-shot sketch that clears EEPROM on boot and halts (LED blinks as a "not the real firmware" indicator). Use this when the host has lost the key entirely (key files deleted with no backup). Workflow:
  ```
  arduino-cli upload --fqbn arduino:avr:nano:cpu=atmega328 --port /dev/r503 firmware/r503fp_wipe/
  # ... LED starts blinking, indicating wipe complete ...
  arduino-cli upload --fqbn arduino:avr:nano:cpu=atmega328 --port /dev/r503 firmware/r503fp/
  sudo touch /etc/r503d/allow-pair
  sudo r503d --pair
  ```

**Why reflash-to-wipe isn't itself an attack vector.** An attacker with physical USB access can reflash the Nano to anything — that's the Arduino bootloader's nature, with or without our wipe sketch. But re-pairing requires `/etc/r503d/allow-pair` (root-owned) or the `r503d --pair` CLI (root-only because it writes to `/var/lib/r503d/`). Without root on the host, a wiped Nano just stays unwiped from the daemon's perspective: the daemon's stored key still expects a paired sensor and all framed commands fail. The user notices, investigates, and remediates.

### 13.6 Host-side state

```
/etc/r503d/allow-pair          # opt-in marker (presence = consent to pair)
/var/lib/r503d/key             # live key, 32 hex chars + newline, 0600 root:root
/var/lib/r503d/key.bak         # fallback copy, 0400 root:root
/var/lib/r503d/state.json      # {"next_cmd_counter": N}, 0600 root:root
/var/lib/r503d/users.json      # user→slot map (pre-existing), 0600 root:root
```

- `/var/lib/r503d/` is created at first pair with mode `0700` (root-only directory).
- The directory and config (`/etc/r503d/`) are deliberately separate so config can be world-readable without leaking the key.
- Key write is atomic: `key.tmp` (0600) → `fsync` → `rename` to `key`, then `cp key key.bak` + `chmod 0400`. If the live file is later deleted by accident, the daemon falls through to `.bak`.

**Load-time hardening (2026-05-28 audit, findings M2/M3).** The `0700` directory already keeps non-root out, but the load paths defend themselves anyway rather than trusting the directory alone:

- **Key load** (`keystore::load_key`): `symlink_metadata` rejects a symlink (no following a planted `key → /etc/shadow`), rejects any file not owned by uid 0, rejects group/other access bits (`0o077` mask for `key`, `0o177` for `key.bak`), then opens with `O_NOFOLLOW` to defeat a post-stat swap. A failed check falls through to the next candidate exactly as a missing file does.
- **JSON load** (`state.json`, `users.json`): both structs deserialize with `#[serde(deny_unknown_fields)]` (schema drift / hostile extra keys are rejected loudly, not silently dropped), and both loaders refuse a file whose mode isn't exactly `0600`. `save()` on both paths already writes `0600`, so the happy path is unchanged; a tampered or group-readable file stops the daemon with a clear error instead of being trusted.

**Device node (`/dev/r503`).** `dist/70-r503.rules` sets `OWNER="root" GROUP="root" MODE="0600"` on every matching rule, so the underlying `ttyACM*`/`ttyUSB*` is root-only rather than the distro default `0660 root:dialout`. The daemon (root, granted the device by the systemd unit's `DeviceAllow`) opens it with `.exclusive(true)` (`TIOCEXCL` + `flock`). Net: no non-root process can open the device, and no second opener can race the daemon (2026-05-28 audit, finding H1).

### 13.7 Failure modes

| Failure | Detection | Wire response | Recovery |
|---|---|---|---|
| MAC mismatch on incoming command | Firmware constant-time compare fails | `ERR mac_invalid` (unauthenticated; no MAC to bind to) | Daemon logs and surfaces `framing_rejected` to caller (pam_fprintd typically retries) |
| Frame too short / bad suffix / bad leader / bad mac hex / bad counter token | Firmware `verify_command_frame` returns the corresponding status | `ERR frame_too_short` / `bad_frame_suffix` / `bad_frame_leader` / `bad_mac_hex` / `bad_counter` | Same |
| Counter regression (replay) | Firmware: `incoming <= last_seen` | `ERR replay` | Same. If chronic (host's state.json got rolled back), wipe + re-pair |
| Unframed command sent to paired Nano | Firmware: line doesn't start with `C ` and isn't `ping`/`status` | `ERR mac_required` | Daemon shouldn't have done this; indicates a bug or a v1 client talking to a paired Nano |
| Pair command on already-paired Nano | Firmware: `ee_is_paired() == true` | `ERR already_paired` | `r503d --unpair` first, then re-pair |
| Unpair command on unpaired Nano | Firmware: `ee_is_paired() == false` | `ERR not_paired` | Nothing — already in desired state |
| Daemon-side MAC mismatch on response | Daemon's `verify_response` fails | Daemon errors the in-flight call; logged | Caller (pam_fprintd) typically retries once |
| Daemon-side counter or seq mismatch | Daemon checks `R <ctr> <seq>` vs expected | Same | Same |
| Host key file lost (no backup) | Daemon start: `keystore::load_key()` returns None on a paired Nano | Daemon proceeds in unframed mode, all commands fail with `mac_required` from firmware; PAM sees errors | Reflash-to-wipe + re-pair (§13.5) |
| Host state.json lost | Daemon start: `state::load()` returns Ok(None) | Daemon defaults to `next_cmd_counter = 1`. On first send, firmware accepts if `1 > last_seen`; otherwise `ERR replay` | Run `r503d --resync`: reads the Nano's `last_seen` from a `status` query and sets the host counter to `last_seen + 1`, no re-pair needed. `--status` prints a hint when it detects this state. |
| Nano EEPROM ring all-CRC-fail (extreme bit-rot or fresh chip without prior pairing) | Firmware scan returns `any_valid=false` | `last_seen` reads as 0; daemon's counter > 0 will be accepted | Self-healing on first successful command |
| R503 sensor doesn't respond on first `info` after boot | Firmware: `finger.verifyPassword()` returns false | Framed `ERR sensor_unreachable` | Daemon retries; usually transient (SoftwareSerial timing on cold boot) |
| Inbound line exceeds 4096 bytes with no newline (glitchy firmware, or a co-opener that slipped past the exclusive lock) | Daemon: `read_line` cap | `SensorError::Protocol` after clearing the RX buffer + flushing the kernel input queue | Caller decides to retry or fail; bounds RAM growth (2026-05-28 audit / M1) |
| Key / `state.json` / `users.json` present but symlinked, non-root-owned, or not mode `0600` | Daemon load-time guard | Key file: ignored (falls through). state/users: daemon refuses to start with a clear error | `chmod 0600` the file, or delete it to start fresh (2026-05-28 audit / M2, M3) |
| MAC-verified framed command whose inner body is ≥ 96 bytes | Firmware: length check after counter commit | Unframed `ERR frame_body_too_long` (counter already committed, so no replay) | None needed today — no real command is that long; the body is rejected, never silently truncated (2026-05-28 audit / M4) |

**Errors the firmware emits for framing failures are intentionally unframed.** They have no agreed counter to bind a response MAC to. The daemon distinguishes them by the leading `R `: anything else is treated as a firmware-side rejection and surfaced as `SensorError::Command { code: "framing_rejected", detail }`.

### 13.8 Migration from v1 plaintext

**Hard cutover, no compatibility window.** A "downgrade to plaintext" capability would itself be an attack vector — strip it from the protocol entirely. v1 was an early-development prototype with one known deployment (the author's desk) at the time of cutover; no installed base to preserve.

**Versioning:** firmware `fw=0.4` → `fw=1.0`, daemon `r503d 0.1.0` → `1.0.0`. Mixed versions detect the mismatch at sensor open: the paired firmware rejects any unframed command other than `ping`/`status` with `ERR mac_required`, and the v1 daemon doesn't know how to frame, so the failure is loud and immediate.

**EEPROM format version** also bumps: `fmt=1` (used briefly during Milestone C development with CRC-8) → `fmt=2` (CRC-16-CCITT cells). Any Nano with old-format EEPROM contents fails `ee_is_paired()` on the new firmware and is silently treated as unpaired — clean forced re-pair on first boot of `fw=1.0`.

### 13.9 Implementation status

**Implemented:**
- All of §13.2 (crypto), §13.3 (frame format), §13.4 (counter rules), §13.5 (pairing flow), §13.6 (host state), §13.7 (failure modes), §13.8 (migration).
- Constant-time MAC comparison both sides.
- Atomic state file writes.
- Wear-leveled counter ring with CRC-16 integrity.
- Reflash-to-wipe sketch (`firmware/r503fp_wipe/`).
- `r503d --pair / --unpair / --status / --resync` CLI surface.
- `r503d --resync`: recover a lost/rolled-back `state.json` without re-pairing — reads the Nano's `last_seen` from a `status` query and sets the host counter to `last_seen + 1` (`pairing::run_resync`). `--status` prints a hint when it detects paired-with-key-but-no-state.
- USB unplug/replug recovery: `SensorActor` reopens the port, re-applies auth (key + counter reloaded from state.json), continues. Tested implicitly during dev.
- 2026-05-28 adversarial-audit hardening: root-only `/dev/r503` + explicit exclusive open (H1), bounded `read_line` (M1), `O_NOFOLLOW`/owner/mode guards on key load (M2), `deny_unknown_fields` + `0600` mode-verify on JSON load (M3), firmware body-length reject (M4), pinned `PATH` in `reseal-tpm.sh` (M5), plus the LOW-severity hygiene items. One commit per validated finding; see the validation report.

**Implementation footprint (actual, not the original budget):**

| Component | Lines |
|---|---:|
| `firmware/r503fp/siphash.h` | ~80 |
| `firmware/r503fp/framing.h` (including hex helpers + format_u64 + parse_u64 + MAC compute) | ~210 |
| `firmware/r503fp/eeprom.h` (including CRC-16) | ~150 |
| `firmware/r503fp/r503fp.ino` additions (LineFramer + process_line + handlers) | ~250 |
| `firmware/r503fp_wipe/r503fp_wipe.ino` | ~40 |
| **Firmware total added** | **~730** |
| `pcside/daemon/src/crypto.rs` | ~150 incl. tests |
| `pcside/daemon/src/framing.rs` | ~290 incl. tests |
| `pcside/daemon/src/keystore.rs` | ~140 incl. tests |
| `pcside/daemon/src/pairing.rs` | ~250 |
| `pcside/daemon/src/state.rs` | ~85 incl. tests |
| `sensor.rs` / `sensor_actor.rs` / `main.rs` deltas | ~150 |
| **Daemon total added** | **~1,065** |

**Footprint on the Nano (`fw=1.0`):** 70% of flash (21,674 / 30,720 bytes), 36% of SRAM (741 / 2,048 bytes) — measured with `arduino-cli compile --fqbn arduino:avr:nano:cpu=atmega328` after the 2026-05-28 audit hardening (the body-length reject of finding M4 added the handful of bytes over the original ~21,290).

**Not implemented, on the roadmap (§13.11):**
- `degraded=true` banner field for EEPROM-ring-all-corrupted edge case.
- Round-trip latency measurement (claimed budget was <10 ms vs v1 baseline; not actually benchmarked).

### 13.10 Testing

**Unit tests (run in CI via `cargo test`):**
- SipHash-2-4 against published Aumasson vectors (lengths 0, 1, 8, 15) + determinism + key/message distinctness + block-boundary sensitivity — `crypto.rs` 10 tests.
- Frame encode/decode round-trips, multi-space body, domain separation between command/response MACs, tampered body/counter/MAC rejection, malformed-frame rejection, wrong-leader rejection — `framing.rs` 12 tests.
- Hex round-trip + parse rejection edges — `keystore.rs` 4 tests.
- State JSON round-trip — `state.rs` 2 tests.

**Cross-implementation tests** (require the Nano):
- `pcside/daemon/examples/framing_xverify.rs` (pre-cutover) — 31 input cases: empty, sub-block, block-boundary, multi-block, randomized — firmware and daemon SipHash MACs match bit-for-bit. Also exercises bidirectional framing (daemon encodes → firmware parses → firmware encodes → daemon parses) with 4 tamper variants rejected.
- `pcside/daemon/examples/tamper_test.rs` (post-cutover) — drives the firmware via the production framing module: valid frame → accepted, replay → `ERR replay`, MAC bit-flip → `ERR mac_invalid`, counter regression → `ERR replay`, valid recovery frame → accepted.

**System / integration:**
- EEPROM persistence + wear-leveling: 13 assertions including DTR-power-cycle survival and predicted cell distribution after 20 counter bumps — `eeprom_xverify.py`.
- End-to-end pairing flow: 10 stages from prep → opt-in gate → pair → permissions check → re-pair → fprintd-verify regression — `pairing_e2e.sh`.
- PAM `fprintd-verify mat` on the authenticated channel: 5/5 consecutive matches, counter advancing as expected.

**Reviewed by:**
- Multi-pass review by the project author (Mat), 2026-05-28. Five layers covered (crypto primitive, wire framing, EEPROM ring, TPM seal, daemon lifecycle); 10 findings (1 P1 DOS in the host wire parser, 2 P2 RAM-leak / parser-strictness, 7 P3 defence-in-depth) all addressed on `feat/crypto-posture-upgrade`. Full report and methodology: [`docs/REVIEW-2026-05-28.md`](../docs/REVIEW-2026-05-28.md).
- Cross-implementation property test against the third-party `siphasher` crate (`pcside/daemon/tests/crossimpl_siphash.rs`, 1024 random vectors).
- Stable-Rust property fuzzer on the wire parsers, ~135 000 inputs per CI run, no panics (`pcside/daemon/tests/fuzz_framing_smoke.rs`).
- `cargo fuzz` libFuzzer target available at `pcside/daemon/fuzz/` for long-corpus passes on nightly.
- `cargo audit` (RustSec) on every CI run, no advisories at time of this review.

**Not yet done:**
- Physical EEPROM wear-out simulation on a sacrificial Nano (the per-cell write distribution is verified analytically and via the 20-bump test in `eeprom_xverify.py`).
- Round-trip latency measurement under load.
- Paid third-party cryptographic audit (the multi-pass review above is documented evidence, not an external firm's report).
- TPM userAuth PIN gate (PolicyPCR + PolicyAuthValue) — PCR-list parameterisation shipped in §13.12; PIN is a tracked follow-up.

### 13.11 Known limitations and future work

- **Single Nano = single point of failure.** If the Nano dies, login via this path is gone until you reflash a spare. Keep a second authentication method enabled (password). The R503 templates live on the sensor itself, so if you transplant the R503 onto a fresh Nano you'd still need to enroll all fingers again unless you transferred the EEPROM somehow.
- **State.json loss is recoverable without re-pairing.** If `state.json` is lost or rolled back while the firmware still has a high `last_seen`, the daemon hits `ERR replay` on its first send. Recovery is `r503d --resync`: it reads `last_seen` from a `status` query and sets the local counter to `last_seen + 1`. The `status` reply is unauthenticated, but resync can only move the host counter *forward* to match what the Nano already committed — a lying MITM can at worst cause a self-inflicted `ERR replay` (which it could already do by garbling frames), never make an old frame replayable. (`pairing::run_resync`; `--status` hints when it detects the paired-but-no-state condition.)
- **No `degraded=true` banner.** The EEPROM all-CRC-fail edge case currently silently degrades to `last_seen = 0`. Should expose this via the boot banner so the daemon can refuse to operate instead of accepting whatever the host sends.
- **Hand-rolled SipHash, no paid third-party audit.** The implementations are short, KAT-verified against published Aumasson vectors, cross-validated against the third-party `siphasher` crate on 1024 random vectors (`pcside/daemon/tests/crossimpl_siphash.rs`), and the firmware runs a boot-time on-device KAT self-test that halts the channel if the primitive diverges. A paid external audit would still catch things this combined evidence doesn't. PRs from people who do this professionally are welcome.
- **TPM seal is opt-in, not default.** Hosts without a TPM2 device, or hosts where the operator hasn't run `--pair --seal-tpm`, still keep the key as plaintext on disk per §13.6. Defaulting on once the TPM path has more bake-in is on the roadmap.
- **No firmware-side fuzzing.** The host-side wire parsers are property-fuzzed on every CI run (`pcside/daemon/tests/fuzz_framing_smoke.rs`, ~135 000 inputs covering random / mutated / round-trip cases — the same harness that found the P1 UTF-8-boundary panic listed in `docs/REVIEW-2026-05-28.md`). The firmware parser is bounds-checked, the inbound line is length-capped at exactly 128 chars (`inbuf` overflow; the off-by-one of audit finding L4 is fixed), and a MAC-verified inner command body of ≥ 96 bytes is rejected rather than silently truncated (audit M4). A dedicated AVR-side fuzz harness would still close the analogous DOS angle on the device.
- **CH340-based Nano clones have a fixed USB VID/PID.** The daemon can't tell "the right Nano" from "any Nano" without looking at the udev-stable `/dev/r503` symlink (set up by the project's `70-r503.rules`). A genuine Nano (ATmega16U2 USB chip) or a Pro Micro (ATmega32U4 native USB) would allow a custom `iProduct` string for stronger identification. Not blocking.

### 13.12 Host key sealing to TPM2 (opt-in)

**Status: implemented behind `r503d --pair --seal-tpm`.** Adds a TPM2-sealed copy of the SipHash key at `/var/lib/r503d/key.tpm`, replacing the plaintext `key` / `key.bak` files. The seal binds the key to **PCR7** (Secure Boot policy and keys), so the key only unwraps on the same physical machine running with the same Secure Boot configuration.

**Threat closed.** §13.1 explicitly carves out "host root compromise" as out-of-scope (root can always read `/var/lib/r503d/key`), but the plaintext file is also readable in scenarios that *don't* require booting the OS:

- Stolen laptop with SSD pulled and `dd`'d on an attacker's host.
- Cold-boot image-and-revert against a parked machine.
- Offline filesystem-level access via any path that doesn't have to satisfy PAM (rescue mode, USB boot, Live ISO with chroot).

With the key sealed, those scenarios get ciphertext. The unwrap key never leaves the TPM, and the TPM only releases it when current PCR values match the policy baked into the sealed object at pairing time.

**PCR choice: PCR7 by default; `--seal-tpm-pcrs=<list>` opts into additional PCRs.** PCR7 measures Secure Boot policy and the keys that signed the booted EFI binaries. It survives kernel and initrd updates (those don't change SB policy), survives `fwupd` UEFI firmware updates (those measure into PCR0, not PCR7), and survives `dnf upgrade` of grub2/shim. It only changes when:

- Secure Boot is turned off or back on.
- A new MOK key is enrolled.
- The SB key database is edited from the UEFI firmware UI.
- The disk (or SSD) is moved to a different machine with a different SB configuration.

Each of those is something the operator deliberately did or had done to them — exactly the events we want to invalidate the seal for. PCR0 / PCR4 / PCR8 are intentionally not bound by default, on the principle that operational pain that doesn't buy security is just pain.

**Binding additional PCRs (advanced).** `r503d --pair --seal-tpm --seal-tpm-pcrs=<list>` and the matching `dist/reseal-tpm.sh --pcrs <list>` accept a comma-separated list of PCR indices in the SHA256 bank:

- `7,11` — PCR7 + PCR11 (systemd-stub UKI measurement, binds kernel+initrd hash). Any kernel update requires re-running `reseal-tpm.sh` to re-seal against the new measurement.
- `0,4,7` — Adds PCR0 (UEFI firmware / CRTM) and PCR4 (bootloader / shim). Useful on machines where firmware updates should also invalidate the seal.
- `7` — the default; equivalent to omitting the flag.

The PCR list is encoded into the sealed blob (on-disk format bumps from `R503TPM\x01` to `R503TPM\x02` when used; existing `\x01` blobs continue to load as PCR7-only) so `unseal_key` reconstructs the same policy automatically — no operator state needs to be remembered separately.

**Failure mode.** When PCR7 changes between pair time and boot time, `TPM2_Unseal` returns `TPM_RC_POLICY_FAIL`. The daemon refuses to start with a journal message pointing at the recovery ceremony. PAM falls back to the next configured auth method (typically password). There is **no plaintext fallback**: keeping a plaintext copy alongside the sealed blob would defeat the seal.

**Recovery (the reseal ceremony).** Run `sudo bash dist/reseal-tpm.sh`. The script:

1. Stops `r503d.service`.
2. Reflashes the Nano with `firmware/r503fp_wipe/` to clear the EEPROM (the old SipHash key on the Nano is paired to the lost host key — both sides have to forget together).
3. Reflashes the main firmware on top.
4. Creates `/etc/r503d/allow-pair`.
5. Runs `r503d --reseal-tpm`, which generates a fresh 128-bit key, pairs the freshly-wiped Nano with it, and seals the new key to **current** PCR7.
6. Starts `r503d.service`.

Wall-clock: ~90 seconds. Enrolled fingers are preserved — templates live in the R503 sensor's onboard flash, not in the Nano's EEPROM, and not on the host. The user re-logs-in with the same fingers, transparently.

**No new firmware command.** The reseal flow uses the existing reflash-to-wipe path (`firmware/r503fp_wipe/`, §13.5). The running firmware's command surface is unchanged from `fw=1.0`. The capability the wrapper script depends on — "anyone with physical USB access can reflash the Nano" — was already documented in §13.1 bullet 4 as out-of-scope. We're just using it as a deliberate recovery tool.

**Crypto details.**

- **Library:** Rust `tss-esapi` 7.x, linking against system `tpm2-tss` (`/dev/tpmrm0`, the resource-managed TPM device).
- **Primary key:** Restricted-decryption RSA-2048 on the Owner hierarchy. The Owner Primary Seed is persistent and deterministic across reboots, so the daemon recreates the same primary on each unseal — no need to persist a primary handle.
- **Sealed object:** `TPM_ALG_KEYEDHASH` with `userWithAuth = false`, `adminWithPolicy = true`. The only path to authorize the unseal is to satisfy the PCR policy.
- **Policy:** `TPM2_PolicyPCR` over `sha256:7`. Trial session at seal time computes the policy digest, real session at unseal time satisfies it against current PCR7.
- **On-disk format:** magic `R503TPM\x01` + length-prefixed `Public` (TPM2-marshalled) + length-prefixed `Private` (raw TPM2B buffer). Written atomically (`tmp → fsync → rename`) at mode `0600 root:root`.

**Implementation footprint:**

| Component | Lines |
|---|---:|
| `pcside/daemon/src/tpm.rs` | ~310 incl. tests |
| `pcside/daemon/src/keystore.rs` additions (`load_key_with_source`, `save_key_sealed`, `delete_sealed_key`, `delete_all_keys`) | ~70 |
| `pcside/daemon/src/pairing.rs` additions (`--seal-tpm` flag wiring, `run_reseal_tpm`) | ~65 |
| `pcside/daemon/src/main.rs` deltas (CLI flags + boot-time refuse-on-unseal-fail) | ~25 |
| `pcside/daemon/dist/reseal-tpm.sh` | ~110 |

**What's still out of scope.**

- PCR policy authorization (signed updatable policies, à la systemd-cryptenroll) — would let kernel updates that *do* shift PCRs (with `--seal-tpm-pcrs=7,11`) survive without a reseal. Roadmap; the existing `reseal-tpm.sh` ceremony is the workaround.
- TPM PIN (userAuth-bound seal). The operator could attach an additional `userAuth` value so that a thief who steals the running machine *and* the disk still needs a passphrase, with the TPM's own anti-hammering protection. The canonical TPM2 pattern is a chained `PolicyPCR + PolicyAuthValue` policy. UX cost is a passphrase prompt at every daemon boot (i.e. every reboot). Roadmap; not in `fw=1.0` / `r503d 1.0.0`.

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
