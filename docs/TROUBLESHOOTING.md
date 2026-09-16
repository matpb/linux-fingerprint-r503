# Troubleshooting

Lessons from the 2026-05-23 Saturday bench session that brought the R503 from "appeared dead" to "working perfectly".

## "Sensor sends 0x55 on power-up but never responds to commands"

**Root cause:** voltage divider on Uno TX → sensor RX. The R503's RX input has an internal pullup that fights a 1kΩ/2kΩ divider; the line never drops low enough to register a valid start bit.

**Symptom set:**
- Power-cycling the sensor (RED disconnect/reconnect while listener firmware runs) reliably captures `0x55` boot handshake on yellow → D2
- All command attempts (Adafruit_Fingerprint or hand-crafted) get zero response bytes
- No LED ring on power-up (LED control needs a command, not autonomous)
- Touch detection (blue / WAKEUP) toggles correctly on finger touch

**Fix:** Remove the divider entirely. Connect brown directly to Uno D3. The R503's RX is 5V-tolerant in practice despite the "3.3V TTL" datasheet specification.

## "Touch detection seems to work even though sensor is otherwise dead"

The R503 contains two pieces of silicon: a main fingerprint MCU (red wire / V_main) and an autonomous capacitive-touch IC (white wire / V_touch / 5µA always-on). They are independent. Touch detection working tells you nothing about the main MCU being alive.

To confirm the main MCU is alive, listen on D2 while power-cycling the sensor — a working sensor sends `0x55` ~50ms after power-up.

## "WAKEUP pin appears to read finger touches without the sensor being powered correctly"

Before fixing the sensor's GND, the WAKEUP signal (blue) read `HIGH` whenever the user's finger was near the sensor. This was **not** the sensor detecting touch — it was the Uno's D4 input floating with capacitive coupling to the body. Without sensor GND, the sensor's WAKEUP output isn't defined.

Always verify sensor GND is electrically connected before trusting any signal from the sensor.

## "Yellow (sensor TX) idles at ~2.6V instead of the expected 3.3V"

This is **normal** for the R503. The sensor's TX line plus Uno's internal 50kΩ pullup on D2 (when SoftwareSerial RX is initialized) reaches equilibrium around 2.6V at idle. The sensor still drives the line cleanly during transmission. The 2.6V is not a sign of damage; it's the resting state of the divider formed by sensor leakage and Uno pullup.

## "Multimeter can't read through silicone insulation"

Yes. Silicone is too good an insulator. To test wire continuity, you must access bare metal at both ends. If wires are encased in hot glue at the sensor end (most R503s ship like this), you can only test from the breadboard side back to your own connectors. Don't waste time trying to probe through insulation.

## "SoftwareSerial loopback (jumper D2 to D3) doesn't work even with a known-good Uno"

SoftwareSerial is **half-duplex**. It disables interrupts during TX, so the RX interrupt can't fire to catch the byte coming back on the same chip. Loopback tests on a single SoftwareSerial instance are physically impossible and tell you nothing about whether SoftSerial works.

To test the Uno's SoftSerial independently, measure TX voltage during continuous transmission of a known pattern (e.g. 0x55 spam → D3 reads ~2.5V average for 50% duty) and verify RX pullup behavior (~Vcc with no input).

## "Wiring works but sensor seems dead"

Before anything else, **verify sensor GND with a multimeter** end-to-end. "I plugged it in" is not proof. On 2026-05-23 we wasted ~90 minutes debugging sensor symptoms because the sensor's black wire was floating (not in the breadboard's GND rail). Touch detection, UART, and LED control all behave erratically without proper GND.

## "Fingerprint login stopped working after a routine system update"

**Root cause:** the TPM-sealed host key is bound to a PCR policy (PCR7 by default, SPEC §13.12) and the boot state no longer matches. `TPM2_Unseal` returns `TPM_RC_POLICY_FAIL` (`0x99d`), `r503d` refuses to start, and PAM falls back to password — quietly, unless the alerting below is installed.

**Symptom set:**
- `systemctl status r503d` shows the unit failed or restarting
- `journalctl -u r503d` contains `Esys_Unseal() ... ErrorCode (0x0000099d)` and `FATAL: TPM-sealed key present but could not be unsealed`
- The sensor's LED never lights at the login or lock screen
- `sudo` and unlock still work, by password

**The suspect is almost never the kernel.** PCR7 is not extended by kernel or initrd updates. It *is* extended by the Secure Boot variables (`SecureBoot`, `PK`, `KEK`, `db`, `dbx`), and `fwupd` ships `db`/`dbx`/`KEK` updates from LVFS through ordinary unattended desktop updates — usually in the same batch as a kernel, which is what makes the kernel look guilty.

**Diagnose:**

```bash
fwupdmgr get-history          # look for UEFI dbx / UEFI CA / KEK CA entries near the failure date
mokutil --sb-state            # Secure Boot on or off changes what PCR7 is worth
sudo tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements | grep -A2 'PCRIndex: 7'
```

**Fix, in order of preference:**

1. If the key is still readable (the daemon was running before you stopped it), re-seal it in place — seconds, and the Nano is never touched:

   ```bash
   sudo systemctl stop r503d
   sudo r503d --reseal-policy            # drops PCR binding; --seal-tpm-pcrs 7 keeps it
   sudo systemctl start r503d
   ```

2. If the key is already unrecoverable, only the full ceremony works, because the firmware will not re-pair while paired and `unpair` needs a valid MAC:

   ```bash
   sudo bash pcside/daemon/dist/reseal-tpm.sh
   ```

   Enrolled fingers survive either path — templates live on the R503's own flash.

**Stop it happening silently.** The daemon exits `78` on an unrecoverable unseal; `r503d.service` sets `RestartPreventExitStatus=78` so it fails fast instead of crash-looping, and `OnFailure=r503d-alert.service` pushes a desktop notification. Without those, a broken seal can sit unnoticed for days.

## "`fprintd-verify` says verify-no-match but the journal shows a confident match"

`fprintd-verify` with no `-f` picks one specific finger. If you present a different one, `r503d` logs a genuine match and then rejects it for being the wrong slot:

```
VerifyStart user=... selected=left-index-finger expected={3}
verify done slot=5 confidence=183 accepted=false
```

That output is good news: a `slot=N confidence=NNN` line proves the authenticated v2 channel is healthy, since a bad or unsealable key fails at the MAC long before any matching happens. Check the name→slot map in `/var/lib/r503d/users.json` — the order `fprintd-verify` prints when listing enrolled fingers is **not** slot order — then re-run with the right finger:

```bash
fprintd-verify -f right-index-finger "$USER"
```
