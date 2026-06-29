//! Pairing flows for the v2 authenticated channel (SPEC §13.5).
//!
//! Three CLI entry points (all run synchronously inside the tokio main):
//!   `r503d --pair`    — generate a fresh 128-bit key, send to Nano, persist.
//!                       Requires /etc/r503d/allow-pair as host-side opt-in.
//!   `r503d --unpair`  — wipe the Nano's EEPROM and delete the host key.
//!                       Authenticates by passing the current key as proof
//!                       (transitional; Milestone E wraps this in MAC framing).
//!   `r503d --status`  — print pairing state from both sides without mutating.
//!
//! Each flow opens the serial port directly (not via SensorActor) so the
//! daemon must be stopped first: `systemctl stop r503d && r503d --pair`.

#![allow(dead_code)]

use std::io::{ErrorKind, Read, Write};
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serialport::SerialPort;

use crate::framing;
use crate::keystore;
use crate::sensor;
use crate::state;

const BAUD: u32 = 115_200;

// ----- port handling -----

struct Link {
    port: Box<dyn SerialPort>,
    rx: Vec<u8>,
}

/// Human-facing context attached to a reply-timeout error. Takes only the
/// non-secret `label` (e.g. `pair`, `unpair`, `status`) — NEVER the wire bytes,
/// which may carry the 128-bit key or a MAC tag. Single source of truth for the
/// timeout message so the redaction can be asserted by `cargo test` alone.
fn timeout_context(label: &str) -> String {
    format!("timeout reading reply to: {}", label)
}

impl Link {
    fn open(path: &str) -> Result<Self> {
        // .exclusive(true) is the serialport-4.x POSIX default; setting it
        // explicitly keeps the TIOCEXCL + LOCK_EX guarantee visible at the
        // call site and pins us against a future crate-default flip
        // (security audit 2026-05-28 / H1).
        let port = serialport::new(path, BAUD)
            .timeout(Duration::from_millis(200))
            .exclusive(true)
            .open()
            .with_context(|| format!("opening {}", path))?;
        let mut link = Link {
            port,
            rx: Vec::new(),
        };
        // Retry ping until OK pong (covers both cold DTR-reset boot and warm
        // re-open). Up to 8s total.
        let deadline = Instant::now() + Duration::from_secs(8);
        let mut last: Option<String> = None;
        while Instant::now() < deadline {
            link.rx.clear();
            let _ = link.port.clear(serialport::ClearBuffer::Input);
            link.port.write_all(b"ping\n")?;
            link.port.flush()?;
            let per_attempt = Instant::now() + Duration::from_millis(800);
            loop {
                let remaining = per_attempt.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                match link.read_line(remaining)? {
                    Some(line) if line == "OK pong" => return Ok(link),
                    Some(line) => {
                        last = Some(line);
                    }
                    None => break,
                }
            }
        }
        bail!("could not sync with firmware; last line seen: {:?}", last)
    }

    /// Send a non-secret command whose text is safe to echo in errors/logs
    /// (e.g. `status`, `ping`). The command string doubles as its own label.
    fn cmd(&mut self, cmd: &str, timeout: Duration) -> Result<String> {
        self.cmd_labeled(cmd, cmd, timeout)
    }

    /// Send `wire` bytes to the Nano, but use `label` (never `wire`) in any
    /// error/log text. Callers that put key material on the wire — the `pair`
    /// bootstrap (a literal `pair <key-hex>`) and the MAC-framed `unpair`
    /// (the frame embeds the SipHash tag) — MUST route through this with a
    /// constant, secret-free label so a reply timeout can never interpolate
    /// the secret into the anyhow chain that `main` prints to stderr / the
    /// journal (security audit 2026-05-28 / L-pairing-key-in-error).
    fn cmd_labeled(&mut self, wire: &str, label: &str, timeout: Duration) -> Result<String> {
        self.rx.clear();
        let _ = self.port.clear(serialport::ClearBuffer::Input);
        self.port.write_all(wire.as_bytes())?;
        self.port.write_all(b"\n")?;
        self.port.flush()?;
        let deadline = Instant::now() + timeout;
        loop {
            let line = self
                .read_line(deadline.saturating_duration_since(Instant::now()))?
                .with_context(|| timeout_context(label))?;
            if line.is_empty() || line.starts_with("PROGRESS ") {
                continue;
            }
            return Ok(line);
        }
    }

    fn read_line(&mut self, max_wait: Duration) -> Result<Option<String>> {
        let deadline = Instant::now() + max_wait;
        loop {
            if let Some(nl) = self.rx.iter().position(|&b| b == b'\n') {
                let mut line: Vec<u8> = self.rx.drain(..=nl).collect();
                line.pop();
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                return Ok(Some(String::from_utf8_lossy(&line).into_owned()));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            self.port.set_timeout(Duration::from_millis(100)).ok();
            let mut buf = [0u8; 256];
            match self.port.read(&mut buf) {
                Ok(0) => {}
                Ok(n) => self.rx.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == ErrorKind::TimedOut => {}
                Err(e) => return Err(e.into()),
            }
        }
    }
}

// ----- status parsing -----

#[derive(Debug, Clone)]
pub struct FirmwareStatus {
    pub paired: bool,
    pub counter: u64,
    pub fmt: u8,
    pub fw: String,
}

fn parse_status(line: &str) -> Result<FirmwareStatus> {
    let body = line
        .strip_prefix("OK ")
        .ok_or_else(|| anyhow::anyhow!("status reply missing OK: {:?}", line))?;
    let mut paired = None;
    let mut counter = None;
    let mut fmt = None;
    let mut fw = None;
    for tok in body.split_whitespace() {
        if let Some((k, v)) = tok.split_once('=') {
            match k {
                "paired" => paired = Some(v == "true"),
                "counter" => counter = v.parse().ok(),
                "fmt" => fmt = v.parse().ok(),
                "fw" => fw = Some(v.to_string()),
                _ => {}
            }
        }
    }
    Ok(FirmwareStatus {
        paired: paired.ok_or_else(|| anyhow::anyhow!("status missing paired"))?,
        counter: counter.ok_or_else(|| anyhow::anyhow!("status missing counter"))?,
        fmt: fmt.ok_or_else(|| anyhow::anyhow!("status missing fmt"))?,
        fw: fw.ok_or_else(|| anyhow::anyhow!("status missing fw"))?,
    })
}

// ----- flows -----

pub fn run_status(port_override: Option<&str>) -> Result<()> {
    let port_path = match port_override {
        Some(p) => p.to_string(),
        None => sensor::find_port().context("locating R503 serial port")?,
    };
    let mut link = Link::open(&port_path)?;
    let raw = link.cmd("status", Duration::from_secs(1))?;
    let fw_status = parse_status(&raw)?;
    let host_key_present = Path::new(keystore::KEY_PATH).exists();
    let host_bak_present = Path::new(keystore::KEY_BAK_PATH).exists();
    let host_tpm_present = Path::new(keystore::KEY_TPM_PATH).exists();
    let allow_pair = keystore::allow_pair_present();
    let tpm_device = crate::tpm::device_present();

    println!("port:             {}", port_path);
    println!(
        "firmware:         fw={} fmt={}",
        fw_status.fw, fw_status.fmt
    );
    println!("firmware paired:  {}", fw_status.paired);
    println!("firmware counter: {}", fw_status.counter);
    println!(
        "host key.tpm:     {}",
        if host_tpm_present {
            keystore::KEY_TPM_PATH
        } else {
            "(absent)"
        }
    );
    println!(
        "host key:         {}",
        if host_key_present {
            keystore::KEY_PATH
        } else {
            "(missing)"
        }
    );
    println!(
        "host key.bak:     {}",
        if host_bak_present {
            keystore::KEY_BAK_PATH
        } else {
            "(missing)"
        }
    );
    println!(
        "tpm device:       {}",
        if tpm_device {
            crate::tpm::TPM_DEVICE
        } else {
            "(absent)"
        }
    );
    println!(
        "allow-pair:       {}",
        if allow_pair {
            keystore::ALLOW_PAIR_PATH
        } else {
            "(absent)"
        }
    );

    let host_has_key = host_key_present || host_bak_present || host_tpm_present;
    match (fw_status.paired, host_has_key) {
        (true, false) => {
            println!("\nWARNING: firmware paired but no host key. Re-pair or reflash-to-wipe.")
        }
        (false, true) => println!(
            "\nWARNING: host key present but firmware unpaired. Stale key — `--unpair` cannot succeed; delete host files manually."
        ),
        _ => {}
    }
    if host_tpm_present && (host_key_present || host_bak_present) {
        println!(
            "\nWARNING: both sealed and plaintext key files present. Sealed takes priority; \
            the plaintext copies are stale and should be removed."
        );
    }
    // Paired + keyed but no host counter state ⇒ the next framed command would
    // hit ERR replay. Point the operator at the cheap recovery (SPEC §13.11).
    let host_state_present = Path::new(state::STATE_PATH).exists();
    if fw_status.paired && host_has_key && !host_state_present {
        println!(
            "\nNOTE: paired with a host key but {} is missing — the next command \
             would hit ERR replay. Run `r503d --resync` to recover the counter \
             without re-pairing.",
            state::STATE_PATH
        );
    }
    Ok(())
}

pub fn run_pair(
    port_override: Option<&str>,
    seal_tpm: bool,
    seal_tpm_pcrs: Option<&str>,
) -> Result<()> {
    if !keystore::allow_pair_present() {
        bail!(
            "host opt-in missing: create {} to authorize pairing\n\
             (this gate defeats the attacker-races-to-pair scenario; see SPEC §13.5)",
            keystore::ALLOW_PAIR_PATH
        );
    }
    // Sanity check the TPM up front: it's better to bail BEFORE wiping the
    // allow-pair gate / mutating the Nano than to discover at save-time that
    // the daemon was running on a host without a TPM.
    if seal_tpm && !crate::tpm::device_present() {
        bail!(
            "--seal-tpm requested but {} not present on this host",
            crate::tpm::TPM_DEVICE
        );
    }

    let port_path = match port_override {
        Some(p) => p.to_string(),
        None => sensor::find_port().context("locating R503 serial port")?,
    };
    let mut link = Link::open(&port_path)?;
    let pre = parse_status(&link.cmd("status", Duration::from_secs(1))?)?;
    if pre.paired {
        bail!("Nano already paired; run `--unpair` first or reflash-to-wipe");
    }

    let key = keystore::generate_key().context("generating 128-bit key from /dev/urandom")?;
    let key_h = keystore::key_hex(&key);
    // Close the allow-pair gate BEFORE sending the key (SPEC §13.5 / audit
    // §P1-1). If the daemon crashes between the Nano accepting the key and
    // the host persisting it, the next `--pair` attempt would otherwise be
    // racetable by a hostile Nano replacement. With the gate closed first,
    // any recovery path requires admin to recreate the opt-in marker
    // explicitly. Cost: a legitimate failure mid-flow (USB hiccup, Nano
    // refusal) requires `--unpair` + `touch /etc/r503d/allow-pair` to retry.
    keystore::remove_allow_pair().context("closing allow-pair gate before sending key")?;

    // Wire bytes carry the fresh 128-bit key; the label must not, so a reply
    // timeout cannot leak the key into the error chain (audit L-pairing-key).
    let reply = link.cmd_labeled(&format!("pair {}", &*key_h), "pair", Duration::from_secs(2))?;
    if reply != "OK paired" {
        bail!("Nano refused pair: {:?}", reply);
    }
    // Re-query to confirm the firmware actually persisted.
    let post = parse_status(&link.cmd("status", Duration::from_secs(1))?)?;
    if !post.paired {
        bail!("paired ok but status still reports paired=false — EEPROM not committed?");
    }

    if seal_tpm {
        let pcrs = match seal_tpm_pcrs {
            Some(s) => crate::tpm::parse_pcr_list(s).context("parsing --seal-tpm-pcrs")?,
            None => vec![7],
        };
        keystore::save_key_sealed_with_pcrs(&key, &pcrs).with_context(|| {
            format!(
                "sealing host key to TPM (PCRs {:?}) and writing key.tpm",
                pcrs
            )
        })?;
    } else {
        keystore::save_key(&key).context("saving host key")?;
    }
    // Fresh state: client counter starts at 1 (Nano's last_seen is 0 post-pair).
    state::save(&state::State::fresh()).context("initializing client counter state")?;

    println!(
        "paired: fw={} fmt={} counter={}",
        post.fw, post.fmt, post.counter
    );
    if seal_tpm {
        let pcrs_label = seal_tpm_pcrs.unwrap_or("7");
        println!(
            "host key SEALED to TPM (PCRs {}); blob at {} (mode 0600)",
            pcrs_label,
            keystore::KEY_TPM_PATH
        );
        println!(
            "plaintext key + .bak removed — recovery via \
             `sudo dist/reseal-tpm.sh --pcrs {}` if any bound PCR changes",
            pcrs_label
        );
    } else {
        println!("host key written to {} (mode 0600)", keystore::KEY_PATH);
        println!("backup written to {} (mode 0400)", keystore::KEY_BAK_PATH);
    }
    println!(
        "state initialized at {} (next_cmd_counter=1)",
        state::STATE_PATH
    );
    println!(
        "opt-in marker {} closed before key send",
        keystore::ALLOW_PAIR_PATH
    );
    Ok(())
}

/// Reseal recovery flow (SPEC §13.12). Assumes the Nano's EEPROM has been
/// wiped externally (reflash-to-wipe + reflash of main firmware) — this is
/// what `dist/reseal-tpm.sh` does before invoking us.
///
/// Difference vs `--pair --seal-tpm`: also purges any stale plaintext key,
/// stale TPM blob, and stale counter state up front. The old host key is
/// unrecoverable (that's the whole reason we're here), so there's nothing to
/// preserve.
pub fn run_reseal_tpm(port_override: Option<&str>, seal_tpm_pcrs: Option<&str>) -> Result<()> {
    if !crate::tpm::device_present() {
        bail!(
            "no TPM device present at {} — nothing to reseal against",
            crate::tpm::TPM_DEVICE
        );
    }
    if !keystore::allow_pair_present() {
        bail!(
            "host opt-in missing: create {} before reseal\n\
             (the reseal flow re-pairs the Nano with a fresh key; same gate as --pair)",
            keystore::ALLOW_PAIR_PATH
        );
    }

    let port_path = match port_override {
        Some(p) => p.to_string(),
        None => sensor::find_port().context("locating R503 serial port")?,
    };
    // Probe the Nano's pairing state, then DROP the port before `run_pair`:
    // run_pair re-opens the same device with `.exclusive(true)` (TIOCEXCL +
    // flock LOCK_EX), so holding `link` open across the call would deadlock the
    // reseal against its own exclusive lock — "Unable to acquire exclusive lock
    // on serial port". It only bites when the Nano is freshly wiped
    // (pre.paired == false), i.e. every real reseal. Scoping `link` to this
    // block releases the fd (and the lock) as soon as the status read returns.
    let pre = {
        let mut link = Link::open(&port_path)?;
        parse_status(&link.cmd("status", Duration::from_secs(1))?)?
    };
    if pre.paired {
        bail!(
            "Nano still reports paired=true — the reseal flow expects a wiped Nano.\n\
             Run `dist/reseal-tpm.sh` instead of calling --reseal-tpm directly, \
             or reflash firmware/r503fp_wipe/ + firmware/r503fp/ manually first."
        );
    }

    // Stale on-disk state from the prior pairing — keys we can no longer
    // unwrap, a counter that doesn't match the freshly-wiped Nano. Drop them.
    keystore::delete_all_keys().ok();
    state::delete().ok();

    // Now the normal pair-with-seal path.
    run_pair(port_override, /*seal_tpm=*/ true, seal_tpm_pcrs)
}

/// Compute the post-resync `next_cmd_counter` from the Nano's reported
/// `last_seen`, refusing any value in the reserved ceiling band. Pure +
/// total so the keyless-MITM brick vector is unit-testable without a serial
/// port (security audit 2026-05-28 / firmware DoS-2).
fn resync_target(reported_last_seen: u64) -> Result<u64> {
    if reported_last_seen >= framing::COUNTER_CEILING - 1 {
        bail!(
            "reported counter {} is at/above the reserved ceiling",
            reported_last_seen
        );
    }
    Ok(reported_last_seen + 1)
}

/// Recover from a lost or rolled-back `state.json` while the Nano is still
/// paired and the host key still exists (SPEC §13.11).
///
/// Reads the Nano's persisted replay counter (`last_seen`) from a `status`
/// query and rewrites the host's `next_cmd_counter` to `last_seen + 1`, so the
/// daemon's next framed command is accepted instead of bouncing off the
/// firmware's `ERR replay`. Before this existed, the only recovery from a lost
/// `state.json` was a full wipe-and-re-pair.
///
/// Security: the `status` reply is unauthenticated — by definition there is no
/// agreed counter to bind a MAC to before resync. A wire-MITM could lie about
/// `counter`, but the firmware remains the sole source of truth for replay
/// rejection, so resync can only ever move the host's counter *forward* to
/// match what the Nano already committed — it cannot weaken replay protection:
///   - A too-low reported value just makes our next real command bounce as
///     `ERR replay` (a self-inflicted DoS a MITM can already cause by garbling
///     frames); no old frame becomes replayable, because the Nano's real
///     `last_seen` is unchanged.
///   - A reported value in the reserved ceiling band is REFUSED (see
///     `resync_target`). Previously it was accepted and could drive the host's
///     persisted counter to `u64::MAX`, so the next real `counter + 1` wrapped
///     to 0 and permanently desynced the channel — a MITM lying `counter=MAX`
///     during a single resync was enough (security audit 2026-05-28 /
///     firmware DoS-2). The firmware now also refuses to commit a ceiling
///     counter, so neither end can be bricked.
pub fn run_resync(port_override: Option<&str>) -> Result<()> {
    // A host key must still exist — resync recovers counter state, not the
    // pairing itself. With no key we couldn't authenticate any command anyway,
    // so the correct recovery is to re-pair, not resync.
    if keystore::load_key_with_source()
        .context("checking for a host key before resync")?
        .is_none()
    {
        bail!(
            "no host key at {} / {} / {}; --resync only recovers a lost \
             state.json while the key still exists.\n\
             With no key, re-pair instead (`--unpair` then `--pair`, or \
             reflash-to-wipe + `--pair`).",
            keystore::KEY_TPM_PATH,
            keystore::KEY_PATH,
            keystore::KEY_BAK_PATH
        );
    }

    let port_path = match port_override {
        Some(p) => p.to_string(),
        None => sensor::find_port().context("locating R503 serial port")?,
    };
    let mut link = Link::open(&port_path)?;
    let fw = parse_status(&link.cmd("status", Duration::from_secs(1))?)?;
    if !fw.paired {
        bail!(
            "Nano reports paired=false — nothing to resync against. \
             Pair first with `--pair`."
        );
    }

    // `last_seen + 1` is the lowest counter the firmware will accept next.
    // resync_target refuses a reported counter in the reserved ceiling band so
    // an unauthenticated `status` can't drive us into the brick/wrap zone.
    let new_counter = resync_target(fw.counter).with_context(|| {
        format!(
            "Nano reported counter {} in the reserved ceiling band — refusing \
             to resync (suspected MITM or corrupt EEPROM). Reflash-to-wipe \
             (firmware/r503fp_wipe) + re-pair to reset.",
            fw.counter
        )
    })?;
    let old = state::load().context("loading current client counter state")?;
    state::save(&state::State {
        next_cmd_counter: new_counter,
    })
    .context("writing resynced client counter state")?;

    match old {
        Some(s) => println!(
            "resynced: next_cmd_counter {} → {} (Nano last_seen={})",
            s.next_cmd_counter, new_counter, fw.counter
        ),
        None => println!(
            "resynced: next_cmd_counter set to {} (state was missing; Nano last_seen={})",
            new_counter, fw.counter
        ),
    }
    println!("state written to {}", state::STATE_PATH);
    println!("restart the daemon to pick up the new counter: systemctl start r503d");
    Ok(())
}

pub fn run_unpair(port_override: Option<&str>) -> Result<()> {
    let (key, source) = keystore::load_key_with_source()
        .context("loading host key for unpair")?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no host key at {} / {} / {}; cannot authenticate unpair.\n\
                 For the lost-key case, use reflash-to-wipe \
                 (firmware/r503fp_wipe/, SPEC §13.5).",
                keystore::KEY_TPM_PATH,
                keystore::KEY_PATH,
                keystore::KEY_BAK_PATH
            )
        })?;
    tracing::debug!(?source, "unpair: host key loaded");
    let port_path = match port_override {
        Some(p) => p.to_string(),
        None => sensor::find_port().context("locating R503 serial port")?,
    };
    let mut link = Link::open(&port_path)?;
    let pre = parse_status(&link.cmd("status", Duration::from_secs(1))?)?;
    if !pre.paired {
        // Already unpaired. Tidy up host-side files and call it a success.
        keystore::delete_key().ok();
        println!("Nano already unpaired; cleared host key files.");
        return Ok(());
    }

    // v2 cutover: unpair is now a framed command (the MAC proves we know the
    // key; we no longer send the key over the wire). The pre-cutover plaintext
    // `unpair <key>` form is rejected by post-fw=1.0 firmware as mac_required.
    let st = state::load()
        .context("loading client counter state")?
        .unwrap_or_else(state::State::fresh);
    let counter = st.next_cmd_counter;
    // Refuse to advance into the reserved ceiling band (security audit
    // 2026-05-28 / firmware DoS-2). counter < CEILING ⇒ counter+1 can't wrap.
    if counter >= framing::COUNTER_CEILING {
        bail!(
            "v2 counter {} is at/above the reserved ceiling; reflash-to-wipe \
             (firmware/r503fp_wipe) + re-pair to reset",
            counter
        );
    }
    // Persist counter+1 BEFORE send (SPEC §13.4): crash here ⇒ next start
    // skips one counter slot, never replays.
    state::save(&state::State {
        next_cmd_counter: counter + 1,
    })
    .context("persisting client counter before unpair")?;

    let frame = framing::encode_command(&key, counter, "unpair");
    // The frame embeds the SipHash MAC tag; label with the bare verb so a
    // reply timeout never leaks key-derived material (audit L-pairing-key).
    let raw_reply = link.cmd_labeled(&frame, "unpair", Duration::from_secs(2))?;
    if !raw_reply.starts_with("R ") {
        bail!(
            "Nano refused framed unpair (unframed reply): {:?}",
            raw_reply
        );
    }
    let (got_ctr, _got_seq, body) = framing::verify_response(&key, &raw_reply)
        .map_err(|e| anyhow::anyhow!("response framing: {:?} (line: {:?})", e, raw_reply))?;
    if got_ctr != counter {
        bail!(
            "unpair response counter mismatch: got {}, want {}",
            got_ctr,
            counter
        );
    }
    if body != "OK unpaired" {
        bail!("Nano refused unpair: {:?}", body);
    }

    // Post-unpair: Nano is now unpaired, so status goes unframed.
    let post = parse_status(&link.cmd("status", Duration::from_secs(1))?)?;
    if post.paired {
        bail!("unpair ok but status still reports paired=true — EEPROM not committed?");
    }
    keystore::delete_all_keys().context("removing host key files")?;
    state::delete().context("removing client counter state")?;

    println!(
        "unpaired. fw={} fmt={} counter={}",
        post.fw, post.fmt, post.counter
    );
    println!("host key + state files removed (plaintext + sealed).");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore;

    // DoS-2: a forged/exhausted unauthenticated `status counter=...` must not be
    // able to drive the host's persisted counter into the brick/wrap zone.
    #[test]
    fn resync_target_advances_below_ceiling() {
        assert_eq!(resync_target(0).unwrap(), 1);
        assert_eq!(resync_target(41).unwrap(), 42);
        assert_eq!(
            resync_target(framing::COUNTER_CEILING - 2).unwrap(),
            framing::COUNTER_CEILING - 1
        );
    }

    #[test]
    fn resync_target_refuses_ceiling_band() {
        // The exact MITM-during-resync vector: a lie of u64::MAX (and anything
        // that would land at/above the ceiling) is rejected, not trusted.
        assert!(resync_target(u64::MAX).is_err());
        assert!(resync_target(framing::COUNTER_CEILING).is_err());
        assert!(resync_target(framing::COUNTER_CEILING - 1).is_err());
    }

    // Regression guard for audit finding L-pairing-key-in-error: a reply
    // timeout during `--pair`/`--unpair` must never interpolate the wire bytes
    // (which carry the 128-bit key / MAC tag) into the operator-visible error.
    // `cmd_labeled` is the only path the secret-bearing call sites use, and the
    // error text is built solely from `timeout_context(label)`.

    #[test]
    fn timeout_context_uses_label_not_wire_bytes() {
        // Simulate the exact `pair` call site: wire = "pair <32-hex-key>".
        let key = keystore::generate_key().unwrap();
        let key_h = keystore::key_hex(&key);
        let wire = format!("pair {}", &*key_h);

        let msg = timeout_context("pair");

        assert_eq!(msg, "timeout reading reply to: pair");
        assert!(
            !msg.contains(&*key_h),
            "timeout error leaked the key hex: {msg}"
        );
        assert!(
            !msg.contains(&wire),
            "timeout error leaked the full pair command: {msg}"
        );
    }

    #[test]
    fn timeout_context_redacts_unpair_frame() {
        // Simulate the `unpair` call site: wire = MAC-framed command. The frame
        // embeds the SipHash tag; the label must not.
        let key = keystore::generate_key().unwrap();
        let frame = framing::encode_command(&key, 1, "unpair");

        let msg = timeout_context("unpair");

        assert_eq!(msg, "timeout reading reply to: unpair");
        assert!(
            !msg.contains(&frame),
            "timeout error leaked the framed unpair command: {msg}"
        );
        // Defensive: no portion of the hex frame body should appear.
        assert!(
            frame.len() < 8 || !msg.contains(&frame[frame.len() - 8..]),
            "timeout error leaked a MAC-tag suffix: {msg}"
        );
    }

    #[test]
    fn non_secret_label_is_preserved_verbatim() {
        // status/ping route through cmd() which passes the command as its own
        // label; those are safe and must remain debuggable.
        assert_eq!(
            timeout_context("status"),
            "timeout reading reply to: status"
        );
        assert_eq!(timeout_context("ping"), "timeout reading reply to: ping");
    }
}
