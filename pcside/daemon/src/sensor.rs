//! R503 ASCII-protocol driver over USB-CDC serial.
//!
//! Port of pcside/r503ctl.py. Same firmware-side protocol (§5 of SPEC.md).
//! All I/O is blocking; callers should run inside `tokio::task::spawn_blocking`
//! or a dedicated thread.

use serialport::SerialPort;
use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

use crate::framing;
use crate::state;

const DEFAULT_BAUD: u32 = 115_200;

const TIMEOUT_INFO_MS: u64 = 2_000;
const TIMEOUT_ENROLL_MS: u64 = 45_000;
const TIMEOUT_VERIFY_MS: u64 = 15_000;
const TIMEOUT_DELETE_MS: u64 = 2_000;
const TIMEOUT_CLEAR_MS: u64 = 3_000;
const TIMEOUT_LED_MS: u64 = 2_000;
const TIMEOUT_WAKE_MS: u64 = 2_000;
const TIMEOUT_PING_MS: u64 = 2_000;

// Hard cap on a single inbound line. The longest realistic framed reply
// (SPEC §13) is ~120 bytes; 4 KiB is ~30x that. A run-on stream of
// non-'\n' bytes — either a glitchy firmware or a co-opener of /dev/r503
// who slipped past H1's exclusive lock — would otherwise grow rx_buf
// without bound and OOM the daemon (security audit 2026-05-28 / M1).
const MAX_LINE_LEN: usize = 4096;

#[derive(Debug, thiserror::Error)]
pub enum SensorError {
    #[error("no R503 serial device at /dev/ttyACM* or /dev/ttyUSB*; is the Uno plugged in?")]
    NoDevice,
    #[error("could not open {path}: {source}")]
    OpenFailed {
        path: String,
        #[source]
        source: serialport::Error,
    },
    #[error("serial I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("timed out waiting for response to: {0}")]
    Timeout(String),
    #[error("firmware ERR {code}{detail}", detail = .detail.as_ref().map(|d| format!(" {}", d)).unwrap_or_default())]
    Command {
        code: String,
        detail: Option<String>,
    },
    #[error("invalid response from firmware: {0}")]
    Protocol(String),
    #[error(
        "v2 command counter exhausted (reached the reserved ceiling); \
         reflash-to-wipe (firmware/r503fp_wipe) + re-pair to reset"
    )]
    CounterExhausted,
}

/// Advance the monotonic command counter by one, refusing to enter the reserved
/// ceiling band. Returns `CounterExhausted` rather than wrapping past `u64::MAX`
/// — a plain `counter + 1` wraps to 0 in a release build (overflow-checks off),
/// which would silently roll replay protection back to the lowest floor. Pairing
/// the ceiling guard with the wrap guard closes both (security audit 2026-05-28
/// / firmware DoS-2). Pure + counter-only so it is unit-testable without a port.
fn advance_counter(counter: u64) -> Result<u64, SensorError> {
    if counter >= framing::COUNTER_CEILING {
        return Err(SensorError::CounterExhausted);
    }
    // counter < COUNTER_CEILING < u64::MAX, so +1 cannot overflow.
    Ok(counter + 1)
}

#[derive(Debug, Clone)]
pub struct SensorInfo {
    pub fw: String,
    pub capacity: u16,
    pub enrolled: u16,
}

#[derive(Debug, Clone)]
pub struct MatchResult {
    pub slot: u8,
    pub confidence: u16,
}

/// Box-typed progress callback. PROGRESS lines from the firmware are forwarded
/// here so callers can relay them as D-Bus signals.
pub type ProgressFn = Box<dyn FnMut(&str) + Send + 'static>;

pub struct R503 {
    port: Box<dyn SerialPort>,
    port_path: String,
    rx_buf: Vec<u8>,
    on_progress: ProgressFn,

    // v2 authenticated-channel state (SPEC §13). When `key` is Some, every
    // execute() wraps the outgoing command in `C <ctr> ... M <mac>` framing
    // and verifies the corresponding `R <ctr> <seq> ... M <mac>` responses.
    // When None, execute() falls back to the v1 plain-ASCII protocol.
    //
    // `Zeroizing<...>` so the key bytes are scrubbed from RAM on drop / unset
    // (crypto-posture review item #2 — closes the RAM/swap/core-dump leak).
    key: Option<Zeroizing<[u8; 16]>>,
    /// Counter to use on the NEXT framed command. Persisted to state::STATE_PATH
    /// BEFORE each send so a crash never lets us reuse a counter.
    client_counter: u64,
}

impl R503 {
    /// Open the sensor. If `port_path` is None, auto-detect /dev/ttyACM* or
    /// /dev/ttyUSB*. Performs the quiescence-then-ping handshake before
    /// returning; on success the firmware is in its idle loop ready for
    /// commands.
    pub fn open(port_path: Option<&str>, sync_timeout: Duration) -> Result<Self, SensorError> {
        let path = match port_path {
            Some(p) => p.to_string(),
            None => find_port()?,
        };
        // .exclusive(true) sets TIOCEXCL + flock LOCK_EX on the fd so a
        // second open(2) from any non-root process returns EBUSY. This is
        // ALREADY the serialport-4.x POSIX default, but we set it explicitly
        // so a future crate-default flip can't silently downgrade us — and
        // so the security posture is obvious to a reader (audit 2026-05-28).
        let port = serialport::new(&path, DEFAULT_BAUD)
            .timeout(Duration::from_millis(200))
            .exclusive(true)
            .open()
            .map_err(|e| SensorError::OpenFailed {
                path: path.clone(),
                source: e,
            })?;
        let mut this = R503 {
            port,
            port_path: path,
            rx_buf: Vec::with_capacity(1024),
            on_progress: Box::new(|msg: &str| tracing::debug!(progress = msg)),
            key: None,
            client_counter: 0,
        };
        this.sync(sync_timeout)?;
        Ok(this)
    }

    /// Engage the v2 authenticated channel. `next_counter` is the value to
    /// use on the first framed command — typically loaded from `state.json`
    /// (or `state::State::fresh().next_cmd_counter` for a brand-new pairing).
    pub fn set_auth(&mut self, key: Zeroizing<[u8; 16]>, next_counter: u64) {
        self.key = Some(key);
        self.client_counter = next_counter;
    }

    pub fn port_path(&self) -> &str {
        &self.port_path
    }

    /// Install a new progress callback. Called once per PROGRESS line that
    /// streams from the firmware during multi-step operations (enroll, verify).
    pub fn set_progress<F>(&mut self, f: F)
    where
        F: FnMut(&str) + Send + 'static,
    {
        self.on_progress = Box::new(f);
    }

    /// Quiescence-then-ping handshake.
    ///
    /// When opening the port triggers a DTR reset on the Uno (cold connect),
    /// the firmware's setup() prints "R503FP READY" + a full info() line over
    /// ~2.5s. We wait for 300ms of silence after the LAST byte to know boot
    /// has finished.
    ///
    /// But opens that DON'T trigger a DTR reset (e.g. opening the same kernel
    /// cdc-acm node after a daemon restart, or a re-open with no power cycle)
    /// produce NO boot output at all — the Uno is already in its main loop.
    /// In that case waiting indefinitely for the first byte would chew the
    /// whole timeout budget; we cap the drain phase at `first_byte_grace` and
    /// proceed straight to ping if nothing arrives.
    fn sync(&mut self, timeout: Duration) -> Result<(), SensorError> {
        let deadline = Instant::now() + timeout;
        let first_byte_grace = Duration::from_millis(800);
        let silence_after_byte = Duration::from_millis(300);
        let drain_start = Instant::now();
        let mut last_byte_at: Option<Instant> = None;
        let mut buf = [0u8; 256];
        loop {
            if Instant::now() >= deadline {
                break;
            }
            // No bytes ever arrived AND grace period elapsed → Uno is already
            // in main loop, skip ahead to ping.
            if last_byte_at.is_none() && drain_start.elapsed() > first_byte_grace {
                break;
            }
            self.port.set_timeout(Duration::from_millis(100)).ok();
            match self.port.read(&mut buf) {
                Ok(0) => {}
                Ok(_n) => {
                    last_byte_at = Some(Instant::now());
                }
                Err(ref e) if e.kind() == ErrorKind::TimedOut => {
                    if let Some(t) = last_byte_at
                        && t.elapsed() > silence_after_byte
                    {
                        break;
                    }
                }
                Err(e) => return Err(SensorError::Io(e)),
            }
        }
        // Phase 2 — retry pings until we hear "OK pong" or run out of budget.
        // A ping sent while setup() is still running (cold boot) gets either
        // queued past the boot banner or lost; the next one always lands once
        // the main loop starts. Per-ping wait is 1s, the outer deadline caps
        // total attempts.
        //
        // Critical: clear both rx_buf and the kernel input queue BEFORE each
        // attempt. Otherwise, a previous attempt's "OK pong" that arrived late
        // (after we'd given up on it) gets consumed by the next attempt's
        // read_line, and the queue still holds an unmatched response that will
        // bleed into the next caller's execute() — observable as `info` parsing
        // "OK pong" and returning a SensorInfo full of zeros.
        while Instant::now() < deadline {
            self.rx_buf.clear();
            self.port
                .clear(serialport::ClearBuffer::Input)
                .map_err(|e| SensorError::Io(e.into()))?;
            self.port.write_all(b"ping\n")?;
            self.port.flush()?;
            let per_attempt = Instant::now() + Duration::from_secs(1);
            let attempt_deadline = per_attempt.min(deadline);
            loop {
                match self.read_line(attempt_deadline)? {
                    Some(l) if l == "OK pong" => {
                        // Belt-and-suspenders: discard anything queued behind
                        // the pong before handing control back. A failure here
                        // is non-fatal — we just got a valid pong, the port
                        // works; log and proceed.
                        self.rx_buf.clear();
                        if let Err(e) = self.port.clear(serialport::ClearBuffer::Input) {
                            tracing::debug!("post-pong drain clear() failed: {}", e);
                        }
                        return Ok(());
                    }
                    Some(_) => continue,
                    None => break, // attempt timed out — outer loop will retry
                }
            }
        }
        Err(SensorError::Timeout(format!(
            "could not synchronize with firmware (no OK pong within {:?})",
            timeout
        )))
    }

    /// Read one newline-terminated line, or None on deadline.
    fn read_line(&mut self, deadline: Instant) -> Result<Option<String>, SensorError> {
        loop {
            if let Some(nl) = self.rx_buf.iter().position(|&b| b == b'\n') {
                let line_bytes: Vec<u8> = self.rx_buf.drain(..=nl).collect();
                let mut line =
                    String::from_utf8_lossy(&line_bytes[..line_bytes.len() - 1]).into_owned();
                if line.ends_with('\r') {
                    line.pop();
                }
                return Ok(Some(line));
            }
            if self.rx_buf.len() > MAX_LINE_LEN {
                // No newline within the cap. Discard everything pending,
                // flush the kernel input queue, and surface a Protocol
                // error so the caller can decide whether to retry or fail.
                self.rx_buf.clear();
                let _ = self.port.clear(serialport::ClearBuffer::Input);
                return Err(SensorError::Protocol(format!(
                    "line exceeded {} bytes without newline (sensor noise or co-opener?)",
                    MAX_LINE_LEN
                )));
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            let remaining = deadline - now;
            let chunk_timeout = remaining.min(Duration::from_millis(200));
            self.port.set_timeout(chunk_timeout).ok();
            let mut buf = [0u8; 256];
            match self.port.read(&mut buf) {
                Ok(0) => {}
                Ok(n) => self.rx_buf.extend_from_slice(&buf[..n]),
                Err(ref e) if e.kind() == ErrorKind::TimedOut => {}
                Err(e) => return Err(SensorError::Io(e)),
            }
        }
    }

    fn send(&mut self, cmd: &str) -> Result<(), SensorError> {
        self.port.write_all(cmd.as_bytes())?;
        self.port.write_all(b"\n")?;
        self.port.flush()?;
        Ok(())
    }

    /// Send a command, stream PROGRESS lines through `on_progress`, return the
    /// final OK/ERR line body. Times out if neither arrives within `timeout_ms`.
    ///
    /// Branches by auth state:
    ///   - `key` is None → plain v1 ASCII protocol.
    ///   - `key` is Some → v2 framed: wraps the outgoing command in
    ///     `C <ctr> ... M <mac>` and verifies each `R <ctr> <seq> ... M <mac>`
    ///     response against the same counter. PROGRESS bodies stream through
    ///     `on_progress` after their frame's MAC + seq + counter check pass.
    fn execute(&mut self, cmd: &str, timeout_ms: u64) -> Result<String, SensorError> {
        if self.key.is_some() {
            self.execute_framed(cmd, timeout_ms)
        } else {
            self.execute_unframed(cmd, timeout_ms)
        }
    }

    /// Plain v1 ASCII protocol — unchanged from pre-Milestone-E.
    fn execute_unframed(&mut self, cmd: &str, timeout_ms: u64) -> Result<String, SensorError> {
        self.rx_buf.clear();
        self.port
            .clear(serialport::ClearBuffer::Input)
            .map_err(|e| SensorError::Io(e.into()))?;
        self.send(cmd)?;
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        loop {
            let line = self
                .read_line(deadline)?
                .ok_or_else(|| SensorError::Timeout(cmd.to_string()))?;
            if line.is_empty() {
                continue;
            }
            if let Some(rest) = line.strip_prefix("PROGRESS ") {
                (self.on_progress)(rest);
                continue;
            }
            if line.starts_with("OK") || line.starts_with("ERR") {
                return Ok(line);
            }
            (self.on_progress)(&format!("[unhandled] {}", line));
        }
    }

    /// v2 framed protocol. `cmd` is the inner body (e.g. "verify 0"); we wrap
    /// it with the current `client_counter`, persist counter+1 to disk BEFORE
    /// sending (so a crash never lets us reuse a counter — SPEC §13.4), and
    /// verify every incoming response frame against the same counter.
    fn execute_framed(&mut self, cmd: &str, timeout_ms: u64) -> Result<String, SensorError> {
        // Clone into a local `Zeroizing<[u8; 16]>` — borrowing from `self.key`
        // would block the mutable `&mut self` borrows used by `read_line` /
        // `port.write_all` below. The local copy scrubs on drop at the end
        // of execute_framed.
        let key: Zeroizing<[u8; 16]> = self
            .key
            .as_ref()
            .expect("execute_framed called without key")
            .clone();
        let counter = self.client_counter;

        // Refuse to advance into the reserved ceiling band BEFORE we persist or
        // send anything — both the counter-exhaustion brick and the release-mode
        // `+1` wrap are closed here (security audit 2026-05-28 / firmware DoS-2).
        let next = advance_counter(counter)?;

        // Persist next BEFORE sending. Crash here ⇒ daemon restart sees the
        // higher next, sends C=counter+1, Nano sees a gap, accepts. Crash
        // after send but before next reply ⇒ Nano already updated last_seen
        // to `counter`, daemon's next == counter+1 still works.
        let next_state = state::State {
            next_cmd_counter: next,
        };
        state::save(&next_state).map_err(|e| {
            SensorError::Io(std::io::Error::other(format!(
                "persist client_counter: {}",
                e
            )))
        })?;
        self.client_counter = next;

        let frame = framing::encode_command(&key, counter, cmd);
        self.rx_buf.clear();
        self.port
            .clear(serialport::ClearBuffer::Input)
            .map_err(|e| SensorError::Io(e.into()))?;
        self.port.write_all(frame.as_bytes())?;
        self.port.write_all(b"\n")?;
        self.port.flush()?;

        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        let mut expected_seq: u32 = 0;
        loop {
            let line = self
                .read_line(deadline)?
                .ok_or_else(|| SensorError::Timeout(cmd.to_string()))?;
            if line.is_empty() {
                continue;
            }
            // Firmware-side framing rejections come back unframed (the Nano
            // has no agreed counter/seq for an invalid frame to bind to).
            // Treat them as command errors so the daemon can surface them.
            if !line.starts_with("R ") {
                return Err(SensorError::Command {
                    code: "framing_rejected".to_string(),
                    detail: Some(line),
                });
            }
            let (got_ctr, got_seq, body) = framing::verify_response(&key, &line).map_err(|e| {
                SensorError::Protocol(format!("response framing: {:?} (line: {:?})", e, line))
            })?;
            if got_ctr != counter {
                return Err(SensorError::Protocol(format!(
                    "response counter mismatch: got {}, want {}",
                    got_ctr, counter
                )));
            }
            if got_seq != expected_seq {
                return Err(SensorError::Protocol(format!(
                    "response seq mismatch: got {}, want {}",
                    got_seq, expected_seq
                )));
            }
            expected_seq += 1;
            if let Some(rest) = body.strip_prefix("PROGRESS ") {
                (self.on_progress)(rest);
                continue;
            }
            if body.starts_with("OK") || body.starts_with("ERR") {
                return Ok(body.to_string());
            }
            (self.on_progress)(&format!("[unhandled] {}", body));
        }
    }

    fn expect_ok(line: String) -> Result<String, SensorError> {
        if let Some(rest) = line.strip_prefix("OK") {
            return Ok(rest.trim().to_string());
        }
        // ERR <code> [<detail …>]
        let mut parts = line.splitn(3, char::is_whitespace);
        let _err_tok = parts.next().unwrap_or("");
        let code = parts.next().unwrap_or("unknown").to_string();
        let detail = parts.next().map(|s| s.to_string());
        Err(SensorError::Command { code, detail })
    }

    fn parse_kv(body: &str) -> HashMap<String, String> {
        body.split_whitespace()
            .filter_map(|tok| {
                tok.split_once('=')
                    .map(|(k, v)| (k.to_string(), v.to_string()))
            })
            .collect()
    }

    fn parse_field<T: std::str::FromStr>(
        kv: &HashMap<String, String>,
        key: &str,
    ) -> Result<T, SensorError> {
        kv.get(key)
            .ok_or_else(|| SensorError::Protocol(format!("missing {}", key)))?
            .parse::<T>()
            .map_err(|_| SensorError::Protocol(format!("bad {}", key)))
    }

    // ----- commands -----

    pub fn info(&mut self) -> Result<SensorInfo, SensorError> {
        let body = Self::expect_ok(self.execute("info", TIMEOUT_INFO_MS)?)?;
        let kv = Self::parse_kv(&body);
        // `capacity` drives slot allocation. The R503 datasheet specifies 200
        // and our firmware reports the same; a garbled `capacity=` (firmware
        // bug, partial line read, parser regression) used to silently collapse
        // to 0 and make every enroll fail NoFreeSlot. Falling back to the
        // datasheet default keeps the daemon usable for list/verify/delete
        // even on a malformed info response, and a warn log surfaces the
        // problem at the diagnostics layer.
        const R503_DATASHEET_CAPACITY: u16 = 200;
        let capacity = Self::parse_field(&kv, "capacity").unwrap_or_else(|e| {
            tracing::warn!(
                error = %e,
                fallback = R503_DATASHEET_CAPACITY,
                "malformed info.capacity — using R503 datasheet default"
            );
            R503_DATASHEET_CAPACITY
        });
        Ok(SensorInfo {
            fw: kv.get("fw").cloned().unwrap_or_default(),
            capacity,
            enrolled: Self::parse_field(&kv, "enrolled").unwrap_or(0),
        })
    }

    pub fn enroll(&mut self, slot: u8) -> Result<u8, SensorError> {
        let body = Self::expect_ok(self.execute(&format!("enroll {}", slot), TIMEOUT_ENROLL_MS)?)?;
        Self::parse_field(&Self::parse_kv(&body), "enrolled")
    }

    pub fn verify(&mut self) -> Result<MatchResult, SensorError> {
        let body = Self::expect_ok(self.execute("verify", TIMEOUT_VERIFY_MS)?)?;
        let kv = Self::parse_kv(&body);
        Ok(MatchResult {
            slot: Self::parse_field(&kv, "match")?,
            confidence: Self::parse_field(&kv, "confidence")?,
        })
    }

    pub fn identify(&mut self) -> Result<MatchResult, SensorError> {
        let body = Self::expect_ok(self.execute("identify", TIMEOUT_VERIFY_MS)?)?;
        let kv = Self::parse_kv(&body);
        Ok(MatchResult {
            slot: Self::parse_field(&kv, "match")?,
            confidence: Self::parse_field(&kv, "confidence")?,
        })
    }

    pub fn delete(&mut self, slot: u8) -> Result<u8, SensorError> {
        let body = Self::expect_ok(self.execute(&format!("delete {}", slot), TIMEOUT_DELETE_MS)?)?;
        Self::parse_field(&Self::parse_kv(&body), "deleted")
    }

    pub fn clear(&mut self) -> Result<(), SensorError> {
        Self::expect_ok(self.execute("clear confirm", TIMEOUT_CLEAR_MS)?)?;
        Ok(())
    }

    pub fn wake(&mut self) -> Result<bool, SensorError> {
        let body = Self::expect_ok(self.execute("wake", TIMEOUT_WAKE_MS)?)?;
        Ok(Self::parse_kv(&body)
            .get("wake")
            .map(|s| s == "1")
            .unwrap_or(false))
    }

    pub fn ping(&mut self) -> Result<bool, SensorError> {
        let line = self.execute("ping", TIMEOUT_PING_MS)?;
        Ok(line.starts_with("OK pong"))
    }

    pub fn led_off(&mut self) -> Result<(), SensorError> {
        Self::expect_ok(self.execute("led off", TIMEOUT_LED_MS)?)?;
        Ok(())
    }
}

/// Discover the R503-attached Arduino's serial device.
///
/// Preference order:
///   1. `/dev/r503` — the stable symlink created by `70-r503.rules` (matches
///      common Arduino-compatible VID/PIDs). This is the supported path for
///      anyone running the installer.
///   2. `/dev/ttyACM*` — genuine Arduinos (ATmega16U2 / Native USB).
///   3. `/dev/ttyUSB*` — CH340 / FTDI clones.
///
/// The fall-throughs exist so that a user without the udev rule installed
/// (e.g. running the daemon manually for development) still works.
pub fn find_port() -> Result<String, SensorError> {
    let symlink = PathBuf::from("/dev/r503");
    if symlink.exists() {
        return Ok(symlink.to_string_lossy().into_owned());
    }
    for pattern in &["ttyACM", "ttyUSB"] {
        let mut matches = Vec::new();
        if let Ok(entries) = std::fs::read_dir("/dev") {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str()
                    && name.starts_with(pattern)
                {
                    matches.push(PathBuf::from("/dev").join(name));
                }
            }
        }
        matches.sort();
        if let Some(first) = matches.first() {
            return Ok(first.to_string_lossy().into_owned());
        }
    }
    Err(SensorError::NoDevice)
}

#[cfg(test)]
mod counter_tests {
    use super::*;

    // DoS-2: the send path must never wrap past u64::MAX (which would roll the
    // persisted counter back to 0 in a release build) or advance into the
    // reserved ceiling band that bricks the firmware's replay counter.
    #[test]
    fn advance_counter_increments_below_ceiling() {
        assert_eq!(advance_counter(0).unwrap(), 1);
        assert_eq!(advance_counter(41).unwrap(), 42);
        assert_eq!(
            advance_counter(framing::COUNTER_CEILING - 2).unwrap(),
            framing::COUNTER_CEILING - 1
        );
    }

    #[test]
    fn advance_counter_refuses_ceiling_instead_of_wrapping() {
        assert!(matches!(
            advance_counter(framing::COUNTER_CEILING),
            Err(SensorError::CounterExhausted)
        ));
        // The release-mode wrap target: u64::MAX would have wrapped to 0.
        assert!(matches!(
            advance_counter(u64::MAX),
            Err(SensorError::CounterExhausted)
        ));
    }
}
