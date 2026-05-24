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

const DEFAULT_BAUD: u32 = 115_200;

const TIMEOUT_INFO_MS: u64 = 2_000;
const TIMEOUT_COUNT_MS: u64 = 2_000;
const TIMEOUT_ENROLL_MS: u64 = 45_000;
const TIMEOUT_VERIFY_MS: u64 = 15_000;
const TIMEOUT_DELETE_MS: u64 = 2_000;
const TIMEOUT_CLEAR_MS: u64 = 3_000;
const TIMEOUT_LED_MS: u64 = 2_000;
const TIMEOUT_WAKE_MS: u64 = 2_000;
const TIMEOUT_PING_MS: u64 = 2_000;

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
    Command { code: String, detail: Option<String> },
    #[error("invalid response from firmware: {0}")]
    Protocol(String),
}

#[derive(Debug, Clone)]
pub struct SensorInfo {
    pub fw: String,
    pub capacity: u16,
    pub enrolled: u16,
    pub sysid: String,
    pub security: u8,
    pub device_addr: String,
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
        let port = serialport::new(&path, DEFAULT_BAUD)
            .timeout(Duration::from_millis(200))
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
        };
        this.sync(sync_timeout)?;
        Ok(this)
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
                    if let Some(t) = last_byte_at {
                        if t.elapsed() > silence_after_byte {
                            break;
                        }
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
            let _ = self.port.clear(serialport::ClearBuffer::Input);
            self.port.write_all(b"ping\n")?;
            self.port.flush()?;
            let per_attempt = Instant::now() + Duration::from_secs(1);
            let attempt_deadline = per_attempt.min(deadline);
            loop {
                match self.read_line(attempt_deadline)? {
                    Some(l) if l == "OK pong" => {
                        // Belt-and-suspenders: discard anything queued behind
                        // the pong before handing control back.
                        self.rx_buf.clear();
                        let _ = self.port.clear(serialport::ClearBuffer::Input);
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
    /// final OK/ERR line. Times out if neither arrives within `timeout_ms`.
    ///
    /// Discards anything left in the input buffer first: a previous command
    /// that hit Rust-side timeout may have left a late OK/ERR line in the
    /// kernel queue or in `rx_buf`, and we don't want it to satisfy the next
    /// command. (The firmware is single-threaded and won't reply out of order,
    /// so dropping stale bytes is always safe.)
    fn execute(&mut self, cmd: &str, timeout_ms: u64) -> Result<String, SensorError> {
        self.rx_buf.clear();
        let _ = self.port.clear(serialport::ClearBuffer::Input);
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
            .filter_map(|tok| tok.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())))
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
        // `capacity` is required — a missing/garbled value would silently
        // collapse to 0, which then makes allocate_slot() return NoFreeSlot for
        // every enroll. Treat it as a protocol error so the daemon refuses to
        // start instead of failing every later enroll with a confusing reason.
        Ok(SensorInfo {
            fw: kv.get("fw").cloned().unwrap_or_default(),
            capacity: Self::parse_field(&kv, "capacity")?,
            enrolled: Self::parse_field(&kv, "enrolled").unwrap_or(0),
            sysid: kv.get("sysid").cloned().unwrap_or_default(),
            security: Self::parse_field(&kv, "security").unwrap_or(0),
            device_addr: kv.get("device_addr").cloned().unwrap_or_default(),
        })
    }

    pub fn count(&mut self) -> Result<u16, SensorError> {
        let body = Self::expect_ok(self.execute("count", TIMEOUT_COUNT_MS)?)?;
        Self::parse_field(&Self::parse_kv(&body), "count")
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
        Ok(Self::parse_kv(&body).get("wake").map(|s| s == "1").unwrap_or(false))
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
                if let Some(name) = entry.file_name().to_str() {
                    if name.starts_with(pattern) {
                        matches.push(PathBuf::from("/dev").join(name));
                    }
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
