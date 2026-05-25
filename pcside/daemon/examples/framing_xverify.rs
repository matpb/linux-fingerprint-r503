//! Cross-verify v2 framing: drives the Nano's `frame_resp` / `frame_cmd` test
//! commands and checks bit-for-bit agreement with daemon-side framing.rs.
//!
//! Bidirectional:
//!   1. Daemon encodes a command frame → firmware parses + verifies → returns
//!      inner cmdline → assert match.
//!   2. Firmware encodes a response frame → daemon parses + verifies →
//!      returns (counter, seq, body) → assert match.
//!   3. Tamper checks: flip a bit in a daemon-built frame → firmware must reject.
//!
//! Used only during Milestone B. Not shipped.

use std::env;
use std::io::{ErrorKind, Read, Write};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use r503d::framing;
use serialport::SerialPort;

const BAUD: u32 = 115_200;

fn default_port() -> String {
    if std::path::Path::new("/dev/r503").exists() {
        "/dev/r503".to_string()
    } else if std::path::Path::new("/dev/ttyUSB1").exists() {
        "/dev/ttyUSB1".to_string()
    } else {
        "/dev/ttyACM0".to_string()
    }
}

struct Link {
    port: Box<dyn SerialPort>,
    rx: Vec<u8>,
}

impl Link {
    fn open(path: &str) -> Result<Self> {
        let port = serialport::new(path, BAUD)
            .timeout(Duration::from_millis(200))
            .open()
            .with_context(|| format!("opening {}", path))?;
        let mut link = Link { port, rx: Vec::new() };
        // Boot takes ~2.5s (setup() + delay(500) + finger.begin() + emitInfo()).
        // After that the Nano is in its main loop. Some opens trigger DTR reset
        // (cold), some don't (warm); cover both by retrying ping until we hear
        // OK pong or run out of attempts.
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
                if remaining.is_zero() { break; }
                match link.read_line(remaining)? {
                    Some(line) if line == "OK pong" => return Ok(link),
                    Some(line) => { last = Some(line); continue; }
                    None => break,
                }
            }
        }
        bail!("never got OK pong; last line: {:?}", last)
    }

    fn cmd(&mut self, cmd: &str, timeout: Duration) -> Result<String> {
        // Drain stale bytes (boot banner, prior command's late reply) before
        // sending. Matches sensor.rs::execute() behavior.
        self.rx.clear();
        let _ = self.port.clear(serialport::ClearBuffer::Input);
        self.port.write_all(cmd.as_bytes())?;
        self.port.write_all(b"\n")?;
        self.port.flush()?;
        let deadline = Instant::now() + timeout;
        loop {
            let line = self
                .read_line(deadline.saturating_duration_since(Instant::now()))?
                .with_context(|| format!("timeout reading reply to: {}", cmd))?;
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
                line.pop(); // \n
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                return Ok(Some(String::from_utf8_lossy(&line).into_owned()));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            self.port
                .set_timeout(Duration::from_millis(100))
                .ok();
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

fn rand_bytes(n: usize) -> Vec<u8> {
    use std::fs::File;
    let mut f = File::open("/dev/urandom").unwrap();
    let mut out = vec![0u8; n];
    f.read_exact(&mut out).unwrap();
    out
}

fn rand_key() -> [u8; 16] {
    let mut k = [0u8; 16];
    k.copy_from_slice(&rand_bytes(16));
    k
}

fn key_hex(k: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for b in k.iter() {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn main() -> Result<()> {
    let port = env::args().nth(1).unwrap_or_else(default_port);
    eprintln!("opening {}", port);
    let mut link = Link::open(&port)?;
    eprintln!("link up\n");

    let mut fails = 0;
    let mut total = 0;

    // ----- Test 1: daemon-encoded cmd → firmware verifies + returns inner -----
    eprintln!("== T1: daemon encodes command frame, firmware parses + verifies ==");
    let t1_cases: Vec<(u64, &str)> = vec![
        (0, "ping"),
        (1, "info"),
        (42, "verify 0"),
        (12345, "enroll 199"),
        (u32::MAX as u64, "led off"),
        (u64::MAX / 2, "clear confirm"),
        // body with multiple spaces:
        (7, "OK match=0 confidence=168"),
    ];
    let t1_key = rand_key();
    for (i, (ctr, cmd)) in t1_cases.iter().enumerate() {
        total += 1;
        let frame = framing::encode_command(&t1_key, *ctr, cmd);
        let req = format!("frame_cmd {} {}", key_hex(&t1_key), frame);
        let reply = link.cmd(&req, Duration::from_millis(500))?;
        let want = format!("OK counter={} inner={}", ctr, cmd);
        let ok = reply == want;
        let flag = if ok { "OK " } else { "BAD" };
        eprintln!("[t1/{:2}] {} ctr={} cmd={:?}\n        reply: {}", i, flag, ctr, cmd, reply);
        if !ok {
            eprintln!("        want : {}", want);
            fails += 1;
        }
    }

    // ----- Test 2: firmware encodes response → daemon parses + verifies -----
    eprintln!("\n== T2: firmware encodes response frame, daemon parses + verifies ==");
    let t2_cases: Vec<(u64, u32, &str)> = vec![
        (1, 0, "OK pong"),
        (42, 0, "PROGRESS place_finger"),
        (42, 1, "OK match=0 confidence=168"),
        (99, 5, "ERR no_match"),
        (u64::MAX / 3, 0xFFFF_FFFF, "OK fw=1.0 capacity=200"),
    ];
    let t2_key = rand_key();
    for (i, (ctr, seq, body)) in t2_cases.iter().enumerate() {
        total += 1;
        let req = format!("frame_resp {} {} {} {}", key_hex(&t2_key), ctr, seq, body);
        let reply = link.cmd(&req, Duration::from_millis(500))?;
        let Some(frame) = reply.strip_prefix("OK frame=") else {
            eprintln!("[t2/{:2}] BAD ctr={} seq={} body={:?}\n        unexpected reply: {}", i, ctr, seq, body, reply);
            fails += 1;
            continue;
        };
        match framing::verify_response(&t2_key, frame) {
            Ok((got_ctr, got_seq, got_body)) => {
                let ok = got_ctr == *ctr && got_seq == *seq && got_body == *body;
                let flag = if ok { "OK " } else { "BAD" };
                eprintln!("[t2/{:2}] {} ctr={} seq={} body={:?}", i, flag, ctr, seq, body);
                if !ok {
                    eprintln!("        got ctr={} seq={} body={:?}", got_ctr, got_seq, got_body);
                    fails += 1;
                }
            }
            Err(e) => {
                eprintln!("[t2/{:2}] BAD verify failed: {:?}\n        frame: {}", i, e, frame);
                fails += 1;
            }
        }
    }

    // ----- Test 3: tamper checks (firmware must reject) -----
    eprintln!("\n== T3: tampered frames must be rejected by firmware ==");
    let t3_key = rand_key();
    let good_frame = framing::encode_command(&t3_key, 100, "verify 5");

    let tampered_body = good_frame.replacen("verify 5", "verify 7", 1);
    let tampered_counter = good_frame.replacen("100", "200", 1);
    let mut tampered_mac = good_frame.clone();
    // Flip the last hex char to a guaranteed-different one. Naive pop+push('0')
    // is a no-op when the original char was already '0'.
    let last = tampered_mac.pop().unwrap();
    let flipped = if last == '0' { 'f' } else { '0' };
    tampered_mac.push(flipped);
    // Wrong key: encode with a different key, send for verification under t3_key.
    let wrong_key_frame = framing::encode_command(&rand_key(), 100, "verify 5");

    let t3_cases = vec![
        ("tampered body", tampered_body),
        ("tampered counter", tampered_counter),
        ("tampered mac", tampered_mac),
        ("wrong key", wrong_key_frame),
    ];
    for (i, (label, frame)) in t3_cases.iter().enumerate() {
        total += 1;
        let req = format!("frame_cmd {} {}", key_hex(&t3_key), frame);
        let reply = link.cmd(&req, Duration::from_millis(500))?;
        // FRAME_MAC_MISMATCH = 7 in framing.h enum
        let ok = reply.starts_with("ERR frame_rc=");
        let flag = if ok { "OK " } else { "BAD" };
        eprintln!("[t3/{:2}] {} {} -> {}", i, flag, label, reply);
        if !ok {
            fails += 1;
        }
    }

    eprintln!("\n{}/{} matched", total - fails, total);
    if fails > 0 {
        std::process::exit(1);
    }
    Ok(())
}
