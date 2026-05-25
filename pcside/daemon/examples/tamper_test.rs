//! Milestone E7: confirm the firmware rejects tampered & replayed frames.
//! Run with the daemon stopped (we drive /dev/r503 directly):
//!   sudo systemctl stop r503d
//!   sudo cargo run --example tamper_test
//!
//! After the test we re-bump state.json so the daemon can resume seamlessly.

use std::io::{ErrorKind, Read, Write};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use r503d::{framing, keystore, state};
use serialport::SerialPort;

const PORT: &str = "/dev/r503";
const BAUD: u32 = 115_200;

struct Link {
    port: Box<dyn SerialPort>,
    rx: Vec<u8>,
}

impl Link {
    fn open() -> Result<Self> {
        let port = serialport::new(PORT, BAUD).timeout(Duration::from_millis(200)).open()?;
        let mut link = Link { port, rx: Vec::new() };
        // Robust ping handshake (drains boot banner + waits for OK pong).
        let deadline = Instant::now() + Duration::from_secs(8);
        let mut last: Option<String> = None;
        while Instant::now() < deadline {
            link.rx.clear();
            let _ = link.port.clear(serialport::ClearBuffer::Input);
            link.port.write_all(b"ping\n")?;
            link.port.flush()?;
            let per = Instant::now() + Duration::from_millis(800);
            loop {
                let remaining = per.saturating_duration_since(Instant::now());
                if remaining.is_zero() { break; }
                match link.read_line(remaining)? {
                    Some(l) if l == "OK pong" => return Ok(link),
                    Some(l) => { last = Some(l); }
                    None => break,
                }
            }
        }
        bail!("no OK pong; last: {:?}", last)
    }

    fn cmd(&mut self, c: &str, timeout: Duration) -> Result<String> {
        self.rx.clear();
        let _ = self.port.clear(serialport::ClearBuffer::Input);
        self.port.write_all(c.as_bytes())?;
        self.port.write_all(b"\n")?;
        self.port.flush()?;
        let deadline = Instant::now() + timeout;
        loop {
            let line = self
                .read_line(deadline.saturating_duration_since(Instant::now()))?
                .ok_or_else(|| anyhow!("timeout on {}", c))?;
            if line.is_empty() || line.starts_with("PROGRESS ") { continue; }
            return Ok(line);
        }
    }

    fn read_line(&mut self, max: Duration) -> Result<Option<String>> {
        let deadline = Instant::now() + max;
        loop {
            if let Some(nl) = self.rx.iter().position(|&b| b == b'\n') {
                let mut line: Vec<u8> = self.rx.drain(..=nl).collect();
                line.pop();
                if line.last() == Some(&b'\r') { line.pop(); }
                return Ok(Some(String::from_utf8_lossy(&line).into_owned()));
            }
            if Instant::now() >= deadline { return Ok(None); }
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

fn ok(label: &str, got: &str) {
    println!("  OK  {}: {}", label, got);
}
fn bad(label: &str, got: &str, want: &str) -> ! {
    eprintln!("  BAD {}: got {:?}, want {:?}", label, got, want);
    std::process::exit(1);
}

fn main() -> Result<()> {
    let key = keystore::load_key().context("no host key at /var/lib/r503d/key")?;
    let st = state::load()?.unwrap_or_else(state::State::fresh);
    let mut counter = st.next_cmd_counter;
    println!("starting counter: {}", counter);

    let mut link = Link::open()?;

    // T1: valid framed ping → must be accepted, response is framed OK pong.
    let frame = framing::encode_command(&key, counter, "ping");
    let reply = link.cmd(&frame, Duration::from_secs(2))?;
    let (rc, rseq, body) = framing::verify_response(&key, &reply)
        .with_context(|| format!("T1 verify response: {:?}", reply))?;
    if rc != counter || rseq != 0 || body != "OK pong" {
        bad("T1 valid ping", &format!("({},{},{:?})", rc, rseq, body), "(counter,0,\"OK pong\")");
    }
    ok("T1 valid ping", &format!("counter={} seq={} body={:?}", rc, rseq, body));
    let advanced_counter = counter + 1;

    // T2: replay — re-send the exact same frame. Firmware ee_counter is now
    // `counter`, so this should be rejected as replay.
    let reply = link.cmd(&frame, Duration::from_secs(2))?;
    if reply != "ERR replay" {
        bad("T2 replay rejected", &reply, "ERR replay");
    }
    ok("T2 replay rejected", &reply);

    // T3: MAC tamper — encode a fresh-counter frame, flip last hex char.
    let mut tampered = framing::encode_command(&key, advanced_counter, "ping");
    let last = tampered.pop().unwrap();
    tampered.push(if last == '0' { 'f' } else { '0' });
    let reply = link.cmd(&tampered, Duration::from_secs(2))?;
    // Post-F2 the firmware emits stable named errors instead of enum integers.
    if reply != "ERR mac_invalid" {
        bad("T3 MAC tamper rejected", &reply, "ERR mac_invalid");
    }
    ok("T3 MAC tamper rejected", &reply);

    // T4: counter regression — send `counter - 1` (already used long ago).
    if counter >= 1 {
        let frame = framing::encode_command(&key, counter - 1, "ping");
        let reply = link.cmd(&frame, Duration::from_secs(2))?;
        if reply != "ERR replay" {
            bad("T4 counter regression rejected", &reply, "ERR replay");
        }
        ok("T4 counter regression rejected", &reply);
    }

    // T5: valid frame at fresh counter still works after tampering attempts.
    let frame = framing::encode_command(&key, advanced_counter, "ping");
    let reply = link.cmd(&frame, Duration::from_secs(2))?;
    let (rc, rseq, body) = framing::verify_response(&key, &reply)?;
    if rc != advanced_counter || rseq != 0 || body != "OK pong" {
        bad("T5 recovery", &format!("({},{},{:?})", rc, rseq, body), "(advanced,0,OK pong)");
    }
    ok("T5 recovery after tampering", &format!("counter={} body={:?}", rc, body));

    // Re-sync host state.json so the daemon doesn't replay-fail on its next
    // send. Firmware's last_seen is now `advanced_counter`; daemon needs
    // next > that.
    counter = advanced_counter + 1;
    state::save(&state::State { next_cmd_counter: counter })?;
    println!("\nstate.json bumped to next_cmd_counter={} for daemon resume", counter);
    println!("\nPASS");
    Ok(())
}
