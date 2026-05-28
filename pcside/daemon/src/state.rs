//! Host-side counter state for the v2 authenticated channel (SPEC §13.4).
//!
//! Stores one number: `next_cmd_counter` — the value to use on the NEXT
//! framed command. Persisted to /var/lib/r503d/state.json. Updates MUST
//! happen BEFORE the command is sent, so a crash mid-command loses a counter
//! slot (Nano sees a gap, accepts the higher value) but never replays an old
//! one (Nano rejects anything `<= last_seen`).

#![allow(dead_code)]

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

pub const STATE_DIR: &str = "/var/lib/r503d";
pub const STATE_PATH: &str = "/var/lib/r503d/state.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
// deny_unknown_fields: a stale/garbled/maliciously-edited state.json with extra
// keys is rejected loudly rather than silently parsed (audit 2026-05-28 / M3).
#[serde(deny_unknown_fields)]
pub struct State {
    /// Counter value to use on the NEXT framed command.
    pub next_cmd_counter: u64,
}

impl State {
    pub fn fresh() -> Self {
        // Nano accepts any C > last_seen, where last_seen starts at 0 after
        // pairing. Starting next_cmd_counter at 1 keeps the wire human-readable.
        Self {
            next_cmd_counter: 1,
        }
    }
}

/// Load state from disk. Returns Ok(None) if the file is missing — the
/// caller decides whether to start fresh or fail.
pub fn load() -> Result<Option<State>> {
    let path = Path::new(STATE_PATH);
    if !path.exists() {
        return Ok(None);
    }
    // Refuse a state file that's readable/writable by anyone but root. save()
    // always writes 0600; anything looser means the file was tampered with or
    // left behind by a buggy migration (audit 2026-05-28 / M3).
    let mode = fs::metadata(STATE_PATH)
        .with_context(|| format!("stat {}", STATE_PATH))?
        .permissions()
        .mode()
        & 0o777;
    if mode != 0o600 {
        bail!("insecure mode {:o} on {} (expected 0600)", mode, STATE_PATH);
    }
    let bytes = fs::read(STATE_PATH).with_context(|| format!("reading {}", STATE_PATH))?;
    let state: State =
        serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", STATE_PATH))?;
    Ok(Some(state))
}

/// Atomic write: tmp + fsync + rename.
pub fn save(state: &State) -> Result<()> {
    fs::create_dir_all(STATE_DIR).with_context(|| format!("creating {}", STATE_DIR))?;
    fs::set_permissions(STATE_DIR, fs::Permissions::from_mode(0o700)).ok();

    let tmp = format!("{}.tmp", STATE_PATH);
    let json = serde_json::to_vec_pretty(state).context("serializing state")?;
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("creating {}", tmp))?;
        f.write_all(&json)?;
        f.write_all(b"\n")?;
        f.sync_all()?;
    }
    fs::rename(&tmp, STATE_PATH).with_context(|| format!("renaming {} → {}", tmp, STATE_PATH))?;
    Ok(())
}

pub fn delete() -> Result<()> {
    match fs::remove_file(STATE_PATH) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("removing {}", STATE_PATH)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_starts_at_one() {
        assert_eq!(State::fresh().next_cmd_counter, 1);
    }

    #[test]
    fn round_trip_serde() {
        let s = State {
            next_cmd_counter: 42,
        };
        let j = serde_json::to_string(&s).unwrap();
        let back: State = serde_json::from_str(&j).unwrap();
        assert_eq!(back.next_cmd_counter, 42);
    }
}
