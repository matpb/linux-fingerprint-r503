//! Host-side key & pairing-opt-in state for the v2 authenticated channel
//! (SPEC §13.5, §13.6).
//!
//! Layout:
//!   /etc/r503d/allow-pair         (opt-in flag; presence = "host consents to pair")
//!   /var/lib/r503d/key            (live key, 32 hex chars + newline, mode 0600 root:root)
//!   /var/lib/r503d/key.bak        (read-only fallback, mode 0400 root:root)
//!
//! `load_key` returns the live key if present, falling through to .bak. `save_key`
//! writes the live file atomically (tmp + rename) then copies to .bak. `delete_key`
//! removes both.

#![allow(dead_code)] // wired into main.rs --pair / --unpair flows

use anyhow::{bail, Context, Result};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

pub const KEY_DIR: &str = "/var/lib/r503d";
pub const KEY_PATH: &str = "/var/lib/r503d/key";
pub const KEY_BAK_PATH: &str = "/var/lib/r503d/key.bak";
pub const ALLOW_PAIR_DIR: &str = "/etc/r503d";
pub const ALLOW_PAIR_PATH: &str = "/etc/r503d/allow-pair";

pub fn allow_pair_present() -> bool {
    Path::new(ALLOW_PAIR_PATH).exists()
}

/// Remove the allow-pair opt-in marker. Idempotent.
pub fn remove_allow_pair() -> Result<()> {
    match fs::remove_file(ALLOW_PAIR_PATH) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).context("removing allow-pair marker"),
    }
}

pub fn load_key() -> Option<[u8; 16]> {
    for p in [KEY_PATH, KEY_BAK_PATH] {
        if let Ok(s) = fs::read_to_string(p) {
            if let Ok(k) = parse_key_hex(s.trim()) {
                return Some(k);
            }
        }
    }
    None
}

/// Write the key atomically to `KEY_PATH` (mode 0600), then copy to
/// `KEY_BAK_PATH` (mode 0400). Both files end in a single newline.
pub fn save_key(key: &[u8; 16]) -> Result<()> {
    // Ensure the parent directory exists with restrictive perms.
    fs::create_dir_all(KEY_DIR).with_context(|| format!("creating {}", KEY_DIR))?;
    fs::set_permissions(KEY_DIR, fs::Permissions::from_mode(0o700)).ok();

    let hex = key_hex(key);
    let tmp = format!("{}.tmp", KEY_PATH);

    // tmp file: 0600.
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("creating {}", tmp))?;
        f.write_all(hex.as_bytes())?;
        f.write_all(b"\n")?;
        f.sync_all()?;
    }
    fs::rename(&tmp, KEY_PATH)
        .with_context(|| format!("renaming {} → {}", tmp, KEY_PATH))?;

    // Backup copy: 0400.
    fs::copy(KEY_PATH, KEY_BAK_PATH)
        .with_context(|| format!("copying {} → {}", KEY_PATH, KEY_BAK_PATH))?;
    fs::set_permissions(KEY_BAK_PATH, fs::Permissions::from_mode(0o400)).ok();
    Ok(())
}

/// Remove both key files. Idempotent — missing files are not an error.
pub fn delete_key() -> Result<()> {
    for p in [KEY_PATH, KEY_BAK_PATH] {
        match fs::remove_file(p) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("removing {}", p)),
        }
    }
    Ok(())
}

pub fn generate_key() -> Result<[u8; 16]> {
    let mut key = [0u8; 16];
    let mut f = fs::File::open("/dev/urandom").context("opening /dev/urandom")?;
    f.read_exact(&mut key).context("reading /dev/urandom")?;
    Ok(key)
}

pub fn key_hex(key: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for b in key {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

pub fn parse_key_hex(s: &str) -> Result<[u8; 16]> {
    if s.len() != 32 {
        bail!("key must be 32 hex chars, got {}", s.len());
    }
    let mut out = [0u8; 16];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = nybble(chunk[0])?;
        let lo = nybble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn nybble(c: u8) -> Result<u8> {
    Ok(match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => 10 + c - b'a',
        b'A'..=b'F' => 10 + c - b'A',
        _ => bail!("non-hex byte: {:?}", c as char),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_hex() {
        let k: [u8; 16] = std::array::from_fn(|i| i as u8 * 17);
        let h = key_hex(&k);
        let back = parse_key_hex(&h).unwrap();
        assert_eq!(k, back);
    }

    #[test]
    fn known_vector() {
        let k = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        assert_eq!(key_hex(&k), "000102030405060708090a0b0c0d0e0f");
    }

    #[test]
    fn parse_rejects_wrong_length() {
        assert!(parse_key_hex("deadbeef").is_err());
    }

    #[test]
    fn parse_rejects_bad_chars() {
        let mut s = String::from("0102030405060708090a0b0c0d0e0f10");
        unsafe { s.as_bytes_mut()[0] = b'!'; }
        assert!(parse_key_hex(&s).is_err());
    }
}
