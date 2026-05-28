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
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use zeroize::Zeroizing;

pub const KEY_DIR: &str = "/var/lib/r503d";
pub const KEY_PATH: &str = "/var/lib/r503d/key";
pub const KEY_BAK_PATH: &str = "/var/lib/r503d/key.bak";
/// TPM2-sealed copy of the host key (SPEC §13.12). Binary blob produced by
/// `crate::tpm::seal_key`, unsealed at boot. When this exists the daemon
/// MUST use it — falling through to plaintext would defeat the seal.
pub const KEY_TPM_PATH: &str = "/var/lib/r503d/key.tpm";
pub const ALLOW_PAIR_DIR: &str = "/etc/r503d";
pub const ALLOW_PAIR_PATH: &str = "/etc/r503d/allow-pair";

/// Where a key on disk came from. Surfaces in logs so the operator can tell
/// at a glance whether the daemon is running in plaintext-key mode (the
/// original v2 deployment) or TPM-sealed mode (SPEC §13.12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    Plaintext,
    Tpm,
}

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

pub fn load_key() -> Option<Zeroizing<[u8; 16]>> {
    for p in [KEY_PATH, KEY_BAK_PATH] {
        if let Ok(s) = fs::read_to_string(p) {
            // Wrap the hex form too — it's just as sensitive as the bytes
            // and lives on the heap until the trim()'d slice is parsed.
            let hex = Zeroizing::new(s);
            if let Ok(k) = parse_key_hex(hex.trim()) {
                return Some(k);
            }
        }
    }
    None
}

/// Load the host key in TPM-aware order: sealed blob first, plaintext fallback
/// ONLY when no sealed blob exists. When `KEY_TPM_PATH` is present, this
/// function either returns the unsealed key or errors — it will not silently
/// fall back to plaintext (which would defeat the seal). The caller is
/// expected to surface the error and refuse to start.
pub fn load_key_with_source() -> Result<Option<(Zeroizing<[u8; 16]>, KeySource)>> {
    if Path::new(KEY_TPM_PATH).exists() {
        let blob = fs::read(KEY_TPM_PATH)
            .with_context(|| format!("reading sealed key blob at {}", KEY_TPM_PATH))?;
        let key = crate::tpm::unseal_key(&blob).context(
            "unsealing TPM-protected host key. \
                 The Secure Boot policy (PCR7) changed since this key was sealed. \
                 Recovery: `sudo dist/reseal-tpm.sh` (SPEC §13.12).",
        )?;
        return Ok(Some((key, KeySource::Tpm)));
    }
    if let Some(k) = load_key() {
        return Ok(Some((k, KeySource::Plaintext)));
    }
    Ok(None)
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

/// Overwrite the existing file's bytes with 0xFF before unlinking. On
/// classic block filesystems this rewrites the same disk blocks; on
/// copy-on-write filesystems (btrfs, zfs) and SSDs with TRIM the prior
/// extents may persist until reused — full guarantees need at-rest
/// encryption (LUKS) underneath. This is hygiene, not absolute erasure.
fn shred_file(path: &str) -> std::io::Result<()> {
    // 33 = 32 hex chars + newline. Match the on-disk layout so block
    // boundaries line up on the fs side.
    let zap = [0xFFu8; 33];
    match fs::OpenOptions::new().write(true).truncate(false).open(path) {
        Ok(mut f) => {
            f.write_all(&zap)?;
            f.sync_all()?;
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Remove both plaintext key files. Idempotent — missing files are not an
/// error. Shreds contents (0xFF-overwrite + fsync) before unlink as a
/// best-effort defense against post-delete recovery from raw disk reads.
pub fn delete_key() -> Result<()> {
    for p in [KEY_PATH, KEY_BAK_PATH] {
        // KEY_BAK is 0400 — flip to writable before shred, otherwise the
        // overwrite fails with EACCES.
        fs::set_permissions(p, fs::Permissions::from_mode(0o600)).ok();
        if let Err(e) = shred_file(p) {
            tracing::warn!(path = p, error = %e, "shred_file failed; continuing to unlink");
        }
        match fs::remove_file(p) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("removing {}", p)),
        }
    }
    Ok(())
}

/// Seal the key to PCR7 (default) and write `KEY_TPM_PATH` atomically.
/// Equivalent to `save_key_sealed_with_pcrs(key, &[7])`.
pub fn save_key_sealed(key: &[u8; 16]) -> Result<()> {
    save_key_sealed_with_pcrs(key, &[7])
}

/// Seal the key to a caller-chosen PCR set and write `KEY_TPM_PATH`
/// atomically. Deletes any plaintext key copies on success — keeping them
/// would defeat the seal. The PCR set is encoded into the sealed blob so the
/// unseal path uses the same policy automatically (see `tpm::deserialize_blob`).
pub fn save_key_sealed_with_pcrs(key: &[u8; 16], pcrs: &[u8]) -> Result<()> {
    let blob = crate::tpm::seal_key_with_pcrs(key, pcrs)
        .with_context(|| format!("sealing key to TPM (PCRs {:?})", pcrs))?;

    fs::create_dir_all(KEY_DIR).with_context(|| format!("creating {}", KEY_DIR))?;
    fs::set_permissions(KEY_DIR, fs::Permissions::from_mode(0o700)).ok();

    let tmp = format!("{}.tmp", KEY_TPM_PATH);
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("creating {}", tmp))?;
        f.write_all(&blob)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, KEY_TPM_PATH)
        .with_context(|| format!("renaming {} → {}", tmp, KEY_TPM_PATH))?;

    // Wipe plaintext copies. The whole point of sealing is that the key isn't
    // sitting in plaintext on disk anymore.
    delete_key().ok();
    Ok(())
}

/// Remove the sealed-key blob. Idempotent.
pub fn delete_sealed_key() -> Result<()> {
    match fs::remove_file(KEY_TPM_PATH) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("removing {}", KEY_TPM_PATH)),
    }
}

/// Remove every host-side copy of the key — plaintext and sealed. Used by
/// `--unpair` and at the start of `--reseal-tpm`.
pub fn delete_all_keys() -> Result<()> {
    delete_key()?;
    delete_sealed_key()?;
    Ok(())
}

/// Generate a fresh 128-bit key via the `getrandom(2)` syscall (SPEC §13.2).
/// `getrandom` blocks until the kernel CSPRNG pool is seeded; the resulting
/// bytes are wrapped in `Zeroizing` so they scrub on drop.
pub fn generate_key() -> Result<Zeroizing<[u8; 16]>> {
    let mut key = Zeroizing::new([0u8; 16]);
    getrandom::fill(&mut *key)
        .map_err(|e| anyhow::anyhow!("getrandom(2) failed: {e}"))?;
    Ok(key)
}

/// Hex form of the key. Returned `Zeroizing<String>` scrubs the heap-allocated
/// buffer on drop so a `String::clone` floating around can't outlive use.
pub fn key_hex(key: &[u8; 16]) -> Zeroizing<String> {
    let mut s = String::with_capacity(32);
    for b in key {
        s.push_str(&format!("{:02x}", b));
    }
    Zeroizing::new(s)
}

pub fn parse_key_hex(s: &str) -> Result<Zeroizing<[u8; 16]>> {
    if s.len() != 32 {
        bail!("key must be 32 hex chars, got {}", s.len());
    }
    let mut out = Zeroizing::new([0u8; 16]);
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
        assert_eq!(k, *back);
    }

    #[test]
    fn known_vector() {
        let k = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        assert_eq!(&*key_hex(&k), "000102030405060708090a0b0c0d0e0f");
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
