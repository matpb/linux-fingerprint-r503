//! Smoke test for the TPM2 seal/unseal path (SPEC §13.12). Run with:
//!
//!     sudo target/debug/examples/tpm_smoketest
//!
//! Doesn't touch the Nano or any production state files. Just exercises
//! `tpm::seal_key` and `tpm::unseal_key` against a synthetic 16-byte key,
//! reads PCR7, and reports timings. Useful during development and as a
//! one-shot "does this host's TPM actually work" probe.
//!
//! NOTE: needs `/dev/tpmrm0` read+write. The daemon gets that as root; for
//! the smoke test you either run as root or add yourself to the `tss` group.

use std::time::Instant;

use anyhow::Result;
use r503d::tpm;

fn main() -> Result<()> {
    if !tpm::device_present() {
        anyhow::bail!("no TPM device at {} on this host", tpm::TPM_DEVICE);
    }

    let pcr7 = tpm::current_pcr7_hex()?;
    println!("PCR7 (sha256):  {}", pcr7);

    let key: [u8; 16] = [
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x23, 0x45, 0x67,
        0x89, 0xab, 0xcd, 0xef,
    ];
    println!("input key:      {}", hex16(&key));

    let t0 = Instant::now();
    let blob = tpm::seal_key(&key)?;
    let seal_ms = t0.elapsed().as_millis();
    println!("sealed blob:    {} bytes (in {} ms)", blob.len(), seal_ms);

    let t1 = Instant::now();
    let recovered = tpm::unseal_key(&blob)?;
    let unseal_ms = t1.elapsed().as_millis();
    println!("unsealed:       {} (in {} ms)", hex16(&recovered), unseal_ms);

    if recovered != key {
        anyhow::bail!("round-trip mismatch");
    }
    println!("OK: round-trip succeeded");
    Ok(())
}

fn hex16(k: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for b in k {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
