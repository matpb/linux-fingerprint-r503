//! Cross-implementation property test: in-tree `crypto::siphash24` vs
//! the third-party `siphasher` crate. The two must agree bit-for-bit on
//! 1024 random (key, msg) pairs. A divergence here means the in-tree
//! hand-rolled SipHash-2-4 has a bug the canonical KAT vectors didn't
//! catch — making this assertion loud closes one of the strongest
//! "no formal review" rebuttals.
//!
//! `siphasher` is the descendant of Rust's `std::hash::SipHasher` (which
//! was SipHash-2-4 until deprecation), MIT-licensed, widely depended on
//! (serde-rs and millions of downstream crates pull it transitively). It
//! is not the same implementation as the in-tree one — both are
//! independently written.
//!
//! Seeded RNG: deterministic CI failures, reproducible from the seed.

use r503d::crypto;
use siphasher::sip::SipHasher24;
use std::hash::Hasher;

/// xorshift64* — tiny deterministic RNG. We don't need cryptographic
/// quality random for a test that's checking bit-for-bit equality; we
/// just need reproducibility from a seed.
struct Xs64(u64);
impl Xs64 {
    fn new(seed: u64) -> Self { Self(seed.max(1)) }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn fill(&mut self, buf: &mut [u8]) {
        let mut i = 0;
        while i < buf.len() {
            let w = self.next_u64().to_le_bytes();
            let n = (buf.len() - i).min(8);
            buf[i..i + n].copy_from_slice(&w[..n]);
            i += n;
        }
    }
}

fn siphasher_mac(key: &[u8; 16], msg: &[u8]) -> u64 {
    // siphasher exposes SipHasher24 with a 16-byte key via `new_with_key`
    // (older versions) or two-u64 `with_keys`. The two-u64 form is the
    // canonical SipHash key interpretation — low 8 bytes = k0, high 8 = k1
    // — matching what our in-tree impl computes in `load_u64_le(&key[0..8])`
    // and `load_u64_le(&key[8..16])`.
    let k0 = u64::from_le_bytes(key[0..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(key[8..16].try_into().unwrap());
    let mut h = SipHasher24::new_with_keys(k0, k1);
    h.write(msg);
    h.finish()
}

#[test]
fn matches_siphasher_on_1024_random_vectors() {
    // Fixed seed for reproducibility. Bump if you ever need fresh coverage.
    let mut rng = Xs64::new(0xDEAD_BEEF_F00D_BABE);
    let mut mismatches = Vec::new();

    for i in 0..1024 {
        let mut key = [0u8; 16];
        rng.fill(&mut key);

        // Vary message length across short / block-boundary / long. The
        // distribution targets the lengths most likely to expose bugs:
        // 0, 1..7 (sub-block tail), 8 (exact block), 9..15 (one block + tail),
        // 16 (two blocks), 17..63 (multi-block), 64+ (large input).
        let len = match i % 16 {
            0 => 0,
            1 => 1,
            2 => 7,
            3 => 8,
            4 => 9,
            5 => 15,
            6 => 16,
            7 => 17,
            8 => 31,
            9 => 32,
            10 => 33,
            11 => 63,
            12 => 64,
            13 => 65,
            14 => 127,
            _ => (rng.next_u64() & 0xff) as usize, // 0..255
        };
        let mut msg = vec![0u8; len];
        rng.fill(&mut msg);

        let ours = crypto::siphash24(&key, &msg);
        let theirs = siphasher_mac(&key, &msg);
        if ours != theirs {
            mismatches.push((i, len, key, msg.clone(), ours, theirs));
            if mismatches.len() <= 5 {
                eprintln!(
                    "DIVERGENCE @ vector #{i} (len={len}): ours={ours:016x} theirs={theirs:016x}\n  key={key:02x?}\n  msg={msg:02x?}"
                );
            }
        }
    }

    assert!(
        mismatches.is_empty(),
        "{} of 1024 random vectors diverged between in-tree crypto::siphash24 and the third-party siphasher::sip::SipHasher24 crate. \
         This means our hand-rolled SipHash-2-4 has a bug the canonical KAT vectors did not catch. \
         The first few are printed above for triage.",
        mismatches.len()
    );
}

#[test]
fn matches_siphasher_on_canonical_aumasson_vectors() {
    // Sanity layer: same 0/1/8/15-byte vectors that crypto.rs already
    // asserts against, but here cross-checked against the siphasher crate.
    // If this fails, the divergence is in either our impl OR siphasher's,
    // and the next clue is checking which side matches the Aumasson MACs
    // in `crypto.rs::tests`. (Spoiler: both should match.)
    const K: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    ];
    for len in [0usize, 1, 7, 8, 9, 15, 16, 17, 31, 32, 63, 64, 65, 127] {
        let msg: Vec<u8> = (0..len as u8).collect();
        assert_eq!(
            crypto::siphash24(&K, &msg),
            siphasher_mac(&K, &msg),
            "divergence at len={}",
            len
        );
    }
}
