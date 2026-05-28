//! SipHash-2-4 keyed PRF.
//!
//! Hand-rolled mirror of `firmware/r503fp/siphash.h`. The two impls must
//! produce bit-identical MACs — see `tests` below for the canonical Aumasson
//! vectors, and the firmware integration tests in `tests/siphash_xverify.rs`
//! for the cross-implementation check.
//!
//! MAC wire format is little-endian: byte 0 = `mac & 0xff`, byte 7 = `mac >> 56`.

#![allow(dead_code)] // used by upcoming framing/pairing modules

#[inline]
fn rotl64(x: u64, b: u32) -> u64 {
    x.rotate_left(b)
}

#[inline]
fn load_u64_le(p: &[u8]) -> u64 {
    debug_assert!(p.len() >= 8);
    u64::from_le_bytes(p[..8].try_into().unwrap())
}

macro_rules! sipround {
    ($v0:expr, $v1:expr, $v2:expr, $v3:expr) => {{
        $v0 = $v0.wrapping_add($v1);
        $v1 = rotl64($v1, 13);
        $v1 ^= $v0;
        $v0 = rotl64($v0, 32);
        $v2 = $v2.wrapping_add($v3);
        $v3 = rotl64($v3, 16);
        $v3 ^= $v2;
        $v0 = $v0.wrapping_add($v3);
        $v3 = rotl64($v3, 21);
        $v3 ^= $v0;
        $v2 = $v2.wrapping_add($v1);
        $v1 = rotl64($v1, 17);
        $v1 ^= $v2;
        $v2 = rotl64($v2, 32);
    }};
}

pub fn siphash24(key: &[u8; 16], msg: &[u8]) -> u64 {
    let k0 = load_u64_le(&key[0..8]);
    let k1 = load_u64_le(&key[8..16]);

    let mut v0 = k0 ^ 0x736f6d6570736575u64;
    let mut v1 = k1 ^ 0x646f72616e646f6du64;
    let mut v2 = k0 ^ 0x6c7967656e657261u64;
    let mut v3 = k1 ^ 0x7465646279746573u64;

    let blocks = msg.len() / 8;
    for i in 0..blocks {
        let m = load_u64_le(&msg[i * 8..]);
        v3 ^= m;
        sipround!(v0, v1, v2, v3);
        sipround!(v0, v1, v2, v3);
        v0 ^= m;
    }

    // Final block: leftover bytes + (len & 0xff) << 56.
    let mut b: u64 = ((msg.len() as u64) & 0xff) << 56;
    let tail = &msg[blocks * 8..];
    for (i, &byte) in tail.iter().enumerate() {
        b |= (byte as u64) << (i * 8);
    }

    v3 ^= b;
    sipround!(v0, v1, v2, v3);
    sipround!(v0, v1, v2, v3);
    v0 ^= b;

    v2 ^= 0xff;
    sipround!(v0, v1, v2, v3);
    sipround!(v0, v1, v2, v3);
    sipround!(v0, v1, v2, v3);
    sipround!(v0, v1, v2, v3);

    v0 ^ v1 ^ v2 ^ v3
}

/// Wire form of the MAC: 8 bytes, little-endian.
pub fn mac_to_le_bytes(mac: u64) -> [u8; 8] {
    mac.to_le_bytes()
}

/// Lowercase hex of the wire-form MAC. 16 chars.
pub fn mac_to_hex(mac: u64) -> String {
    let bytes = mac_to_le_bytes(mac);
    let mut s = String::with_capacity(16);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const STANDARD_KEY: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    // Canonical Aumasson/Bernstein test vectors. Reference C implementation
    // emits MAC bytes in transmission order (little-endian).
    fn check_vector(msg_len: usize, want_le: [u8; 8]) {
        let msg: Vec<u8> = (0..msg_len as u8).collect();
        let mac = siphash24(&STANDARD_KEY, &msg);
        let got = mac_to_le_bytes(mac);
        assert_eq!(
            got, want_le,
            "msg_len={} got={:02x?} want={:02x?}",
            msg_len, got, want_le
        );
    }

    #[test]
    fn vector_len_0() {
        check_vector(0, [0x31, 0x0e, 0x0e, 0xdd, 0x47, 0xdb, 0x6f, 0x72]);
    }

    #[test]
    fn vector_len_1() {
        check_vector(1, [0xfd, 0x67, 0xdc, 0x93, 0xc5, 0x39, 0xf8, 0x74]);
    }

    #[test]
    fn vector_len_8() {
        // Block-boundary case: exactly one full block + zero-byte tail.
        check_vector(8, [0x62, 0x24, 0x93, 0x9a, 0x79, 0xf5, 0xf5, 0x93]);
    }

    #[test]
    fn vector_len_15() {
        // One full block + 7-byte tail (max partial). Most common boundary bug.
        check_vector(15, [0xe5, 0x45, 0xbe, 0x49, 0x61, 0xca, 0x29, 0xa1]);
    }

    #[test]
    fn deterministic() {
        let key = [0x42u8; 16];
        let msg = b"hello world";
        assert_eq!(siphash24(&key, msg), siphash24(&key, msg));
    }

    #[test]
    fn different_keys_distinct() {
        let k1 = [1u8; 16];
        let k2 = [2u8; 16];
        let msg = b"identical message";
        assert_ne!(siphash24(&k1, msg), siphash24(&k2, msg));
    }

    #[test]
    fn different_msgs_distinct() {
        let key = [0x42u8; 16];
        assert_ne!(siphash24(&key, b"foo"), siphash24(&key, b"bar"));
    }

    #[test]
    fn block_boundary_changes_mac() {
        // Catches off-by-one in the block-loop vs final-block split.
        let key = [0x42u8; 16];
        let msg7 = b"1234567";
        let msg8 = b"12345678";
        let msg9 = b"123456789";
        let m7 = siphash24(&key, msg7);
        let m8 = siphash24(&key, msg8);
        let m9 = siphash24(&key, msg9);
        assert_ne!(m7, m8);
        assert_ne!(m8, m9);
        assert_ne!(m7, m9);
    }

    #[test]
    fn mac_to_hex_format() {
        // mac = 0x726fdb47dd0e0e31 → wire bytes 31 0e 0e dd 47 db 6f 72 → hex "310e0edd47db6f72"
        let mac: u64 = 0x726f_db47_dd0e_0e31;
        assert_eq!(mac_to_hex(mac), "310e0edd47db6f72");
    }

    #[test]
    fn empty_key_distinct_from_standard_key() {
        let empty_key = [0u8; 16];
        let msg = b"hello";
        assert_ne!(siphash24(&empty_key, msg), siphash24(&STANDARD_KEY, msg));
    }
}
