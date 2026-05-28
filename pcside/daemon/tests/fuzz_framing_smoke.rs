//! Stable-Rust property fuzzer for the wire frame parsers.
//!
//! Runs ~100 000 inputs against `framing::parse_command`,
//! `framing::parse_response`, `framing::verify_command`, and
//! `framing::verify_response`. The invariant is **must not panic** — the
//! parsers should reject malformed input via `Result::Err`, never via
//! unwrap / index-out-of-bounds / arithmetic overflow.
//!
//! Why not `cargo fuzz`? `cargo fuzz` requires nightly + libFuzzer; the
//! project's CI is stable. We ship the cargo-fuzz scaffolding under
//! `fuzz/` for anyone with nightly to run a long-corpus pass, and this
//! test enforces the same no-crash invariant on every PR using only stable
//! tooling. Crypto-posture review item #10.
//!
//! The corpus is generated three ways for breadth:
//!   1. Uniform random bytes (mostly garbage; catches panics on early bail).
//!   2. ASCII-printable random (covers parser-internal path coverage).
//!   3. Mutations of a valid frame (one-byte flips, truncations, splices).

use r503d::{crypto, framing};

struct Xs64(u64);
impl Xs64 {
    fn new(seed: u64) -> Self { Self(seed.max(1)) }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

const K: [u8; 16] = [
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
];

fn poke_all(input: &[u8]) {
    // The parsers want `&str`; coerce via lossy UTF-8 so we can fuzz raw
    // byte sequences (NULs, invalid UTF-8, etc.) without the wrapper
    // panicking before the parser sees the input.
    let s = String::from_utf8_lossy(input);
    let _ = framing::parse_command(&s);
    let _ = framing::parse_response(&s);
    let _ = framing::verify_command(&K, &s);
    let _ = framing::verify_response(&K, &s);
}

#[test]
fn no_parser_panics_on_random_bytes() {
    let mut rng = Xs64::new(0x0123_4567_89AB_CDEF);
    for _ in 0..50_000 {
        // Lengths 0..256, biased toward "around the framing minimum"
        let len = ((rng.next() & 0x1ff) as usize) % 257;
        let mut buf = vec![0u8; len];
        for byte in buf.iter_mut() {
            *byte = (rng.next() & 0xff) as u8;
        }
        poke_all(&buf);
    }
}

#[test]
fn no_parser_panics_on_random_ascii_printable() {
    let mut rng = Xs64::new(0xFEED_FACE_DEAD_BEEF);
    let alphabet: &[u8] = b"0123456789abcdefABCDEF M CR \n\t \x00";
    for _ in 0..30_000 {
        let len = ((rng.next() & 0x1ff) as usize) % 257;
        let mut buf = vec![0u8; len];
        for byte in buf.iter_mut() {
            let idx = (rng.next() as usize) % alphabet.len();
            *byte = alphabet[idx];
        }
        poke_all(&buf);
    }
}

#[test]
fn no_parser_panics_on_mutated_valid_frames() {
    let mut rng = Xs64::new(0xCAFE_BABE_5555_AAAA);

    // Two valid frames to mutate from: a command and a response.
    let cmd = framing::encode_command(&K, 42, "verify 0");
    let resp = framing::encode_response(&K, 42, 0, "OK match=0 confidence=168");

    for base in [cmd.as_bytes(), resp.as_bytes()] {
        for _ in 0..15_000 {
            let mut buf = base.to_vec();
            // Mutation menu: byte-flip, truncate, splice-insert, byte-zero.
            match rng.next() % 4 {
                0 => {
                    // single-byte flip at random offset
                    if !buf.is_empty() {
                        let off = (rng.next() as usize) % buf.len();
                        buf[off] ^= (rng.next() & 0xff) as u8;
                    }
                }
                1 => {
                    // truncate to 0..len
                    let n = (rng.next() as usize) % (buf.len() + 1);
                    buf.truncate(n);
                }
                2 => {
                    // splice a random byte at a random offset
                    if !buf.is_empty() {
                        let off = (rng.next() as usize) % buf.len();
                        let b = (rng.next() & 0xff) as u8;
                        buf.insert(off, b);
                    }
                }
                _ => {
                    // zero a random byte
                    if !buf.is_empty() {
                        let off = (rng.next() as usize) % buf.len();
                        buf[off] = 0;
                    }
                }
            }
            poke_all(&buf);
        }
    }
}

#[test]
fn verify_command_round_trips_for_random_inputs() {
    // Stronger invariant: for any random (counter, body), encode → verify
    // must succeed. Catches encode/parse asymmetries.
    let mut rng = Xs64::new(0x1357_9bdf_2468_ace0);
    for _ in 0..10_000 {
        let counter = rng.next() & ((1u64 << 53) - 1); // keep printable
        // Random ASCII-printable body, length 1..40
        let body_len = 1 + ((rng.next() as usize) % 40);
        let body: String = (0..body_len)
            .map(|_| {
                let c = b'!' + ((rng.next() & 0x5d) as u8); // 0x21..0x7e
                c.min(0x7e) as char
            })
            .collect();
        let frame = framing::encode_command(&K, counter, &body);
        let got = framing::verify_command(&K, &frame).expect("encode→verify must round-trip");
        assert_eq!(got.0, counter);
        assert_eq!(got.1, body);
    }
}

#[test]
fn verify_response_round_trips_for_random_inputs() {
    let mut rng = Xs64::new(0xc0ff_eede_adbe_ef13);
    for _ in 0..10_000 {
        let counter = rng.next() & ((1u64 << 53) - 1);
        let seq = (rng.next() & 0xffff) as u32;
        let body_len = 1 + ((rng.next() as usize) % 40);
        let body: String = (0..body_len)
            .map(|_| {
                let c = b'!' + ((rng.next() & 0x5d) as u8);
                c.min(0x7e) as char
            })
            .collect();
        let frame = framing::encode_response(&K, counter, seq, &body);
        let got = framing::verify_response(&K, &frame).expect("encode→verify must round-trip");
        assert_eq!(got.0, counter);
        assert_eq!(got.1, seq);
        assert_eq!(got.2, body);
    }
}

#[test]
fn siphash_does_not_panic_on_random_inputs() {
    // Defensive: even though siphash24 has no length-dependent panics in
    // its math (verified by code review), assert no panic across a wide
    // input distribution. Catches future regressions if the impl is ever
    // edited.
    let mut rng = Xs64::new(0xfeed_5aff_a55a_5555);
    for _ in 0..20_000 {
        let mut key = [0u8; 16];
        for b in key.iter_mut() {
            *b = (rng.next() & 0xff) as u8;
        }
        let len = (rng.next() as usize) % 2048;
        let mut msg = vec![0u8; len];
        for b in msg.iter_mut() {
            *b = (rng.next() & 0xff) as u8;
        }
        let _ = crypto::siphash24(&key, &msg);
    }
}
