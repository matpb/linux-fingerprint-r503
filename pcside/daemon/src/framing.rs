//! v2 wire framing per SPEC §13.3.
//!
//! Command (host → Nano):   `C <counter> <cmd_line> M <mac_hex>`
//! Response (Nano → host):  `R <counter> <seq> <body_line> M <mac_hex>`
//!
//! MAC inputs are domain-separated to prevent reflection attacks:
//!   cmd:  `CMD <counter> <cmd_line>`
//!   resp: `RSP <counter> <seq> <body_line>`
//!
//! Mirror of `firmware/r503fp/framing.h`. Any change here must be mirrored on
//! the firmware side, and the cross-verify in `examples/siphash_cli.rs` /
//! `/tmp/framing_xverify.py` must be re-run.

#![allow(dead_code)] // wired into sensor.rs at Milestone E cutover

use crate::crypto;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const MAC_HEX_LEN: usize = 16;
const MAC_SUFFIX_LEN: usize = 3 + MAC_HEX_LEN; // " M " + 16 hex

/// Reserved high band of the 64-bit command counter. Counters at or above this
/// value are refused by BOTH ends so the monotonic counter can never be driven
/// to (or near) `u64::MAX` — which would brick the authenticated channel: once
/// the firmware commits `last_seen = MAX` to EEPROM, every future command
/// (including the framed `unpair` recovery) needs `ctr > MAX`, impossible, and
/// the only recovery is a physical reflash. The reserved band is 2^16 slots;
/// the lifetime maximum is ~1.6M increments (~88 years at 50 logins/day, SPEC
/// §13.4), so the ceiling is unreachable in normal operation. Value MUST be
/// mirrored exactly in `firmware/r503fp/framing.h` (`COUNTER_CEILING`).
/// (Security audit 2026-05-28 / firmware DoS-2.)
pub const COUNTER_CEILING: u64 = 0xFFFF_FFFF_FFFF_0000;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FramingError {
    #[error("frame too short ({0} bytes)")]
    TooShort(usize),
    #[error("missing leading `{expected} `")]
    WrongLeader { expected: char },
    #[error("missing ` M <mac>` suffix")]
    MissingMacSuffix,
    #[error("invalid mac hex")]
    InvalidMac,
    #[error("invalid counter")]
    InvalidCounter,
    #[error("invalid seq")]
    InvalidSeq,
    #[error("mac mismatch")]
    MacMismatch,
}

// ---------- command frames ----------

pub fn encode_command(key: &[u8; 16], counter: u64, cmd_line: &str) -> String {
    // Zeroizing: scrub the heap-allocated MAC input on drop. The input is
    // public per the protocol (command text + counter), so this is hygiene/
    // consistency with the rest of the key path, not a confidentiality fix
    // (audit 2026-05-28 / L2).
    let mac_input = Zeroizing::new(format!("CMD {} {}", counter, cmd_line));
    let mac = crypto::siphash24(key, mac_input.as_bytes());
    format!("C {} {} M {}", counter, cmd_line, crypto::mac_to_hex(mac))
}

/// Parse a command frame WITHOUT verifying the MAC. Returns
/// (counter, cmd_line, claimed_mac). Use `verify_command` when you have the key.
pub fn parse_command(line: &str) -> Result<(u64, &str, u64), FramingError> {
    let rest = line
        .strip_prefix("C ")
        .ok_or(FramingError::WrongLeader { expected: 'C' })?;
    let (head, mac) = split_mac_suffix(rest)?;
    let (counter, cmd_line) = split_counter_body(head)?;
    Ok((counter, cmd_line, mac))
}

/// Parse + MAC-verify a command frame. Returns (counter, cmd_line).
pub fn verify_command<'a>(key: &[u8; 16], line: &'a str) -> Result<(u64, &'a str), FramingError> {
    let (counter, cmd_line, claimed) = parse_command(line)?;
    let mac_input = Zeroizing::new(format!("CMD {} {}", counter, cmd_line));
    let expected = crypto::siphash24(key, mac_input.as_bytes());
    // `subtle::ConstantTimeEq` is the canonical constant-time equality on the
    // host side. The previous XOR + branch-on-zero was *intended* constant-
    // time but Rust gives no codegen guarantee; `ct_eq` is the standard
    // mitigation. Crypto-posture review item #1 (P1). Mirrored on firmware
    // (`framing.h::verify_command_frame`) via XOR-OR over 8 bytes — safe in
    // C++ because both sides write to the same accumulator unconditionally.
    if !bool::from(expected.ct_eq(&claimed)) {
        return Err(FramingError::MacMismatch);
    }
    Ok((counter, cmd_line))
}

// ---------- response frames ----------

pub fn encode_response(key: &[u8; 16], counter: u64, seq: u32, body_line: &str) -> String {
    let mac_input = Zeroizing::new(format!("RSP {} {} {}", counter, seq, body_line));
    let mac = crypto::siphash24(key, mac_input.as_bytes());
    format!(
        "R {} {} {} M {}",
        counter,
        seq,
        body_line,
        crypto::mac_to_hex(mac)
    )
}

/// Parse a response frame WITHOUT verifying. Returns (counter, seq, body, mac).
pub fn parse_response(line: &str) -> Result<(u64, u32, &str, u64), FramingError> {
    let rest = line
        .strip_prefix("R ")
        .ok_or(FramingError::WrongLeader { expected: 'R' })?;
    let (head, mac) = split_mac_suffix(rest)?;
    let sp1 = head.find(' ').ok_or(FramingError::TooShort(head.len()))?;
    let counter = parse_strict_u64(&head[..sp1]).ok_or(FramingError::InvalidCounter)?;
    let rest1 = &head[sp1 + 1..];
    let sp2 = rest1.find(' ').ok_or(FramingError::TooShort(rest1.len()))?;
    let seq = parse_strict_u32(&rest1[..sp2]).ok_or(FramingError::InvalidSeq)?;
    let body = &rest1[sp2 + 1..];
    Ok((counter, seq, body, mac))
}

/// Parse + MAC-verify a response frame. Returns (counter, seq, body).
pub fn verify_response<'a>(
    key: &[u8; 16],
    line: &'a str,
) -> Result<(u64, u32, &'a str), FramingError> {
    let (counter, seq, body, claimed) = parse_response(line)?;
    let mac_input = Zeroizing::new(format!("RSP {} {} {}", counter, seq, body));
    let expected = crypto::siphash24(key, mac_input.as_bytes());
    // See `verify_command` for the `subtle::ConstantTimeEq` rationale.
    if !bool::from(expected.ct_eq(&claimed)) {
        return Err(FramingError::MacMismatch);
    }
    Ok((counter, seq, body))
}

// ---------- shared parser bits ----------

fn split_mac_suffix(s: &str) -> Result<(&str, u64), FramingError> {
    if s.len() < MAC_SUFFIX_LEN {
        return Err(FramingError::TooShort(s.len()));
    }
    // Wire input is technically arbitrary bytes — a hostile MITM could
    // inject non-ASCII garbage. Lossy UTF-8 conversion replaces bad bytes
    // with `\u{FFFD}` (3 UTF-8 bytes), which means `s.len() - 19` can land
    // inside a multi-byte char; `split_at` would panic. Reject before
    // touching the slice. Crypto-posture review item caught by fuzzer.
    let split_at = s.len() - MAC_SUFFIX_LEN;
    if !s.is_char_boundary(split_at) {
        return Err(FramingError::MissingMacSuffix);
    }
    let (head, suffix) = s.split_at(split_at);
    if !suffix.starts_with(" M ") {
        return Err(FramingError::MissingMacSuffix);
    }
    let mac_hex = &suffix[3..];
    let mac = parse_mac_hex(mac_hex)?;
    Ok((head, mac))
}

fn split_counter_body(s: &str) -> Result<(u64, &str), FramingError> {
    let sp = s.find(' ').ok_or(FramingError::TooShort(s.len()))?;
    let counter = parse_strict_u64(&s[..sp]).ok_or(FramingError::InvalidCounter)?;
    Ok((counter, &s[sp + 1..]))
}

/// Strict decimal `u64` parser. Rejects empty, sign chars, non-digit bytes,
/// and leading zeros (except exact "0"). The strictness closes a parser-
/// hygiene gap from the §13 review: stdlib `u64::from_str` accepts "042",
/// which after re-format-for-MAC-compute equals the MAC over "42", so a
/// captured `C 42 ... M xyz` could be reshaped to `C 042 ... M xyz` and pass
/// MAC verify. The replay counter check blocks the actual attack, but a
/// strict parser removes the surface entirely.
fn parse_strict_u64(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.is_empty() {
        return None;
    }
    if b.len() > 1 && b[0] == b'0' {
        return None;
    }
    for &c in b {
        if !c.is_ascii_digit() {
            return None;
        }
    }
    s.parse().ok()
}

fn parse_strict_u32(s: &str) -> Option<u32> {
    let v = parse_strict_u64(s)?;
    if v > u32::MAX as u64 {
        None
    } else {
        Some(v as u32)
    }
}

fn parse_mac_hex(hex: &str) -> Result<u64, FramingError> {
    if hex.len() != MAC_HEX_LEN {
        return Err(FramingError::InvalidMac);
    }
    let bytes = hex.as_bytes();
    let mut out = [0u8; 8];
    for i in 0..8 {
        let hi = nybble(bytes[i * 2]).ok_or(FramingError::InvalidMac)?;
        let lo = nybble(bytes[i * 2 + 1]).ok_or(FramingError::InvalidMac)?;
        out[i] = (hi << 4) | lo;
    }
    Ok(u64::from_le_bytes(out))
}

fn nybble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(10 + c - b'a'),
        b'A'..=b'F' => Some(10 + c - b'A'),
        _ => None,
    }
}

// ---------- tests ----------

#[cfg(test)]
mod tests {
    use super::*;

    const K: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    #[test]
    fn counter_ceiling_is_the_agreed_constant() {
        // MUST equal firmware/r503fp/framing.h COUNTER_CEILING (0xFFFFFFFFFFFF0000).
        // A divergence here is a silent lockstep break, so pin it (DoS-2).
        assert_eq!(COUNTER_CEILING, 0xFFFF_FFFF_FFFF_0000);
        assert_eq!(u64::MAX - COUNTER_CEILING, 0xFFFF); // exactly 2^16-1 reserved slots above
    }

    #[test]
    fn command_round_trip() {
        let frame = encode_command(&K, 42, "verify 0");
        assert!(frame.starts_with("C 42 verify 0 M "));
        assert_eq!(frame.len(), "C 42 verify 0 M ".len() + MAC_HEX_LEN);
        let (ctr, cmd) = verify_command(&K, &frame).unwrap();
        assert_eq!(ctr, 42);
        assert_eq!(cmd, "verify 0");
    }

    #[test]
    fn response_round_trip() {
        let frame = encode_response(&K, 42, 0, "PROGRESS place_finger");
        assert!(frame.starts_with("R 42 0 PROGRESS place_finger M "));
        let (ctr, seq, body) = verify_response(&K, &frame).unwrap();
        assert_eq!(ctr, 42);
        assert_eq!(seq, 0);
        assert_eq!(body, "PROGRESS place_finger");
    }

    #[test]
    fn response_with_multiple_spaces_in_body() {
        let frame = encode_response(&K, 7, 3, "OK match=0 confidence=168");
        let (_, _, body) = verify_response(&K, &frame).unwrap();
        assert_eq!(body, "OK match=0 confidence=168");
    }

    #[test]
    fn wrong_key_fails_verify() {
        let frame = encode_command(&K, 1, "ping");
        let mut bad = K;
        bad[0] ^= 0x01;
        assert_eq!(
            verify_command(&bad, &frame).unwrap_err(),
            FramingError::MacMismatch
        );
    }

    #[test]
    fn tampered_body_fails_verify() {
        let frame = encode_command(&K, 1, "verify 0");
        let tampered = frame.replace("verify 0", "verify 1");
        assert_eq!(
            verify_command(&K, &tampered).unwrap_err(),
            FramingError::MacMismatch
        );
    }

    #[test]
    fn tampered_counter_fails_verify() {
        let frame = encode_command(&K, 100, "verify 0");
        let tampered = frame.replacen("100", "101", 1);
        assert_eq!(
            verify_command(&K, &tampered).unwrap_err(),
            FramingError::MacMismatch
        );
    }

    #[test]
    fn tampered_mac_fails_verify() {
        let mut frame = encode_command(&K, 1, "ping");
        // Flip the last hex nybble.
        frame.pop();
        frame.push('0');
        assert_eq!(
            verify_command(&K, &frame).unwrap_err(),
            FramingError::MacMismatch
        );
    }

    #[test]
    fn missing_suffix_rejected() {
        // "C 1 ping" → strip "C " → "1 ping" (6 chars) — below the
        // ` M XXXXXXXXXXXXXXXX` (19 chars) minimum tail.
        assert_eq!(
            verify_command(&K, "C 1 ping").unwrap_err(),
            FramingError::TooShort(6)
        );
    }

    #[test]
    fn wrong_leader_rejected() {
        assert!(matches!(
            verify_command(&K, "X 1 ping M 0123456789abcdef"),
            Err(FramingError::WrongLeader { .. })
        ));
    }

    #[test]
    fn cmd_frame_not_accepted_as_response() {
        // Encode as command, try to verify as response: leader mismatch.
        let frame = encode_command(&K, 1, "ping");
        assert!(matches!(
            verify_response(&K, &frame),
            Err(FramingError::WrongLeader { .. })
        ));
    }

    #[test]
    fn domain_separation_holds() {
        // Same byte sequence after the leader, but CMD vs RSP MAC inputs differ,
        // so a payload that happens to match between directions still won't.
        let cmd_frame = encode_command(&K, 5, "0 hello");
        // Build a response with counter=5, seq=0, body="hello" so the visible
        // payload between leader and ` M ` is identical: "5 0 hello".
        let resp_frame = encode_response(&K, 5, 0, "hello");
        let cmd_mac = &cmd_frame[cmd_frame.len() - MAC_HEX_LEN..];
        let resp_mac = &resp_frame[resp_frame.len() - MAC_HEX_LEN..];
        assert_ne!(cmd_mac, resp_mac, "domain separation broken");
    }

    #[test]
    fn strict_parser_rejects_leading_zero_counter() {
        // Build a valid frame at counter=42, then re-write the visible counter
        // token as "042". Stdlib parsing would accept this; the strict parser
        // must reject before MAC verify is even attempted.
        let frame = encode_command(&K, 42, "verify 0");
        let rewritten = frame.replacen("C 42 ", "C 042 ", 1);
        assert_eq!(
            verify_command(&K, &rewritten).unwrap_err(),
            FramingError::InvalidCounter
        );
    }

    #[test]
    fn strict_parser_accepts_zero_counter() {
        // The exact-"0" case must still pass — it's the legitimate first frame.
        let frame = encode_command(&K, 0, "ping");
        let (ctr, cmd) = verify_command(&K, &frame).unwrap();
        assert_eq!(ctr, 0);
        assert_eq!(cmd, "ping");
    }

    #[test]
    fn strict_parser_rejects_plus_sign() {
        // stdlib u64::from_str rejects "+42" already, but we re-confirm via the
        // strict parser path.
        let frame = encode_command(&K, 42, "verify 0");
        let rewritten = frame.replacen("C 42 ", "C +42 ", 1);
        assert!(verify_command(&K, &rewritten).is_err());
    }

    #[test]
    fn strict_parser_rejects_leading_zero_seq() {
        // Response with seq=5 should not validate when the seq token is "05".
        let frame = encode_response(&K, 42, 5, "OK match=0 confidence=168");
        let rewritten = frame.replace(" 5 OK", " 05 OK");
        // Note: this replace may also hit "match=0" parts; check the result is
        // either parsed-rejected or MAC-rejected — both prove the strictness
        // works.
        assert!(verify_response(&K, &rewritten).is_err());
    }

    #[test]
    fn known_mac_input_format() {
        // Sanity: confirm we're computing MAC over the documented input.
        let frame = encode_command(&K, 42, "verify 0");
        let expected_input = "CMD 42 verify 0";
        let expected_mac = crypto::siphash24(&K, expected_input.as_bytes());
        let mac_hex = &frame[frame.len() - MAC_HEX_LEN..];
        assert_eq!(mac_hex, crypto::mac_to_hex(expected_mac));
    }
}
