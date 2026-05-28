#![no_main]

//! libFuzzer entry for the v2 wire framing parsers. Feeds raw byte input
//! into all four parsers (`parse_command`, `parse_response`,
//! `verify_command`, `verify_response`) and asserts they never panic.
//!
//! Run (nightly):
//!   cargo +nightly fuzz run framing -- -max_total_time=3600
//!
//! See `tests/fuzz_framing_smoke.rs` for the stable-Rust property-fuzz
//! variant that runs in CI.

use libfuzzer_sys::fuzz_target;
use r503d::framing;

const KEY: [u8; 16] = [
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
];

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    let _ = framing::parse_command(&s);
    let _ = framing::parse_response(&s);
    let _ = framing::verify_command(&KEY, &s);
    let _ = framing::verify_response(&KEY, &s);
});
