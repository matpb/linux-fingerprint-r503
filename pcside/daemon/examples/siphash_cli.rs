//! Tiny CLI wrapper around `crypto::siphash24` for cross-verification against
//! the firmware's `siphash` test command. Reads `<key_hex> <msg_hex>` from
//! argv, prints the lowercase hex MAC to stdout.
//!
//! Used by /tmp/siphash_xverify.py during Milestone A. Not shipped.

use std::env;
use std::process::ExitCode;

#[path = "../src/crypto.rs"]
mod crypto;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || args.len() > 2 {
        eprintln!("usage: siphash_cli <key_hex(32)> [msg_hex]");
        return ExitCode::from(2);
    }
    let key_hex = &args[0];
    let msg_hex = args.get(1).map(String::as_str).unwrap_or("");
    let key_bytes = match hex_decode(key_hex) {
        Ok(b) if b.len() == 16 => b,
        Ok(b) => {
            eprintln!("key must be 16 bytes, got {}", b.len());
            return ExitCode::from(2);
        }
        Err(e) => {
            eprintln!("bad key hex: {}", e);
            return ExitCode::from(2);
        }
    };
    let msg_bytes = match hex_decode(msg_hex) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("bad msg hex: {}", e);
            return ExitCode::from(2);
        }
    };
    let mut key = [0u8; 16];
    key.copy_from_slice(&key_bytes);
    let mac = crypto::siphash24(&key, &msg_bytes);
    println!("{}", crypto::mac_to_hex(mac));
    ExitCode::SUCCESS
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err(format!("odd length {}", s.len()));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().chunks(2) {
        let hi = hex_nybble(chunk[0])?;
        let lo = hex_nybble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nybble(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(10 + (c - b'a')),
        b'A'..=b'F' => Ok(10 + (c - b'A')),
        _ => Err(format!("non-hex byte: {:?}", c as char)),
    }
}
