// framing.h — v2 wire framing per SPEC §13.3.
//
// Mirror of pcside/daemon/src/framing.rs. Any change here must be mirrored on
// the daemon side and re-cross-verified.
//
// Command (host → Nano):   `C <counter> <cmd_line> M <mac_hex>`
// Response (Nano → host):  `R <counter> <seq> <body_line> M <mac_hex>`
//
// MAC inputs are domain-separated:
//   cmd:  "CMD <counter> <cmd_line>"
//   resp: "RSP <counter> <seq> <body_line>"

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "siphash.h"

namespace r503 {

// ---------- hex + decimal helpers ----------

inline bool hex_nybble(char c, uint8_t* out) {
  if (c >= '0' && c <= '9') { *out = c - '0';      return true; }
  if (c >= 'a' && c <= 'f') { *out = 10 + (c - 'a'); return true; }
  if (c >= 'A' && c <= 'F') { *out = 10 + (c - 'A'); return true; }
  return false;
}

inline bool hex_to_bytes(const char* hex, size_t hex_len, uint8_t* out, size_t out_max, size_t* out_len) {
  if (hex_len % 2 != 0) return false;
  size_t n = hex_len / 2;
  if (n > out_max) return false;
  for (size_t i = 0; i < n; ++i) {
    uint8_t hi, lo;
    if (!hex_nybble(hex[i * 2],     &hi)) return false;
    if (!hex_nybble(hex[i * 2 + 1], &lo)) return false;
    out[i] = (hi << 4) | lo;
  }
  *out_len = n;
  return true;
}

inline void bytes_to_hex(const uint8_t* in, size_t len, char* out) {
  static const char H[] = "0123456789abcdef";
  for (size_t i = 0; i < len; ++i) {
    out[i * 2]     = H[in[i] >> 4];
    out[i * 2 + 1] = H[in[i] & 0x0f];
  }
  out[len * 2] = 0;
}

// avr-libc's printf doesn't support %llu by default. Hand-rolled u64 → decimal.
// Writes NUL-terminated decimal to `out`, returns length without the NUL.
// Caller's buffer must be >= 21 bytes (max u64 = 20 digits + NUL).
inline size_t format_u64(uint64_t n, char* out) {
  if (n == 0) { out[0] = '0'; out[1] = 0; return 1; }
  char tmp[21];
  size_t i = 0;
  while (n > 0) {
    tmp[i++] = '0' + (uint8_t)(n % 10);
    n /= 10;
  }
  for (size_t j = 0; j < i; ++j) {
    out[j] = tmp[i - 1 - j];
  }
  out[i] = 0;
  return i;
}

inline size_t format_u32(uint32_t n, char* out) {
  return format_u64((uint64_t)n, out);
}

inline bool parse_u64(const char* p, size_t len, uint64_t* out) {
  if (len == 0) return false;
  uint64_t v = 0;
  for (size_t i = 0; i < len; ++i) {
    char c = p[i];
    if (c < '0' || c > '9') return false;
    if (v > (uint64_t)0xFFFFFFFFFFFFFFFFULL / 10) return false;
    v *= 10;
    uint8_t d = c - '0';
    if (v > (uint64_t)0xFFFFFFFFFFFFFFFFULL - d) return false;
    v += d;
  }
  *out = v;
  return true;
}

inline bool parse_u32(const char* p, size_t len, uint32_t* out) {
  uint64_t v;
  if (!parse_u64(p, len, &v)) return false;
  if (v > 0xFFFFFFFFULL) return false;
  *out = (uint32_t)v;
  return true;
}

// ---------- MAC helpers shared by parse and encode ----------

// Computes the MAC over the canonical command-MAC input:
//   "CMD <counter> <cmd_line>"
// without allocating: feeds SipHash a constructed string in a stack buffer.
// Buffer caps at 192 bytes which fits any v2 command line + counter.
inline bool compute_cmd_mac(const uint8_t key[16], uint64_t counter,
                            const char* cmd_line, size_t cmd_line_len,
                            uint8_t mac_out[8]) {
  // 128 bytes covers any realistic command line. Commands are short:
  // "CMD <20-digit-counter> <80-char-cmd>" ≈ 105 chars max.
  char buf[128];
  size_t off = 0;
  if (off + 4 > sizeof(buf)) return false;
  memcpy(buf + off, "CMD ", 4);
  off += 4;
  size_t n = format_u64(counter, buf + off);
  off += n;
  if (off + 1 > sizeof(buf)) return false;
  buf[off++] = ' ';
  if (off + cmd_line_len > sizeof(buf)) return false;
  memcpy(buf + off, cmd_line, cmd_line_len);
  off += cmd_line_len;
  uint64_t mac = siphash24(key, (const uint8_t*)buf, off);
  siphash_to_le_bytes(mac, mac_out);
  return true;
}

inline bool compute_resp_mac(const uint8_t key[16], uint64_t counter, uint32_t seq,
                             const char* body, size_t body_len,
                             uint8_t mac_out[8]) {
  // 128 bytes covers any realistic response: longest body is the info line at
  // ~80 chars, plus "RSP <20> <10> " ≈ 35 char overhead = ~115 chars.
  char buf[128];

  size_t off = 0;
  if (off + 4 > sizeof(buf)) return false;
  memcpy(buf + off, "RSP ", 4);
  off += 4;
  off += format_u64(counter, buf + off);
  if (off + 1 > sizeof(buf)) return false;
  buf[off++] = ' ';
  off += format_u32(seq, buf + off);
  if (off + 1 > sizeof(buf)) return false;
  buf[off++] = ' ';
  if (off + body_len > sizeof(buf)) return false;
  memcpy(buf + off, body, body_len);
  off += body_len;
  uint64_t mac = siphash24(key, (const uint8_t*)buf, off);
  siphash_to_le_bytes(mac, mac_out);
  return true;
}

// ---------- command frame parse + verify ----------

// Status codes for parse_command_frame.
enum FrameParseStatus : uint8_t {
  FRAME_OK = 0,
  FRAME_BAD_LEADER,
  FRAME_TOO_SHORT,
  FRAME_BAD_SUFFIX,
  FRAME_BAD_MAC_HEX,
  FRAME_BAD_COUNTER,
  FRAME_BAD_SEQ,
  FRAME_MAC_MISMATCH,
};

// Parses "C <counter> <cmd_line> M <mac_hex>" WITHOUT verifying MAC.
// `line` must NOT include a trailing newline; `line_len` is exclusive of NUL.
// On success sets *counter, *cmd_line (pointer into `line`), *cmd_line_len,
// and writes the claimed MAC bytes into mac_out[8].
inline FrameParseStatus parse_command_frame(
    const char* line, size_t line_len,
    uint64_t* counter,
    const char** cmd_line, size_t* cmd_line_len,
    uint8_t mac_out[8]
) {
  // Minimum: "C N B M XXXXXXXXXXXXXXXX" = 2 + 1+ 1+ 1+ 3 + 16 = ?
  // Bare minimum is "C 0 X M " + 16 hex = 24 chars.
  if (line_len < 24) return FRAME_TOO_SHORT;
  if (line[0] != 'C' || line[1] != ' ') return FRAME_BAD_LEADER;
  // Suffix is " M " + 16 hex at the end.
  const size_t suffix_len = 3 + 16;
  if (line_len < 2 + suffix_len) return FRAME_TOO_SHORT;
  const char* suffix = line + line_len - suffix_len;
  if (suffix[0] != ' ' || suffix[1] != 'M' || suffix[2] != ' ') return FRAME_BAD_SUFFIX;
  size_t mac_len;
  if (!hex_to_bytes(suffix + 3, 16, mac_out, 8, &mac_len) || mac_len != 8) {
    return FRAME_BAD_MAC_HEX;
  }
  // Body is between "C " and " M <hex>".
  const char* body = line + 2;
  size_t body_len = line_len - 2 - suffix_len;
  // First space splits counter from cmd_line.
  size_t sp = 0;
  while (sp < body_len && body[sp] != ' ') ++sp;
  if (sp == 0 || sp >= body_len) return FRAME_TOO_SHORT;
  if (!parse_u64(body, sp, counter)) return FRAME_BAD_COUNTER;
  *cmd_line = body + sp + 1;
  *cmd_line_len = body_len - sp - 1;
  return FRAME_OK;
}

// Parses + verifies a command frame against `key`. On success returns FRAME_OK
// and sets *counter and *cmd_line / *cmd_line_len.
inline FrameParseStatus verify_command_frame(
    const uint8_t key[16],
    const char* line, size_t line_len,
    uint64_t* counter,
    const char** cmd_line, size_t* cmd_line_len
) {
  uint8_t claimed_mac[8];
  FrameParseStatus rc = parse_command_frame(line, line_len, counter, cmd_line, cmd_line_len, claimed_mac);
  if (rc != FRAME_OK) return rc;
  uint8_t computed_mac[8];
  if (!compute_cmd_mac(key, *counter, *cmd_line, *cmd_line_len, computed_mac)) {
    return FRAME_TOO_SHORT;
  }
  // Constant-time compare: the loop body has no data-dependent branches,
  // so a serial-MITM attacker who can measure per-byte firmware latency
  // can't probe MAC bytes one position at a time. Mirrored on the host
  // (pcside/daemon/src/framing.rs) via u64 XOR. Audit §P1-3 / §S5.
  uint8_t diff = 0;
  for (int i = 0; i < 8; ++i) diff |= claimed_mac[i] ^ computed_mac[i];
  if (diff != 0) return FRAME_MAC_MISMATCH;
  return FRAME_OK;
}

// ---------- response frame encode ----------

// Writes "R <counter> <seq> <body> M <mac_hex>" (NUL-terminated) into `out`.
// Returns the number of chars written (excluding NUL), or 0 on overflow.
inline size_t encode_response_frame(
    const uint8_t key[16],
    uint64_t counter, uint32_t seq,
    const char* body, size_t body_len,
    char* out, size_t out_max
) {
  uint8_t mac[8];
  if (!compute_resp_mac(key, counter, seq, body, body_len, mac)) return 0;

  // Layout: "R " + counter + " " + seq + " " + body + " M " + 16 hex + NUL.
  size_t off = 0;
  if (off + 2 > out_max) return 0;
  out[off++] = 'R';
  out[off++] = ' ';
  size_t n = format_u64(counter, out + off);
  if (off + n > out_max) return 0;
  off += n;
  if (off + 1 > out_max) return 0;
  out[off++] = ' ';
  n = format_u32(seq, out + off);
  if (off + n > out_max) return 0;
  off += n;
  if (off + 1 > out_max) return 0;
  out[off++] = ' ';
  if (off + body_len > out_max) return 0;
  memcpy(out + off, body, body_len);
  off += body_len;
  if (off + 3 > out_max) return 0;
  out[off++] = ' ';
  out[off++] = 'M';
  out[off++] = ' ';
  if (off + 16 + 1 > out_max) return 0;
  bytes_to_hex(mac, 8, out + off);
  off += 16;
  // bytes_to_hex already wrote a NUL at out[off].
  return off;
}

} // namespace r503
