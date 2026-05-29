// eeprom.h — persistent state for the v2 authenticated channel (SPEC §13.4/§13.5).
//
// Layout in the ATmega328P's 1024-byte EEPROM (only the first 192 bytes used):
//
//   [ 0..7]   magic              "R503FPv2"  ─ marks "this Nano is paired"
//   [   8]   format version     0x02        ─ schema rev; bumps on layout change
//   [ 9..24] shared key         16 bytes    ─ TOFU-paired SipHash-2-4 key
//   [25..31] reserved           7 bytes     ─ zeros, available for v3
//   [32..191] counter ring      16 cells × 10 bytes (8-byte LE counter + CRC-16-CCITT)
//   [192..]  unused
//
// The counter ring is wear-leveled: every save_counter() writes the next cell
// in cyclic order, so any single EEPROM cell only takes 1/16 of the writes.
// AT 100k writes/cell × 16 = 1.6M total counter bumps before any cell wears
// out ≈ 88 years at 50 logins/day. See SPEC §13.4.
//
// CRC-16-CCITT (polynomial 0x1021, init 0xFFFF) guards each cell against
// bit-rot. False-positive per cell is ~1/65536 — overkill for the threat model
// (flash decay over years; the MAC layer handles active attackers) but the
// cost over CRC-8 is one extra byte per cell and ~5 LOC.
//
// Format version bumped 0x01 → 0x02 with this CRC change. Older EEPROM state
// (v0.4 with CRC-8 cells) fails ee_is_paired() and is silently treated as
// unpaired, forcing a clean re-pair on first boot of new firmware.

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <EEPROM.h>

namespace r503 {

constexpr uint16_t EE_MAGIC_ADDR = 0;
constexpr uint16_t EE_MAGIC_LEN = 8;
constexpr uint16_t EE_FMT_ADDR = 8;
constexpr uint8_t  EE_FORMAT_VERSION = 2;
constexpr uint16_t EE_KEY_ADDR = 9;
constexpr uint16_t EE_KEY_LEN = 16;
constexpr uint16_t EE_RESERVED_ADDR = 25;
constexpr uint16_t EE_RESERVED_LEN = 7;
constexpr uint16_t EE_COUNTER_RING_ADDR = 32;
constexpr uint16_t EE_COUNTER_RING_CELLS = 16;
constexpr uint16_t EE_COUNTER_RING_CELL_SIZE = 10; // 8-byte counter + 2-byte CRC-16
constexpr uint16_t EE_END_ADDR =
    EE_COUNTER_RING_ADDR + EE_COUNTER_RING_CELLS * EE_COUNTER_RING_CELL_SIZE; // 192

inline constexpr uint8_t EE_MAGIC[EE_MAGIC_LEN] = {
  'R', '5', '0', '3', 'F', 'P', 'v', '2'
};

// ---------- CRC-16-CCITT (poly 0x1021, init 0xFFFF) ----------

inline uint16_t crc16_ccitt(const uint8_t* p, size_t n) {
  uint16_t c = 0xFFFF;
  for (size_t i = 0; i < n; ++i) {
    c ^= ((uint16_t)p[i]) << 8;
    for (uint8_t b = 0; b < 8; ++b) {
      c = (c & 0x8000) ? (uint16_t)((c << 1) ^ 0x1021) : (uint16_t)(c << 1);
    }
  }
  return c;
}

// ---------- pairing state ----------

inline bool ee_is_paired() {
  for (uint8_t i = 0; i < EE_MAGIC_LEN; ++i) {
    if (EEPROM.read(EE_MAGIC_ADDR + i) != EE_MAGIC[i]) return false;
  }
  return EEPROM.read(EE_FMT_ADDR) == EE_FORMAT_VERSION;
}

inline bool ee_load_key(uint8_t key_out[16]) {
  if (!ee_is_paired()) return false;
  for (uint8_t i = 0; i < EE_KEY_LEN; ++i) {
    key_out[i] = EEPROM.read(EE_KEY_ADDR + i);
  }
  return true;
}

inline void ee_save_pairing(const uint8_t key[16]) {
  for (uint8_t i = 0; i < EE_MAGIC_LEN; ++i) {
    EEPROM.update(EE_MAGIC_ADDR + i, EE_MAGIC[i]);
  }
  EEPROM.update(EE_FMT_ADDR, EE_FORMAT_VERSION);
  for (uint8_t i = 0; i < EE_KEY_LEN; ++i) {
    EEPROM.update(EE_KEY_ADDR + i, key[i]);
  }
  // Reset counter ring: every cell to 0xFF so no cell appears valid.
  // First ee_save_counter() will land in cell 0.
  for (uint16_t a = EE_COUNTER_RING_ADDR; a < EE_END_ADDR; ++a) {
    EEPROM.update(a, 0xFF);
  }
}

inline void ee_wipe() {
  // Restore the entire managed region to 0xFF (uninitialized state).
  for (uint16_t a = 0; a < EE_END_ADDR; ++a) {
    EEPROM.update(a, 0xFF);
  }
}

// ---------- counter ring ----------

// Internal: scan all cells. Returns (max valid counter, cell index, any_valid).
struct RingScan {
  uint64_t max_counter;
  int8_t   max_cell;
  bool     any_valid;
};

inline RingScan ee_scan_ring() {
  RingScan s = { 0, -1, false };
  uint8_t cell[EE_COUNTER_RING_CELL_SIZE];
  for (uint8_t i = 0; i < EE_COUNTER_RING_CELLS; ++i) {
    uint16_t addr = EE_COUNTER_RING_ADDR + i * EE_COUNTER_RING_CELL_SIZE;
    for (uint8_t b = 0; b < EE_COUNTER_RING_CELL_SIZE; ++b) {
      cell[b] = EEPROM.read(addr + b);
    }
    uint16_t want_crc = crc16_ccitt(cell, 8);
    uint16_t got_crc = (uint16_t)cell[8] | ((uint16_t)cell[9] << 8);
    if (got_crc != want_crc) continue;
    uint64_t ctr = 0;
    for (int8_t j = 7; j >= 0; --j) {
      ctr = (ctr << 8) | (uint64_t)cell[j];
    }
    if (!s.any_valid || ctr > s.max_counter) {
      s.max_counter = ctr;
      s.max_cell = i;
      s.any_valid = true;
    }
  }
  return s;
}

inline uint64_t ee_load_counter() {
  return ee_scan_ring().max_counter; // 0 if no valid cell
}

// Saves `new_counter` to the next cell in the ring (cyclic). Always returns
// true; the reserved-ceiling guard that prevents counter exhaustion is enforced
// upstream in process_line() (r503fp.ino) BEFORE this is called, so a
// ceiling/MAX counter never reaches the ring (security audit 2026-05-28 /
// firmware DoS-2).
inline bool ee_save_counter(uint64_t new_counter) {
  RingScan s = ee_scan_ring();
  uint8_t next_cell = s.any_valid
    ? (uint8_t)((s.max_cell + 1) % EE_COUNTER_RING_CELLS)
    : 0;
  uint16_t addr = EE_COUNTER_RING_ADDR + next_cell * EE_COUNTER_RING_CELL_SIZE;
  uint8_t cell[EE_COUNTER_RING_CELL_SIZE];
  for (uint8_t j = 0; j < 8; ++j) {
    cell[j] = (uint8_t)(new_counter >> (j * 8));
  }
  uint16_t crc = crc16_ccitt(cell, 8);
  cell[8] = (uint8_t)(crc & 0xff);
  cell[9] = (uint8_t)(crc >> 8);
  for (uint8_t b = 0; b < EE_COUNTER_RING_CELL_SIZE; ++b) {
    EEPROM.update(addr + b, cell[b]);
  }
  return true;
}

// ---------- debug introspection (test commands only) ----------

// Read a single cell into out[9]. Caller checks CRC.
inline void ee_read_cell(uint8_t i, uint8_t out[EE_COUNTER_RING_CELL_SIZE]) {
  uint16_t addr = EE_COUNTER_RING_ADDR + i * EE_COUNTER_RING_CELL_SIZE;
  for (uint8_t b = 0; b < EE_COUNTER_RING_CELL_SIZE; ++b) {
    out[b] = EEPROM.read(addr + b);
  }
}

} // namespace r503
