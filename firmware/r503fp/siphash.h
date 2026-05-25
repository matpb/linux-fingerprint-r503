// siphash.h — SipHash-2-4 keyed PRF.
//
// Reference: Aumasson & Bernstein, "SipHash: a fast short-input PRF" (2012).
// Header-only, no allocations, AVR-friendly. Mirror of pcside/daemon/src/crypto.rs.
//
// Wire format for the MAC is little-endian: byte 0 = mac & 0xff, byte 7 = mac >> 56.
// That matches the convention used by the reference test vectors and the daemon.
//
// Usage:
//   uint8_t key[16] = { ... };
//   uint64_t mac = r503::siphash24(key, msg_bytes, msg_len);
//   uint8_t mac_bytes[8];
//   r503::siphash_to_le_bytes(mac, mac_bytes);

#pragma once

#include <stdint.h>
#include <stddef.h>

namespace r503 {

inline uint64_t rotl64(uint64_t x, int b) {
  return (x << b) | (x >> (64 - b));
}

inline uint64_t load_u64_le(const uint8_t* p) {
  uint64_t r = 0;
  for (int i = 7; i >= 0; --i) {
    r = (r << 8) | (uint64_t)p[i];
  }
  return r;
}

#define R503_SIPROUND(v0, v1, v2, v3) do { \
  v0 += v1; v1 = rotl64(v1, 13); v1 ^= v0; v0 = rotl64(v0, 32); \
  v2 += v3; v3 = rotl64(v3, 16); v3 ^= v2; \
  v0 += v3; v3 = rotl64(v3, 21); v3 ^= v0; \
  v2 += v1; v1 = rotl64(v1, 17); v1 ^= v2; v2 = rotl64(v2, 32); \
} while (0)

inline uint64_t siphash24(const uint8_t key[16], const uint8_t* msg, size_t len) {
  uint64_t k0 = load_u64_le(key);
  uint64_t k1 = load_u64_le(key + 8);

  uint64_t v0 = k0 ^ 0x736f6d6570736575ULL;
  uint64_t v1 = k1 ^ 0x646f72616e646f6dULL;
  uint64_t v2 = k0 ^ 0x6c7967656e657261ULL;
  uint64_t v3 = k1 ^ 0x7465646279746573ULL;

  size_t blocks = len / 8;
  for (size_t i = 0; i < blocks; ++i) {
    uint64_t m = load_u64_le(msg + i * 8);
    v3 ^= m;
    R503_SIPROUND(v0, v1, v2, v3);
    R503_SIPROUND(v0, v1, v2, v3);
    v0 ^= m;
  }

  // Final block: leftover bytes + length-mod-256 in the high byte.
  uint64_t b = ((uint64_t)(len & 0xff)) << 56;
  size_t left = len & 7;
  const uint8_t* tail = msg + blocks * 8;
  if (left >= 7) b |= (uint64_t)tail[6] << 48;
  if (left >= 6) b |= (uint64_t)tail[5] << 40;
  if (left >= 5) b |= (uint64_t)tail[4] << 32;
  if (left >= 4) b |= (uint64_t)tail[3] << 24;
  if (left >= 3) b |= (uint64_t)tail[2] << 16;
  if (left >= 2) b |= (uint64_t)tail[1] << 8;
  if (left >= 1) b |= (uint64_t)tail[0];

  v3 ^= b;
  R503_SIPROUND(v0, v1, v2, v3);
  R503_SIPROUND(v0, v1, v2, v3);
  v0 ^= b;

  v2 ^= 0xff;
  R503_SIPROUND(v0, v1, v2, v3);
  R503_SIPROUND(v0, v1, v2, v3);
  R503_SIPROUND(v0, v1, v2, v3);
  R503_SIPROUND(v0, v1, v2, v3);

  return v0 ^ v1 ^ v2 ^ v3;
}

inline void siphash_to_le_bytes(uint64_t mac, uint8_t out[8]) {
  for (int i = 0; i < 8; ++i) {
    out[i] = (uint8_t)(mac >> (i * 8));
  }
}

#undef R503_SIPROUND

} // namespace r503
