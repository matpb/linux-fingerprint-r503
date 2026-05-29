// r503fp.ino — first cut of the production firmware implementing §5 ASCII protocol.
//
// Currently supports: info, count, list, enroll <slot>, verify, identify,
// delete <slot>, clear (requires `clear confirm`), led <r> <g> <b> <mode>.
//
// PC link: 115200 8N1, line-terminated commands, "OK …" or "ERR …" final lines,
// optional "PROGRESS …" intermediate lines during multi-step operations.

#include <SoftwareSerial.h>
#include <Adafruit_Fingerprint.h>
#include "siphash.h"
#include "framing.h"
#include "eeprom.h"

const long PC_BAUD = 115200;
const long FP_BAUD = 57600;
const uint8_t PIN_RX = 2;
const uint8_t PIN_TX = 3;
const uint8_t PIN_WAKE = 4;

// Aura ring color index for the R503-RGB variant's green LED. The Adafruit
// library only defines RED/BLUE/PURPLE (0x01/0x02/0x03) — the bi-color R503's
// full palette — so green (0x04) is passed as a raw index. Confirmed lighting
// vibrant green on this unit, so it's an R503-RGB. On a bi-color R503 this
// index does nothing; fall back to FINGERPRINT_LED_PURPLE there.
#define FINGERPRINT_LED_GREEN 0x04

SoftwareSerial sensorSerial(PIN_RX, PIN_TX);
Adafruit_Fingerprint finger(&sensorSerial);

String inbuf;

// ---------- v2 framed-output plumbing (Milestone E) ----------
//
// During a framed dispatch, all handler-internal output goes through `g_out`
// which points at `g_framer`. The framer buffers one line at a time and emits
// a `R <ctr> <seq> <body> M <mac>` frame each time the handler calls println()
// or writes a '\n'. Outside framed dispatch, `g_out` points at `&Serial` so
// the same handlers also work for unframed (pre-pair) responses.

class LineFramer : public Print {
public:
  void reset() { pos = 0; }
  void flush_line(); // forward decl; body defined after the helpers
  size_t write(uint8_t c) override {
    if (c == '\n') {
      flush_line();
    } else if (c == '\r') {
      // strip — Arduino's Print::println sends "\r\n"; we only frame on '\n'
    } else if (pos < sizeof(line) - 1) {
      line[pos++] = (char)c;
    }
    return 1;
  }
private:
  // 128 covers any v2 response body (~80 chars max: emitInfo's full line is
  // the worst case). LineFramer is a global g_framer instance, so this lives
  // in BSS — no stack cost.
  char line[128];
  size_t pos = 0;
};

LineFramer g_framer;
Print* g_out = &Serial;

// Session state for a single framed command in flight. Set by process_line()
// after MAC + counter checks succeed; consumed by g_framer.flush_line().
uint8_t  g_session_key[16];
uint64_t g_session_counter = 0;
uint32_t g_session_seq = 0;

void LineFramer::flush_line() {
  if (pos == 0) return;
  line[pos] = 0;
  // 160 bytes covers the worst realistic frame: "R <20> <10> <100-body> M <16>"
  // ≈ 150 chars. Stack-local is fine after we trimmed the per-call mac buffers
  // to 128 bytes (see framing.h compute_*_mac) and removed the test commands
  // that had bigger transient buffers.
  char out[160];
  size_t n = r503::encode_response_frame(
      g_session_key, g_session_counter, g_session_seq,
      line, pos, out, sizeof(out));
  if (n > 0) {
    Serial.println(out);
  } else {
    // The body itself overflowed our frame buffer. Emit a best-effort
    // unframed warning — daemon will see it and mark sensor unhealthy.
    Serial.println(F("ERR encode_overflow"));
  }
  g_session_seq++;
  pos = 0;
}

void emitInfo() {
  if (!finger.verifyPassword()) {
    g_out->println(F("ERR sensor_unreachable"));
    return;
  }
  finger.getParameters();
  finger.getTemplateCount();
  g_out->print(F("OK fw=1.1 capacity="));
  g_out->print(finger.capacity);
  g_out->print(F(" enrolled="));
  g_out->print(finger.templateCount);
  g_out->print(F(" sysid=0x"));
  g_out->print(finger.system_id, HEX);
  g_out->print(F(" security="));
  g_out->print(finger.security_level);
  g_out->print(F(" device_addr=0x"));
  g_out->println(finger.device_addr, HEX);
}

void emitCount() {
  finger.getTemplateCount();
  g_out->print(F("OK count="));
  g_out->println(finger.templateCount);
}

uint8_t waitForFingerCapture(uint16_t timeoutMs) {
  unsigned long deadline = millis() + timeoutMs;
  uint8_t p;
  while (millis() < deadline) {
    p = finger.getImage();
    if (p == FINGERPRINT_OK) return FINGERPRINT_OK;
    if (p == FINGERPRINT_NOFINGER) { delay(50); continue; }
    return p; // any other error: surface it
  }
  return FINGERPRINT_TIMEOUT;
}

uint8_t waitForFingerRemoval(uint16_t timeoutMs) {
  unsigned long deadline = millis() + timeoutMs;
  while (millis() < deadline) {
    if (finger.getImage() == FINGERPRINT_NOFINGER) return FINGERPRINT_OK;
    delay(50);
  }
  return FINGERPRINT_TIMEOUT;
}

void handleEnroll(int slot) {
  if (slot < 0 || slot >= finger.capacity) {
    g_out->println(F("ERR bad_args slot_out_of_range"));
    return;
  }
  finger.LEDcontrol(FINGERPRINT_LED_BREATHING, 100, FINGERPRINT_LED_PURPLE);

  g_out->println(F("PROGRESS place_finger"));
  uint8_t p = waitForFingerCapture(15000);
  if (p != FINGERPRINT_OK) { finger.LEDcontrol(FINGERPRINT_LED_OFF, 0, 0); g_out->print(F("ERR capture_failed=")); g_out->println(p); return; }
  p = finger.image2Tz(1);
  if (p != FINGERPRINT_OK) { finger.LEDcontrol(FINGERPRINT_LED_OFF, 0, 0); g_out->print(F("ERR image2tz_failed=")); g_out->println(p); return; }

  g_out->println(F("PROGRESS remove_finger"));
  p = waitForFingerRemoval(10000);
  if (p != FINGERPRINT_OK) { finger.LEDcontrol(FINGERPRINT_LED_OFF, 0, 0); g_out->println(F("ERR finger_not_removed")); return; }

  g_out->println(F("PROGRESS place_again"));
  p = waitForFingerCapture(15000);
  if (p != FINGERPRINT_OK) { finger.LEDcontrol(FINGERPRINT_LED_OFF, 0, 0); g_out->print(F("ERR second_capture_failed=")); g_out->println(p); return; }
  p = finger.image2Tz(2);
  if (p != FINGERPRINT_OK) { finger.LEDcontrol(FINGERPRINT_LED_OFF, 0, 0); g_out->print(F("ERR image2tz_failed=")); g_out->println(p); return; }

  p = finger.createModel();
  if (p == FINGERPRINT_ENROLLMISMATCH) { finger.LEDcontrol(FINGERPRINT_LED_FLASHING, 50, FINGERPRINT_LED_RED, 5); g_out->println(F("ERR mismatch")); return; }
  if (p != FINGERPRINT_OK) { finger.LEDcontrol(FINGERPRINT_LED_OFF, 0, 0); g_out->print(F("ERR create_model_failed=")); g_out->println(p); return; }

  p = finger.storeModel((uint16_t)slot);
  if (p != FINGERPRINT_OK) { finger.LEDcontrol(FINGERPRINT_LED_OFF, 0, 0); g_out->print(F("ERR store_failed=")); g_out->println(p); return; }

  finger.LEDcontrol(FINGERPRINT_LED_FLASHING, 50, FINGERPRINT_LED_GREEN, 5);
  g_out->print(F("OK enrolled="));
  g_out->println(slot);
}

void handleVerify() {
  finger.LEDcontrol(FINGERPRINT_LED_BREATHING, 100, FINGERPRINT_LED_BLUE);
  g_out->println(F("PROGRESS place_finger"));
  uint8_t p = waitForFingerCapture(10000);
  if (p != FINGERPRINT_OK) { finger.LEDcontrol(FINGERPRINT_LED_OFF, 0, 0); g_out->println(F("ERR timeout")); return; }
  p = finger.image2Tz();
  if (p != FINGERPRINT_OK) { finger.LEDcontrol(FINGERPRINT_LED_OFF, 0, 0); g_out->println(F("ERR poor_quality")); return; }
  p = finger.fingerSearch();
  if (p == FINGERPRINT_NOTFOUND) {
    finger.LEDcontrol(FINGERPRINT_LED_FLASHING, 50, FINGERPRINT_LED_RED, 3);
    g_out->println(F("ERR no_match"));
    return;
  }
  if (p != FINGERPRINT_OK) { finger.LEDcontrol(FINGERPRINT_LED_OFF, 0, 0); g_out->print(F("ERR search_failed=")); g_out->println(p); return; }
  finger.LEDcontrol(FINGERPRINT_LED_FLASHING, 50, FINGERPRINT_LED_GREEN, 3);
  g_out->print(F("OK match="));
  g_out->print(finger.fingerID);
  g_out->print(F(" confidence="));
  g_out->println(finger.confidence);
}

void handleDelete(int slot) {
  if (slot < 0 || slot >= finger.capacity) { g_out->println(F("ERR bad_args slot_out_of_range")); return; }
  uint8_t p = finger.deleteModel((uint16_t)slot);
  if (p == FINGERPRINT_OK) { g_out->print(F("OK deleted=")); g_out->println(slot); }
  else { g_out->print(F("ERR delete_failed=")); g_out->println(p); }
}

void handleClear(bool confirmed) {
  if (!confirmed) { g_out->println(F("ERR confirmation_required (use: clear confirm)")); return; }
  uint8_t p = finger.emptyDatabase();
  if (p == FINGERPRINT_OK) g_out->println(F("OK cleared"));
  else { g_out->print(F("ERR clear_failed=")); g_out->println(p); }
}

// `status` is the unauthenticated pre-handshake query: the daemon needs to know
// the pairing state before deciding whether to use the framed (v2) or plain
// (v1) wire protocol. Always-allowed even on a paired Nano (see process_line).
void handleStatus() {
  uint64_t ctr = r503::ee_load_counter();
  char ctr_buf[21];
  r503::format_u64(ctr, ctr_buf);
  g_out->print(F("OK paired="));
  g_out->print(r503::ee_is_paired() ? F("true") : F("false"));
  g_out->print(F(" counter="));
  g_out->print(ctr_buf);
  g_out->print(F(" fmt="));
  g_out->print(r503::EE_FORMAT_VERSION);
  g_out->println(F(" fw=1.1"));
}

// Milestone D pairing commands. `pair` is the daemon-driven pairing path
// (refuses when already paired to defeat attacker-races-to-pair). `unpair`
// is now the framed/no-arg form (handleUnpairFramed below) — the MAC proves
// key knowledge so the key never crosses the wire.
void handlePair(const String& args) {
  if (r503::ee_is_paired()) { g_out->println(F("ERR already_paired")); return; }
  if (args.length() != 32)  { g_out->println(F("ERR bad_args bad_key_len")); return; }
  uint8_t key[16];
  size_t key_len;
  if (!r503::hex_to_bytes(args.c_str(), 32, key, 16, &key_len) || key_len != 16) {
    g_out->println(F("ERR bad_args bad_key_hex")); return;
  }
  r503::ee_save_pairing(key);
  g_out->println(F("OK paired"));
}

// Framed v2 unpair: no key argument. The MAC on the wrapping frame already
// proves the caller knows the current key, so we just wipe EEPROM. Reached
// only when process_line() has verified the frame and dispatched the inner
// line "unpair" to dispatch().
void handleUnpairFramed() {
  if (!r503::ee_is_paired()) { g_out->println(F("ERR not_paired")); return; }
  r503::ee_wipe();
  g_out->println(F("OK unpaired"));
}

// process_line() is the top-level dispatcher post-Milestone-E. It enforces
// SPEC §13.3/§13.4 (MAC framing + counter monotonicity) when the Nano is
// paired, and falls through to the plain v1 dispatcher when unpaired.
//
// Always-unframed allowlist (works in either state):
//   ping     — daemon's sync handshake
//   status   — pairing-state probe; daemon needs it BEFORE choosing framed vs raw
//
// Unpaired Nano: every other command is dispatched raw (v1 mode), so the
//   `pair` and `ee_*` test commands keep working during onboarding / recovery.
//
// Paired Nano: every other command MUST arrive framed as `C <ctr> <body> M <mac>`.
//   process_line() decodes + verifies MAC + checks counter, then dispatches
//   `<body>` with g_out swung to g_framer so the handler's print*() output is
//   re-emitted as `R <ctr> <seq> <body> M <mac>` lines.
void process_line(const String& line) {
  bool paired = r503::ee_is_paired();

  // Always-unframed shortcuts.
  if (line == "ping") {
    Serial.println(F("OK pong"));
    return;
  }
  if (line == "status") {
    g_out = &Serial;
    dispatch(line);
    return;
  }

  if (!paired) {
    // v1 / pre-pair mode — everything goes raw.
    g_out = &Serial;
    dispatch(line);
    return;
  }

  // Paired: require framing.
  if (line.length() < 2 || line.charAt(0) != 'C' || line.charAt(1) != ' ') {
    Serial.println(F("ERR mac_required"));
    return;
  }
  if (!r503::ee_load_key(g_session_key)) {
    Serial.println(F("ERR no_key"));
    return;
  }
  uint64_t ctr = 0;
  const char* inner = nullptr;
  size_t inner_len = 0;
  r503::FrameParseStatus rc = r503::verify_command_frame(
      g_session_key, line.c_str(), line.length(),
      &ctr, &inner, &inner_len);
  if (rc != r503::FRAME_OK) {
    // Named errors so the daemon-side parser and human log readers don't
    // have to memorize FrameParseStatus enum values.
    Serial.print(F("ERR "));
    switch (rc) {
      case r503::FRAME_BAD_LEADER:   Serial.println(F("bad_frame_leader")); break;
      case r503::FRAME_TOO_SHORT:    Serial.println(F("frame_too_short")); break;
      case r503::FRAME_BAD_SUFFIX:   Serial.println(F("bad_frame_suffix")); break;
      case r503::FRAME_BAD_MAC_HEX:  Serial.println(F("bad_mac_hex")); break;
      case r503::FRAME_BAD_COUNTER:  Serial.println(F("bad_counter")); break;
      case r503::FRAME_BAD_SEQ:      Serial.println(F("bad_seq")); break;
      case r503::FRAME_MAC_MISMATCH: Serial.println(F("mac_invalid")); break;
      default:                       Serial.println(F("frame_unknown")); break;
    }
    return;
  }
  uint64_t last = r503::ee_load_counter();
  if (ctr <= last) {
    Serial.println(F("ERR replay"));
    return;
  }
  // Refuse the reserved ceiling band and NEVER commit it (security audit
  // 2026-05-28 / firmware DoS-2). Without this, a frame carrying counter=MAX
  // would persist last_seen=MAX, after which every future command — including
  // the framed `unpair` recovery, which is gated by this very check — needs
  // ctr > MAX and is impossible, bricking the channel until a physical reflash.
  // The daemon mirrors this in framing.rs (COUNTER_CEILING) so a compliant host
  // never emits such a frame; this guard defends against a malicious/buggy peer.
  // g_out is still &Serial here, so the error goes out unframed; nothing is
  // committed, so the counter cannot advance into the brick zone.
  if (ctr >= r503::COUNTER_CEILING) {
    Serial.println(F("ERR counter_ceiling"));
    return;
  }
  // Commit the new counter BEFORE handler runs so a crash-and-restart can't
  // be tricked into accepting the same counter twice. The handler's output
  // (success or failure) is irrelevant for replay protection — what matters
  // is that we've seen this counter.
  r503::ee_save_counter(ctr);

  // Reject an overlong inner body rather than silently truncating it. The MAC
  // was verified over the full inner_len bytes, so a memcpy-truncated dispatch
  // would run a command whose authenticated suffix was dropped (e.g. a future
  // "enroll 5 confirm" arriving as "enroll 5"). ibuf holds 95 usable bytes; the
  // longest real command ("verify 199"-class) is ~10, so this never fires for
  // the current command set — it's a hard wall against a future longer-payload
  // verb. g_out is still &Serial here, so the error goes out unframed; the
  // counter is already committed, so the frame can't be replayed.
  // (Audit 2026-05-28 / M4.)
  char ibuf[96];
  if (inner_len >= sizeof(ibuf)) {
    Serial.println(F("ERR frame_body_too_long"));
    return;
  }

  g_session_counter = ctr;
  g_session_seq = 0;
  g_framer.reset();
  g_out = &g_framer;

  // String constructor needs a NUL terminator; inner is a non-terminated slice.
  // inner_len < sizeof(ibuf) is guaranteed by the reject above.
  size_t cap = sizeof(ibuf) - 1;
  size_t n = (inner_len < cap) ? inner_len : cap;
  memcpy(ibuf, inner, n);
  ibuf[n] = 0;
  dispatch(String(ibuf));

  // Safety belt: if the handler wrote a final line without '\n', emit it now.
  // All current handlers end with println, so this is typically a no-op.
  g_framer.flush_line();
  g_out = &Serial;
}

void dispatch(const String& line) {
  if (line == "info") emitInfo();
  else if (line == "count") emitCount();
  else if (line == "verify" || line == "identify") handleVerify();
  else if (line == "clear") handleClear(false);
  else if (line == "clear confirm") handleClear(true);
  else if (line.startsWith("enroll ")) handleEnroll(line.substring(7).toInt());
  else if (line.startsWith("delete ")) handleDelete(line.substring(7).toInt());
  else if (line == "status") handleStatus();
  else if (line.startsWith("pair ")) handlePair(line.substring(5));
  else if (line == "unpair")         handleUnpairFramed();
  else if (line == "wake") { g_out->print(F("OK wake=")); g_out->println(digitalRead(PIN_WAKE) == LOW ? '1' : '0'); }
  else if (line == "ping") g_out->println(F("OK pong"));
  else if (line == "led off") { finger.LEDcontrol(FINGERPRINT_LED_OFF, 0, 0); g_out->println(F("OK")); }
  else {
    // Truncate the echoed verb. The framed response body is "ERR unknown_command "
    // (20) + this echo, and compute_resp_mac (framing.h) builds it into a fixed
    // 128-byte buffer alongside "RSP <ctr> <seq> ". An unbounded echo (the inner
    // body is up to 95 bytes) could push that past 128 once the counter/seq grow,
    // making the response un-encodable: the firmware would fall back to an
    // UNFRAMED `ERR encode_overflow` AFTER the replay counter was already burned,
    // desyncing the channel. Capping at 40 keeps body <= 60 so the frame always
    // encodes for any counter/seq (security audit 2026-05-28 / protocol DoS-1).
    g_out->print(F("ERR unknown_command "));
    g_out->println(line.substring(0, 40));
  }
}

// Boot-time SipHash KAT self-test. Runs 4 canonical Aumasson vectors
// against the on-board SipHash before the framed channel comes up. On any
// mismatch (compiler regression, flash corruption, build-config mix-up)
// we halt with a distinctive 80 ms/80 ms LED strobe + a FATAL serial line,
// rather than enter the main loop with a quietly-broken MAC primitive.
// Crypto-posture review item #10 — turns the KAT vectors that already live
// in the daemon's `crypto.rs` tests into a runtime invariant on the device.
// Cost: ~120 bytes flash + ~8 ms one-shot at boot.
bool siphash_kat_ok() {
  static const uint8_t KEY[16] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
  };
  struct Vec { uint8_t len; uint8_t want[8]; };
  static const Vec VECS[] = {
    { 0,  {0x31,0x0e,0x0e,0xdd,0x47,0xdb,0x6f,0x72}},
    { 1,  {0xfd,0x67,0xdc,0x93,0xc5,0x39,0xf8,0x74}},
    { 8,  {0x62,0x24,0x93,0x9a,0x79,0xf5,0xf5,0x93}},
    {15,  {0xe5,0x45,0xbe,0x49,0x61,0xca,0x29,0xa1}},
  };
  uint8_t msg[16];
  for (uint8_t i = 0; i < 16; ++i) msg[i] = i;
  for (uint8_t v = 0; v < (uint8_t)(sizeof(VECS)/sizeof(VECS[0])); ++v) {
    uint64_t mac = r503::siphash24(KEY, msg, VECS[v].len);
    uint8_t out[8];
    r503::siphash_to_le_bytes(mac, out);
    for (uint8_t b = 0; b < 8; ++b) {
      if (out[b] != VECS[v].want[b]) return false;
    }
  }
  return true;
}

void setup() {
  pinMode(PIN_WAKE, INPUT);
  pinMode(LED_BUILTIN, OUTPUT);
  Serial.begin(PC_BAUD);
  while (!Serial) { ; }
  delay(500);

  if (!siphash_kat_ok()) {
    Serial.println(F("FATAL siphash_kat_fail — refusing to enter main loop"));
    // Strobe ~6 Hz forever. Distinct from r503fp_wipe's 2.5 Hz slow blink
    // and from normal idle (LED off). Visible as "fast pulse" at a glance.
    while (1) {
      digitalWrite(LED_BUILTIN, HIGH); delay(80);
      digitalWrite(LED_BUILTIN, LOW);  delay(80);
    }
  }

  Serial.print(F("R503FP READY fw=1.1 paired="));
  Serial.println(r503::ee_is_paired() ? F("true") : F("false"));
  finger.begin(FP_BAUD);
  emitInfo();
}

void loop() {
  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\n' || c == '\r') {
      if (inbuf.length() > 0) {
        digitalWrite(LED_BUILTIN, HIGH);
        process_line(inbuf);
        digitalWrite(LED_BUILTIN, LOW);
        inbuf = "";
      }
    } else {
      inbuf += c;
      // v2 framed commands are ~80 chars max ("C <counter> <body> M <16-hex>").
      // 128 leaves comfortable headroom and matches the static `out` cap in
      // LineFramer::flush_line. Use >= so the documented "lines capped at 128
      // bytes" invariant holds exactly — > 128 let a 129th byte land in inbuf
      // before the check fired (audit 2026-05-28 / L4).
      if (inbuf.length() >= 128) { Serial.println(F("ERR bad_args overflow")); inbuf = ""; }
    }
  }
}
