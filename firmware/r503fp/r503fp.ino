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

SoftwareSerial sensorSerial(PIN_RX, PIN_TX);
Adafruit_Fingerprint finger(&sensorSerial);

String inbuf;

void emitInfo() {
  if (!finger.verifyPassword()) {
    Serial.println(F("ERR sensor_unreachable"));
    return;
  }
  finger.getParameters();
  finger.getTemplateCount();
  Serial.print(F("OK fw=0.4 capacity="));
  Serial.print(finger.capacity);
  Serial.print(F(" enrolled="));
  Serial.print(finger.templateCount);
  Serial.print(F(" sysid=0x"));
  Serial.print(finger.system_id, HEX);
  Serial.print(F(" security="));
  Serial.print(finger.security_level);
  Serial.print(F(" device_addr=0x"));
  Serial.println(finger.device_addr, HEX);
}

void emitCount() {
  finger.getTemplateCount();
  Serial.print(F("OK count="));
  Serial.println(finger.templateCount);
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
    Serial.println(F("ERR bad_args slot_out_of_range"));
    return;
  }
  finger.LEDcontrol(FINGERPRINT_LED_BREATHING, 100, FINGERPRINT_LED_PURPLE);

  Serial.println(F("PROGRESS place_finger"));
  uint8_t p = waitForFingerCapture(15000);
  if (p != FINGERPRINT_OK) { finger.LEDcontrol(FINGERPRINT_LED_OFF, 0, 0); Serial.print(F("ERR capture_failed=")); Serial.println(p); return; }
  p = finger.image2Tz(1);
  if (p != FINGERPRINT_OK) { finger.LEDcontrol(FINGERPRINT_LED_OFF, 0, 0); Serial.print(F("ERR image2tz_failed=")); Serial.println(p); return; }

  Serial.println(F("PROGRESS remove_finger"));
  p = waitForFingerRemoval(10000);
  if (p != FINGERPRINT_OK) { finger.LEDcontrol(FINGERPRINT_LED_OFF, 0, 0); Serial.println(F("ERR finger_not_removed")); return; }

  Serial.println(F("PROGRESS place_again"));
  p = waitForFingerCapture(15000);
  if (p != FINGERPRINT_OK) { finger.LEDcontrol(FINGERPRINT_LED_OFF, 0, 0); Serial.print(F("ERR second_capture_failed=")); Serial.println(p); return; }
  p = finger.image2Tz(2);
  if (p != FINGERPRINT_OK) { finger.LEDcontrol(FINGERPRINT_LED_OFF, 0, 0); Serial.print(F("ERR image2tz_failed=")); Serial.println(p); return; }

  p = finger.createModel();
  if (p == FINGERPRINT_ENROLLMISMATCH) { finger.LEDcontrol(FINGERPRINT_LED_FLASHING, 50, FINGERPRINT_LED_RED, 5); Serial.println(F("ERR mismatch")); return; }
  if (p != FINGERPRINT_OK) { finger.LEDcontrol(FINGERPRINT_LED_OFF, 0, 0); Serial.print(F("ERR create_model_failed=")); Serial.println(p); return; }

  p = finger.storeModel((uint16_t)slot);
  if (p != FINGERPRINT_OK) { finger.LEDcontrol(FINGERPRINT_LED_OFF, 0, 0); Serial.print(F("ERR store_failed=")); Serial.println(p); return; }

  finger.LEDcontrol(FINGERPRINT_LED_FLASHING, 50, FINGERPRINT_LED_BLUE, 5);
  Serial.print(F("OK enrolled="));
  Serial.println(slot);
}

void handleVerify() {
  finger.LEDcontrol(FINGERPRINT_LED_BREATHING, 100, FINGERPRINT_LED_BLUE);
  Serial.println(F("PROGRESS place_finger"));
  uint8_t p = waitForFingerCapture(10000);
  if (p != FINGERPRINT_OK) { finger.LEDcontrol(FINGERPRINT_LED_OFF, 0, 0); Serial.println(F("ERR timeout")); return; }
  p = finger.image2Tz();
  if (p != FINGERPRINT_OK) { finger.LEDcontrol(FINGERPRINT_LED_OFF, 0, 0); Serial.println(F("ERR poor_quality")); return; }
  p = finger.fingerSearch();
  if (p == FINGERPRINT_NOTFOUND) {
    finger.LEDcontrol(FINGERPRINT_LED_FLASHING, 50, FINGERPRINT_LED_RED, 3);
    Serial.println(F("ERR no_match"));
    return;
  }
  if (p != FINGERPRINT_OK) { finger.LEDcontrol(FINGERPRINT_LED_OFF, 0, 0); Serial.print(F("ERR search_failed=")); Serial.println(p); return; }
  finger.LEDcontrol(FINGERPRINT_LED_FLASHING, 50, FINGERPRINT_LED_BLUE, 3);
  Serial.print(F("OK match="));
  Serial.print(finger.fingerID);
  Serial.print(F(" confidence="));
  Serial.println(finger.confidence);
}

void handleDelete(int slot) {
  if (slot < 0 || slot >= finger.capacity) { Serial.println(F("ERR bad_args slot_out_of_range")); return; }
  uint8_t p = finger.deleteModel((uint16_t)slot);
  if (p == FINGERPRINT_OK) { Serial.print(F("OK deleted=")); Serial.println(slot); }
  else { Serial.print(F("ERR delete_failed=")); Serial.println(p); }
}

void handleClear(bool confirmed) {
  if (!confirmed) { Serial.println(F("ERR confirmation_required (use: clear confirm)")); return; }
  uint8_t p = finger.emptyDatabase();
  if (p == FINGERPRINT_OK) Serial.println(F("OK cleared"));
  else { Serial.print(F("ERR clear_failed=")); Serial.println(p); }
}

// Test-only helper used by Milestone A of the v2 authenticated-channel work:
// proves the firmware's SipHash-2-4 impl produces bit-identical MACs to the
// daemon's. Removed (or gated behind a build flag) once the v2 protocol is the
// only protocol. Hex helpers live in framing.h (r503::hex_to_bytes / bytes_to_hex).
void handleSiphash(const String& args) {
  int sp = args.indexOf(' ');
  String key_hex = (sp < 0) ? args : args.substring(0, sp);
  String msg_hex = (sp < 0) ? String("") : args.substring(sp + 1);
  if (key_hex.length() != 32) { Serial.println(F("ERR bad_args key_hex_must_be_32_chars")); return; }
  if (msg_hex.length() > 256) { Serial.println(F("ERR bad_args msg_hex_too_long")); return; }
  uint8_t key[16];
  size_t key_len;
  if (!r503::hex_to_bytes(key_hex.c_str(), key_hex.length(), key, 16, &key_len) || key_len != 16) {
    Serial.println(F("ERR bad_args bad_key_hex"));
    return;
  }
  uint8_t msg[128];
  size_t msg_len = 0;
  if (msg_hex.length() > 0) {
    if (!r503::hex_to_bytes(msg_hex.c_str(), msg_hex.length(), msg, 128, &msg_len)) {
      Serial.println(F("ERR bad_args bad_msg_hex"));
      return;
    }
  }
  uint64_t mac = r503::siphash24(key, msg, msg_len);
  uint8_t mac_bytes[8];
  r503::siphash_to_le_bytes(mac, mac_bytes);
  char mac_hex[17];
  r503::bytes_to_hex(mac_bytes, 8, mac_hex);
  Serial.print(F("OK mac="));
  Serial.println(mac_hex);
}

// Milestone B test command: emit a firmware-encoded response frame.
// Syntax: frame_resp <key_hex(32)> <counter> <seq> <body...>
// body is everything after the third space and may contain spaces.
void handleFrameResp(const String& args) {
  int sp1 = args.indexOf(' ');
  if (sp1 < 0) { Serial.println(F("ERR bad_args need_counter")); return; }
  int sp2 = args.indexOf(' ', sp1 + 1);
  if (sp2 < 0) { Serial.println(F("ERR bad_args need_seq")); return; }
  int sp3 = args.indexOf(' ', sp2 + 1);
  if (sp3 < 0) { Serial.println(F("ERR bad_args need_body")); return; }
  String key_hex     = args.substring(0, sp1);
  String counter_str = args.substring(sp1 + 1, sp2);
  String seq_str     = args.substring(sp2 + 1, sp3);
  String body        = args.substring(sp3 + 1);

  if (key_hex.length() != 32) { Serial.println(F("ERR bad_args bad_key_len")); return; }
  uint8_t key[16];
  size_t key_len;
  if (!r503::hex_to_bytes(key_hex.c_str(), 32, key, 16, &key_len) || key_len != 16) {
    Serial.println(F("ERR bad_args bad_key_hex")); return;
  }
  uint64_t counter;
  if (!r503::parse_u64(counter_str.c_str(), counter_str.length(), &counter)) {
    Serial.println(F("ERR bad_args bad_counter")); return;
  }
  uint32_t seq;
  if (!r503::parse_u32(seq_str.c_str(), seq_str.length(), &seq)) {
    Serial.println(F("ERR bad_args bad_seq")); return;
  }
  char out[256];
  size_t n = r503::encode_response_frame(key, counter, seq, body.c_str(), body.length(), out, sizeof(out));
  if (n == 0) { Serial.println(F("ERR encode_overflow")); return; }
  Serial.print(F("OK frame="));
  Serial.println(out);
}

// Milestone C: pairing + counter state introspection. `status` stays in v2 as
// the unauthenticated pre-handshake query (daemon needs to know if the Nano is
// paired before deciding to attempt key-based commands). The `ee_*` commands
// are test-only and removed at Milestone D cutover.

void handleStatus() {
  uint64_t ctr = r503::ee_load_counter();
  char ctr_buf[21];
  r503::format_u64(ctr, ctr_buf);
  Serial.print(F("OK paired="));
  Serial.print(r503::ee_is_paired() ? F("true") : F("false"));
  Serial.print(F(" counter="));
  Serial.print(ctr_buf);
  Serial.print(F(" fmt="));
  Serial.print(r503::EE_FORMAT_VERSION);
  Serial.println(F(" fw=0.4"));
}

void handleEePair(const String& args) {
  if (args.length() != 32) { Serial.println(F("ERR bad_args bad_key_len")); return; }
  uint8_t key[16];
  size_t key_len;
  if (!r503::hex_to_bytes(args.c_str(), 32, key, 16, &key_len) || key_len != 16) {
    Serial.println(F("ERR bad_args bad_key_hex")); return;
  }
  r503::ee_save_pairing(key);
  Serial.println(F("OK paired"));
}

// Milestone D: production pairing commands. `pair` is the daemon-driven
// pairing path that REFUSES when the Nano is already paired (defeats
// attacker-races-to-pair). `unpair` requires the caller to prove key
// knowledge by passing the current key — Milestone E replaces this proof
// with a MAC-framed authenticated `unpair` so the key never crosses the wire.
void handlePair(const String& args) {
  if (r503::ee_is_paired()) { Serial.println(F("ERR already_paired")); return; }
  if (args.length() != 32)  { Serial.println(F("ERR bad_args bad_key_len")); return; }
  uint8_t key[16];
  size_t key_len;
  if (!r503::hex_to_bytes(args.c_str(), 32, key, 16, &key_len) || key_len != 16) {
    Serial.println(F("ERR bad_args bad_key_hex")); return;
  }
  r503::ee_save_pairing(key);
  Serial.println(F("OK paired"));
}

void handleUnpair(const String& args) {
  if (!r503::ee_is_paired()) { Serial.println(F("ERR not_paired")); return; }
  if (args.length() != 32)   { Serial.println(F("ERR bad_args bad_key_len")); return; }
  uint8_t given[16];
  size_t given_len;
  if (!r503::hex_to_bytes(args.c_str(), 32, given, 16, &given_len) || given_len != 16) {
    Serial.println(F("ERR bad_args bad_key_hex")); return;
  }
  uint8_t stored[16];
  if (!r503::ee_load_key(stored)) { Serial.println(F("ERR no_key")); return; }
  uint8_t diff = 0;
  for (uint8_t i = 0; i < 16; ++i) diff |= given[i] ^ stored[i];
  if (diff != 0) { Serial.println(F("ERR key_mismatch")); return; }
  r503::ee_wipe();
  Serial.println(F("OK unpaired"));
}

void handleEeBump() {
  uint64_t ctr = r503::ee_load_counter();
  ctr += 1;
  if (!r503::ee_save_counter(ctr)) {
    Serial.println(F("ERR save_failed")); return;
  }
  char ctr_buf[21];
  r503::format_u64(ctr, ctr_buf);
  Serial.print(F("OK counter="));
  Serial.println(ctr_buf);
}

void handleEeWipe() {
  r503::ee_wipe();
  Serial.println(F("OK wiped"));
}

// Dumps all 16 cells as "OK ring=<c0>,<c1>,...,<c15>". Each cell prints as
// either its decimal counter value (if CRC valid) or `-` (if invalid).
void handleEeRing() {
  Serial.print(F("OK ring="));
  uint8_t cell[r503::EE_COUNTER_RING_CELL_SIZE];
  for (uint8_t i = 0; i < r503::EE_COUNTER_RING_CELLS; ++i) {
    if (i > 0) Serial.print(',');
    r503::ee_read_cell(i, cell);
    uint16_t want_crc = r503::crc16_ccitt(cell, 8);
    uint16_t got_crc  = (uint16_t)cell[8] | ((uint16_t)cell[9] << 8);
    if (got_crc != want_crc) {
      Serial.print('-');
    } else {
      uint64_t ctr = 0;
      for (int8_t j = 7; j >= 0; --j) ctr = (ctr << 8) | (uint64_t)cell[j];
      char buf[21];
      r503::format_u64(ctr, buf);
      Serial.print(buf);
    }
  }
  Serial.println();
}

// Milestone B test command: parse + MAC-verify a command frame.
// Syntax: frame_cmd <key_hex(32)> <framed_command>
// `framed_command` is the rest of the line and may contain spaces.
void handleFrameCmd(const String& args) {
  int sp1 = args.indexOf(' ');
  if (sp1 < 0) { Serial.println(F("ERR bad_args need_framed")); return; }
  String key_hex = args.substring(0, sp1);
  String framed  = args.substring(sp1 + 1);

  if (key_hex.length() != 32) { Serial.println(F("ERR bad_args bad_key_len")); return; }
  uint8_t key[16];
  size_t key_len;
  if (!r503::hex_to_bytes(key_hex.c_str(), 32, key, 16, &key_len) || key_len != 16) {
    Serial.println(F("ERR bad_args bad_key_hex")); return;
  }
  uint64_t counter = 0;
  const char* cmd_line = nullptr;
  size_t cmd_line_len = 0;
  r503::FrameParseStatus rc = r503::verify_command_frame(
    key, framed.c_str(), framed.length(),
    &counter, &cmd_line, &cmd_line_len);
  if (rc != r503::FRAME_OK) {
    Serial.print(F("ERR frame_rc=")); Serial.println((int)rc); return;
  }
  char ctr_buf[21];
  r503::format_u64(counter, ctr_buf);
  Serial.print(F("OK counter="));
  Serial.print(ctr_buf);
  Serial.print(F(" inner="));
  for (size_t i = 0; i < cmd_line_len; ++i) Serial.print(cmd_line[i]);
  Serial.println();
}

void dispatch(const String& line) {
  if (line == "info") emitInfo();
  else if (line == "count") emitCount();
  else if (line == "verify" || line == "identify") handleVerify();
  else if (line == "clear") handleClear(false);
  else if (line == "clear confirm") handleClear(true);
  else if (line.startsWith("enroll ")) handleEnroll(line.substring(7).toInt());
  else if (line.startsWith("delete ")) handleDelete(line.substring(7).toInt());
  else if (line.startsWith("siphash ")) handleSiphash(line.substring(8));
  else if (line.startsWith("frame_resp ")) handleFrameResp(line.substring(11));
  else if (line.startsWith("frame_cmd "))  handleFrameCmd(line.substring(10));
  else if (line == "status") handleStatus();
  else if (line.startsWith("pair "))   handlePair(line.substring(5));
  else if (line.startsWith("unpair ")) handleUnpair(line.substring(7));
  else if (line.startsWith("ee_pair ")) handleEePair(line.substring(8));
  else if (line == "ee_bump") handleEeBump();
  else if (line == "ee_wipe") handleEeWipe();
  else if (line == "ee_ring") handleEeRing();
  else if (line == "wake") { Serial.print(F("OK wake=")); Serial.println(digitalRead(PIN_WAKE) == LOW ? '1' : '0'); }
  else if (line == "ping") Serial.println(F("OK pong"));
  else if (line == "led off") { finger.LEDcontrol(FINGERPRINT_LED_OFF, 0, 0); Serial.println(F("OK")); }
  else { Serial.print(F("ERR unknown_command ")); Serial.println(line); }
}

void setup() {
  pinMode(PIN_WAKE, INPUT);
  pinMode(LED_BUILTIN, OUTPUT);
  Serial.begin(PC_BAUD);
  while (!Serial) { ; }
  delay(500);
  Serial.println(F("R503FP READY fw=0.4"));
  finger.begin(FP_BAUD);
  emitInfo();
}

void loop() {
  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\n' || c == '\r') {
      if (inbuf.length() > 0) {
        digitalWrite(LED_BUILTIN, HIGH);
        dispatch(inbuf);
        digitalWrite(LED_BUILTIN, LOW);
        inbuf = "";
      }
    } else {
      inbuf += c;
      // 320 leaves headroom for the test-vector command ("siphash " + 32-char
      // key + space + up to 256-char msg = 297 chars). v2 framed commands are
      // shorter (~80 chars) so this cap stays generous post-cutover too.
      if (inbuf.length() > 320) { Serial.println(F("ERR bad_args overflow")); inbuf = ""; }
    }
  }
}
