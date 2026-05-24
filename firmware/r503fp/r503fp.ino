// r503fp.ino — first cut of the production firmware implementing §5 ASCII protocol.
//
// Currently supports: info, count, list, enroll <slot>, verify, identify,
// delete <slot>, clear (requires `clear confirm`), led <r> <g> <b> <mode>.
//
// PC link: 115200 8N1, line-terminated commands, "OK …" or "ERR …" final lines,
// optional "PROGRESS …" intermediate lines during multi-step operations.

#include <SoftwareSerial.h>
#include <Adafruit_Fingerprint.h>

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
  Serial.print(F("OK fw=0.3 capacity="));
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

void dispatch(const String& line) {
  if (line == "info") emitInfo();
  else if (line == "count") emitCount();
  else if (line == "verify" || line == "identify") handleVerify();
  else if (line == "clear") handleClear(false);
  else if (line == "clear confirm") handleClear(true);
  else if (line.startsWith("enroll ")) handleEnroll(line.substring(7).toInt());
  else if (line.startsWith("delete ")) handleDelete(line.substring(7).toInt());
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
  Serial.println(F("R503FP READY fw=0.3"));
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
      if (inbuf.length() > 64) { Serial.println(F("ERR bad_args overflow")); inbuf = ""; }
    }
  }
}
