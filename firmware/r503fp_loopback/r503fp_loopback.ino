// r503fp_loopback.ino — Uno SoftwareSerial loopback test.
//
// Setup: jumper directly between Uno D3 and Uno D2 (no breadboard, no
// divider, no sensor). Confirms the Uno's SoftSerial TX/RX path works
// end-to-end at the same baud we use for the sensor.
//
// Sends a known pattern. Reads back. Reports match/mismatch over PC link.

#include <SoftwareSerial.h>

const long PC_BAUD = 115200;
const long FP_BAUD = 57600;
const uint8_t PIN_RX = 2;
const uint8_t PIN_TX = 3;

SoftwareSerial soft(PIN_RX, PIN_TX);

void setup() {
  pinMode(LED_BUILTIN, OUTPUT);
  Serial.begin(PC_BAUD);
  soft.begin(FP_BAUD);
  while (!Serial) { ; }
  delay(200);
  Serial.println(F("LOOPBACK TEST @ 57600 — bridge D3 to D2 with a jumper"));

  // Known pattern: 0x55 0xAA 0x33 0xCC 0xEF 0x01 — sync word + a few interesting bytes
  static const byte pattern[] = {0x55, 0xAA, 0x33, 0xCC, 0xEF, 0x01, 0x12, 0x34, 0x56, 0x78};
  const uint8_t nPattern = sizeof(pattern);

  Serial.print(F("TX: "));
  for (uint8_t i = 0; i < nPattern; i++) {
    soft.write(pattern[i]);
    if (pattern[i] < 0x10) Serial.print('0');
    Serial.print(pattern[i], HEX);
    Serial.print(' ');
  }
  Serial.println();

  delay(150);  // give SoftSerial time to clock all bytes out + back in

  Serial.print(F("RX: "));
  byte received[32];
  uint8_t nReceived = 0;
  unsigned long deadline = millis() + 500;
  while (millis() < deadline && nReceived < sizeof(received)) {
    if (soft.available()) {
      byte b = soft.read();
      received[nReceived++] = b;
      digitalWrite(LED_BUILTIN, HIGH);
      if (b < 0x10) Serial.print('0');
      Serial.print(b, HEX);
      Serial.print(' ');
      deadline = millis() + 100;  // extend if still receiving
    }
  }
  digitalWrite(LED_BUILTIN, LOW);
  Serial.println();

  bool matches = (nReceived == nPattern);
  if (matches) {
    for (uint8_t i = 0; i < nPattern; i++) {
      if (received[i] != pattern[i]) { matches = false; break; }
    }
  }

  if (matches) {
    Serial.println(F("VERDICT: PASS — SoftSerial loopback works perfectly"));
  } else if (nReceived == 0) {
    Serial.println(F("VERDICT: FAIL — no bytes received. Jumper D3↔D2 missing, or SoftSerial broken"));
  } else {
    Serial.print(F("VERDICT: FAIL — received "));
    Serial.print(nReceived);
    Serial.print(F(" bytes, expected "));
    Serial.print(nPattern);
    Serial.println(F(". SoftSerial degraded — bit timing issue?"));
  }
}

void loop() { }
