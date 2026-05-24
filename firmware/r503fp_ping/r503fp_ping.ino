// r503fp_ping.ino — Layer 1 partial: prove the Uno can talk to the R503.
//
// Wiring (Uno R3 + R503, voltage divider on D3):
//   R503 red    → Uno 3.3V          (Power Supply, sensor main)
//   R503 black  → Uno GND
//   R503 yellow → Uno D2            (SoftwareSerial RX; sensor TX, 3.3V TTL)
//   R503 brown  → Uno D3 via divider (SoftwareSerial TX; sensor RX, 3.3V only)
//                  D3 ── 1kΩ ──┬── R503 brown
//                              └── 2kΩ ── GND
//   R503 blue   → Uno D4            (WAKEUP, HIGH when finger present; optional)
//   R503 white  → Uno 3.3V          (Touch power, shares rail with red)
//
// Commands (PC link @ 115200, line-terminated):
//   info  → query sensor: capacity, enrolled count, system id, security level, device addr
//   wake  → read WAKEUP pin state (0 or 1)
//   ping  → return "OK pong" without touching the sensor
// Anything else → "ERR unknown_command <token>"

#include <SoftwareSerial.h>
#include <Adafruit_Fingerprint.h>

const long PC_BAUD = 115200;
const long FP_BAUD = 57600;
const uint8_t PIN_RX   = 2;  // sensor TX (yellow)
const uint8_t PIN_TX   = 3;  // sensor RX (brown) via voltage divider
const uint8_t PIN_WAKE = 4;  // sensor WAKEUP (blue)

const char BANNER[] = "R503FP READY fw=0.1-ping";

SoftwareSerial sensorSerial(PIN_RX, PIN_TX);
Adafruit_Fingerprint finger(&sensorSerial);

String inbuf;

void emitInfo() {
  if (!finger.verifyPassword()) {
    Serial.println("ERR sensor_unreachable");
    return;
  }
  finger.getParameters();
  finger.getTemplateCount();
  Serial.print(F("OK fw=0.1-ping capacity="));
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

void setup() {
  pinMode(LED_BUILTIN, OUTPUT);
  pinMode(PIN_WAKE, INPUT);
  Serial.begin(PC_BAUD);
  while (!Serial) { ; }
  delay(100);
  Serial.println(BANNER);

  sensorSerial.begin(FP_BAUD);
  delay(200);
  emitInfo();
}

void loop() {
  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\n' || c == '\r') {
      if (inbuf.length() == 0) continue;
      digitalWrite(LED_BUILTIN, HIGH);
      if (inbuf == "info") {
        emitInfo();
      } else if (inbuf == "wake") {
        Serial.print(F("OK wake="));
        Serial.println(digitalRead(PIN_WAKE) ? '1' : '0');
      } else if (inbuf == "ping") {
        Serial.println(F("OK pong"));
      } else {
        Serial.print(F("ERR unknown_command "));
        Serial.println(inbuf);
      }
      digitalWrite(LED_BUILTIN, LOW);
      inbuf = "";
    } else {
      inbuf += c;
      if (inbuf.length() > 64) {
        Serial.println(F("ERR bad_args overflow"));
        inbuf = "";
      }
    }
  }
}
