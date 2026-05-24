// r503fp_rawdump.ino — raw UART dump for diagnosing dead sensor TX.
//
// Boots, sends a hand-crafted VerifyPassword command at 57600 directly to
// the R503, then dumps anything that comes back on D2 as hex bytes.
// No Adafruit_Fingerprint, no protocol parsing — just bytes in, bytes out.
//
// If we see ANY bytes from the sensor, its TX is alive and the issue is
// upstream (library, parsing). If we see nothing, the sensor's TX is mute.

#include <SoftwareSerial.h>

const long PC_BAUD = 115200;
const long FP_BAUD = 57600;
const uint8_t PIN_RX = 2;
const uint8_t PIN_TX = 3;

SoftwareSerial sensorSerial(PIN_RX, PIN_TX);

void setup() {
  pinMode(LED_BUILTIN, OUTPUT);
  Serial.begin(PC_BAUD);
  sensorSerial.begin(FP_BAUD);
  while (!Serial) { ; }
  delay(200);
  Serial.println(F("RAW UART BRIDGE @ 57600"));

  // Hand-crafted R503 VerifyPassword packet with default password 0x00000000.
  //   Header 0xEF 0x01
  //   Address 0xFFFFFFFF
  //   Package ID 0x01 (command)
  //   Length 0x0007 (instruction + 4 password bytes + 2 checksum bytes)
  //   Instruction 0x13 (VerifyPwd)
  //   Password 0x00000000
  //   Checksum = sum(PID + Length + Instruction + Password) = 0x01+0x00+0x07+0x13 = 0x1B
  static const byte cmd[] = {
    0xEF, 0x01,
    0xFF, 0xFF, 0xFF, 0xFF,
    0x01,
    0x00, 0x07,
    0x13,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x1B
  };

  Serial.print(F("TX: "));
  for (uint8_t i = 0; i < sizeof(cmd); i++) {
    sensorSerial.write(cmd[i]);
    if (cmd[i] < 0x10) Serial.print('0');
    Serial.print(cmd[i], HEX);
    Serial.print(' ');
  }
  Serial.println();

  Serial.print(F("RX: "));
}

unsigned long lastByte = 0;
bool gotAnything = false;

void loop() {
  while (sensorSerial.available()) {
    int b = sensorSerial.read();
    digitalWrite(LED_BUILTIN, HIGH);
    if (b < 0x10) Serial.print('0');
    Serial.print(b, HEX);
    Serial.print(' ');
    lastByte = millis();
    gotAnything = true;
  }
  digitalWrite(LED_BUILTIN, LOW);

  // After 3s of silence, declare a verdict.
  static bool reported = false;
  if (!reported && millis() > 5000) {
    Serial.println();
    if (gotAnything) {
      Serial.println(F("VERDICT: sensor TX is ALIVE (saw bytes above)"));
    } else {
      Serial.println(F("VERDICT: sensor TX is MUTE (no bytes after 5s)"));
    }
    reported = true;
  }
}
