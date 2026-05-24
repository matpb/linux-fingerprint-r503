// r503fp_prod.ino — listen continuously, send VerifyPwd every 2s, report everything.
//
// Hand-crafts the VerifyPwd packet (no Adafruit library) so the test is
// purely about whether bytes reach the sensor's RX and a response comes back.
//
// If the sensor's RX is healthy and the brown-wire path is conducting,
// we'll see a 12-byte ACK packet (EF 01 FF FF FF FF 07 00 03 00 ...) back
// after the command. If the sensor's RX is dead or brown is broken, the
// sensor stays silent BUT we'll still capture 0x55 on power cycle (proving
// TX is alive). The asymmetry tells us where the break is.

#include <SoftwareSerial.h>

const long PC_BAUD = 115200;
const long FP_BAUD = 57600;
SoftwareSerial soft(2, 3);

static const byte verifyPwd[] = {
  0xEF, 0x01,
  0xFF, 0xFF, 0xFF, 0xFF,
  0x01,
  0x00, 0x07,
  0x13,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x1B
};

uint16_t iteration = 0;

void setup() {
  pinMode(LED_BUILTIN, OUTPUT);
  Serial.begin(PC_BAUD);
  soft.begin(FP_BAUD);
  while (!Serial) { ; }
  delay(100);
  Serial.println(F("listen-and-prod @ 57600. sending VerifyPwd every 2s. all RX bytes printed."));
}

void emitByte(byte b) {
  if (b < 0x10) Serial.print('0');
  Serial.print(b, HEX);
  Serial.print(' ');
}

void loop() {
  // Drain anything available right now (could be a delayed response, or a
  // 0x55 from a power cycle the user just did).
  if (soft.available()) {
    Serial.print(F("[unprompted] RX: "));
    while (soft.available()) {
      digitalWrite(LED_BUILTIN, HIGH);
      emitByte((byte)soft.read());
      delay(2); // give SoftSerial a moment to grab any trailing byte
    }
    digitalWrite(LED_BUILTIN, LOW);
    Serial.println();
  }

  // Send a VerifyPwd, then listen for ~1.5s for the response
  iteration++;
  Serial.print(F("--- iteration "));
  Serial.print(iteration);
  Serial.println(F(" ---"));
  Serial.print(F("TX: "));
  for (uint8_t i = 0; i < sizeof(verifyPwd); i++) {
    soft.write(verifyPwd[i]);
    emitByte(verifyPwd[i]);
  }
  Serial.println();

  Serial.print(F("RX: "));
  uint8_t bytesRx = 0;
  unsigned long deadline = millis() + 1500;
  while (millis() < deadline) {
    if (soft.available()) {
      digitalWrite(LED_BUILTIN, HIGH);
      emitByte((byte)soft.read());
      bytesRx++;
      deadline = millis() + 200; // extend deadline if still receiving
    }
  }
  digitalWrite(LED_BUILTIN, LOW);
  Serial.println();
  if (bytesRx == 0) {
    Serial.println(F("(no response)"));
  } else {
    Serial.print(F("("));
    Serial.print(bytesRx);
    Serial.println(F(" bytes)"));
  }

  delay(500); // gap between iterations
}
