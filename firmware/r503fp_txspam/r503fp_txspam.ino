// r503fp_txspam.ino — continuously transmit 0x55 on D3 at 57600 baud.
//
// Measure D3 voltage with a multimeter:
//   ~2.5V → TX is alive, ~50% duty cycle on the line
//   ~5.0V → TX never drives (firmware bug or D3 dead)
//   ~0.0V → D3 stuck low

#include <SoftwareSerial.h>

const long PC_BAUD = 115200;
const long FP_BAUD = 57600;
const uint8_t PIN_RX = 2;
const uint8_t PIN_TX = 3;

SoftwareSerial soft(PIN_RX, PIN_TX);

void setup() {
  Serial.begin(PC_BAUD);
  soft.begin(FP_BAUD);
  while (!Serial) { ; }
  delay(200);
  Serial.println(F("TX SPAM @ 57600 on D3 — measure D3 voltage"));
  Serial.println(F("Expected ~2.5V if TX is working"));
}

void loop() {
  soft.write(0x55);  // 01010101 — alternating bits, 50% duty
  // no delay; spam as fast as SoftSerial will go (~10 bytes/ms at 57600)
}
