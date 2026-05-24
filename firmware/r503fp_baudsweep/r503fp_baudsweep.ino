// r503fp_baudsweep.ino — try common R503 baud rates and report which works.
//
// Sweeps 9600 / 19200 / 38400 / 57600 / 115200 on SoftwareSerial(D2,D3).
// For each: re-initialize, attempt verifyPassword(), report result over PC link.
// Stops on first success and remains usable for `info` queries afterwards.

#include <SoftwareSerial.h>
#include <Adafruit_Fingerprint.h>

const long PC_BAUD = 115200;
const uint8_t PIN_RX = 2;
const uint8_t PIN_TX = 3;

const long bauds[] = {9600, 19200, 38400, 57600, 115200};
const int nBauds = sizeof(bauds) / sizeof(bauds[0]);

SoftwareSerial sensorSerial(PIN_RX, PIN_TX);
Adafruit_Fingerprint finger(&sensorSerial);

long workingBaud = 0;

bool tryBaud(long b) {
  Serial.print(F("PROGRESS trying_baud="));
  Serial.println(b);
  sensorSerial.end();
  delay(50);
  sensorSerial.begin(b);
  delay(200);
  return finger.verifyPassword();
}

void setup() {
  pinMode(LED_BUILTIN, OUTPUT);
  Serial.begin(PC_BAUD);
  while (!Serial) { ; }
  delay(100);
  Serial.println(F("R503FP READY fw=0.2-baudsweep"));

  for (int i = 0; i < nBauds; i++) {
    if (tryBaud(bauds[i])) {
      workingBaud = bauds[i];
      Serial.print(F("OK found_baud="));
      Serial.println(workingBaud);
      finger.getParameters();
      finger.getTemplateCount();
      Serial.print(F("OK capacity="));
      Serial.print(finger.capacity);
      Serial.print(F(" enrolled="));
      Serial.print(finger.templateCount);
      Serial.print(F(" sysid=0x"));
      Serial.print(finger.system_id, HEX);
      Serial.print(F(" security="));
      Serial.print(finger.security_level);
      Serial.print(F(" device_addr=0x"));
      Serial.println(finger.device_addr, HEX);
      return;
    }
  }
  Serial.println(F("ERR no_baud_responded — sensor mute on all sweep rates"));
}

void loop() {
  // Nothing else; sweep already reported.
}
