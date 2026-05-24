// r503fp_clean.ino — minimal, library-correct R503 init.
//
// Goes through Adafruit_Fingerprint's begin() which includes a 1-second
// boot delay. Then ONE attempt at verifyPassword(). Reports.

#include <SoftwareSerial.h>
#include <Adafruit_Fingerprint.h>

const long PC_BAUD = 115200;
const uint8_t PIN_RX = 2;
const uint8_t PIN_TX = 3;

SoftwareSerial sensorSerial(PIN_RX, PIN_TX);
Adafruit_Fingerprint finger = Adafruit_Fingerprint(&sensorSerial);

void setup() {
  Serial.begin(PC_BAUD);
  while (!Serial) { ; }

  // Give the sensor 3 full seconds to power up and stabilize before we
  // touch anything. The Uno's reset glitches the 3V3 rail briefly, so the
  // sensor effectively re-boots on every firmware flash.
  Serial.println(F("waiting 3s for sensor boot..."));
  delay(3000);

  Serial.println(F("calling finger.begin(57600) ..."));
  finger.begin(57600);  // library includes its own 1s boot delay + serial init

  Serial.println(F("calling finger.verifyPassword() ..."));
  if (finger.verifyPassword()) {
    Serial.println(F("OK verifyPassword PASSED"));
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
  } else {
    Serial.println(F("ERR verifyPassword FAILED — sensor mute or wrong password"));
  }
}

void loop() { }
