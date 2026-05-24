// r503fp_touchwake.ino — try verifyPassword repeatedly, report D4 state.
//
// Hypothesis: R503 main MCU sleeps until finger touches the cap ring.
// Touch the sensor face and HOLD throughout the run. If verifyPassword
// succeeds while D4=HIGH, the sensor was just sleeping.

#include <SoftwareSerial.h>
#include <Adafruit_Fingerprint.h>

const long PC_BAUD = 115200;
const uint8_t PIN_RX = 2;
const uint8_t PIN_TX = 3;
const uint8_t PIN_WAKE = 4;

SoftwareSerial sensorSerial(PIN_RX, PIN_TX);
Adafruit_Fingerprint finger(&sensorSerial);

void setup() {
  pinMode(PIN_WAKE, INPUT);
  pinMode(LED_BUILTIN, OUTPUT);
  Serial.begin(PC_BAUD);
  while (!Serial) { ; }
  delay(2000);
  Serial.println(F("TOUCH THE SENSOR NOW AND HOLD"));
  finger.begin(57600);
  Serial.println(F("running 10 verify attempts, 1s apart..."));
}

void loop() {
  static int attempt = 0;
  if (attempt >= 10) {
    digitalWrite(LED_BUILTIN, LOW);
    return;
  }
  attempt++;
  int wake = digitalRead(PIN_WAKE);
  Serial.print(F("attempt "));
  Serial.print(attempt);
  Serial.print(F(" wake="));
  Serial.print(wake);
  Serial.print(F(" -> "));
  digitalWrite(LED_BUILTIN, HIGH);
  bool ok = finger.verifyPassword();
  digitalWrite(LED_BUILTIN, LOW);
  if (ok) {
    Serial.println(F("PASS — SENSOR ALIVE!"));
    finger.getParameters();
    finger.getTemplateCount();
    Serial.print(F("    capacity="));
    Serial.print(finger.capacity);
    Serial.print(F(" enrolled="));
    Serial.println(finger.templateCount);
  } else {
    Serial.println(F("fail"));
  }
  delay(800);
}
