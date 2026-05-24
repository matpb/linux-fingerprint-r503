// r503fp_stub.ino — echo-OK stub for the §6.4 Path A/B/C spike.
//
// Purpose: prove USB enumeration and bidirectional ASCII serial work,
// before we wire the R503. No SoftwareSerial, no Adafruit_Fingerprint.
//
// Behaviour:
//   - On boot, prints the banner once.
//   - For every newline-terminated input line, responds "OK echo=<line>".
//   - Blinks LED_BUILTIN briefly on each accepted line so we have visual
//     proof that command parsing is alive even if the host terminal is silent.
//   - Lines longer than 128 bytes are dropped with "ERR bad_args overflow".

const long PC_BAUD = 115200;
const char BANNER[] = "R503FP READY fw=0.0-stub capacity=0";

String inbuf;

void setup() {
  pinMode(LED_BUILTIN, OUTPUT);
  Serial.begin(PC_BAUD);
  while (!Serial) { ; }
  delay(100);
  Serial.println(BANNER);
}

void loop() {
  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\n' || c == '\r') {
      if (inbuf.length() > 0) {
        digitalWrite(LED_BUILTIN, HIGH);
        Serial.print("OK echo=");
        Serial.println(inbuf);
        digitalWrite(LED_BUILTIN, LOW);
        inbuf = "";
      }
    } else {
      inbuf += c;
      if (inbuf.length() > 128) {
        Serial.println("ERR bad_args overflow");
        inbuf = "";
      }
    }
  }
}
