# Firmware

Arduino sketches for the R503 + Nano bridge.

## Sketches

- **`r503fp_stub/`** — minimal echo-OK firmware. No R503 wiring required. Used for the §6.4 Path A/B/C spike to confirm Nano enumeration and bidirectional serial. See the sketch header comment for details.
- **`r503fp/`** — full firmware implementing the §5 ASCII command protocol (`info`, `enroll`, `verify`, `identify`, `delete`, `clear`, `led`, `cancel`, `reset`). To be written once the stub is verified end-to-end.

## Toolchain

`arduino-cli` driven, no IDE required.

```bash
# One-time setup (already done on mat-linux):
arduino-cli core install arduino:avr
arduino-cli lib install "Adafruit Fingerprint Sensor Library"
```

## Build + flash

Elegoo Nanos ship with the **old** ATmega328 bootloader. Use the `atmega328old` CPU variant for upload — compile is the same either way.

```bash
# Compile
arduino-cli compile --fqbn arduino:avr:nano firmware/r503fp_stub/

# Find the port (CH340 enumerates as ttyUSB on Fedora, not ttyACM)
arduino-cli board list

# Flash (replace /dev/ttyUSB0 with whatever showed up)
arduino-cli upload \
  --fqbn arduino:avr:nano:cpu=atmega328old \
  --port /dev/ttyUSB0 \
  firmware/r503fp_stub/
```

If `upload` complains about permission denied on `/dev/ttyUSB0`, either log out and back in (to pick up the `dialout` group membership) or prefix with `sudo`.

## Serial monitor

```bash
tio -b 115200 /dev/ttyUSB0
```

Type `hello\n`, expect `OK echo=hello`. Banner appears on every reset.
