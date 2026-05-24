#!/usr/bin/env python3
"""
r503ctl.py — pyserial driver for the r503fp firmware's §5 ASCII protocol.

Usage as a library:

    from r503ctl import R503
    with R503() as fp:                       # auto-detects /dev/ttyACM* or ttyUSB*
        info = fp.info()
        print(info.capacity, info.enrolled)
        m = fp.verify()                      # prompts user, blocks until finger
        print(m.slot, m.confidence)

Usage from the shell:

    r503ctl.py info
    r503ctl.py enroll 2
    r503ctl.py verify
    r503ctl.py delete 0
    r503ctl.py clear

NOTE: requires the dnf-installed pyserial at /usr/lib/python3.14/site-packages/.
Run via `/usr/bin/python3 r503ctl.py …`, NOT the Homebrew Python which has its
own (missing) site-packages.
"""
from __future__ import annotations

import argparse
import glob
import sys
import time
from dataclasses import dataclass
from typing import Callable, Optional

import serial  # noqa: E402

DEFAULT_BAUD = 115200

# Per-command timeouts (ms). Conservative; firmware enforces its own internal
# stage timeouts (e.g. 8s per capture stage during enroll).
TIMEOUT_MS = {
    "info":     2000,
    "count":    2000,
    "enroll":   45000,   # multi-step user-interactive
    "verify":   15000,
    "identify": 15000,
    "delete":    2000,
    "clear":     3000,
    "led":       2000,
    "wake":      2000,
    "ping":      2000,
    "reset":     5000,
}


class R503Error(Exception):
    """Base class for any error talking to the sensor."""


class R503Timeout(R503Error):
    """No final OK/ERR within the allotted timeout."""


class R503CommandError(R503Error):
    """Firmware returned an ERR line."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code} {detail}".strip())


@dataclass
class SensorInfo:
    fw: str
    capacity: int
    enrolled: int
    sysid: str
    security: int
    device_addr: str


@dataclass
class MatchResult:
    slot: int
    confidence: int


def find_port() -> str:
    """First matching serial device. ACM (Uno R3 / ATmega16U2) preferred over
    USB (CH340 Nano clones)."""
    for pattern in ("/dev/ttyACM*", "/dev/ttyUSB*"):
        ports = sorted(glob.glob(pattern))
        if ports:
            return ports[0]
    raise FileNotFoundError(
        "No serial device at /dev/ttyACM* or /dev/ttyUSB*. Is the Uno plugged in?"
    )


class R503:
    """Wraps the r503fp firmware's line protocol over USB-CDC."""

    def __init__(
        self,
        port: Optional[str] = None,
        baud: int = DEFAULT_BAUD,
        sync_timeout_s: float = 8.0,
        on_progress: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.port_path = port or find_port()
        self.ser = serial.Serial(self.port_path, baud, timeout=0.2)
        self.on_progress = on_progress or self._default_progress
        self._buf = bytearray()
        # Opening the port DTR-resets the Uno. Firmware setup() can take up
        # to ~3.5s (delay(500) + finger.begin's 1s delay + verifyPassword
        # response). Instead of guessing a fixed delay, we send `ping` until
        # we see `OK pong` — guarantees we're synchronized with loop().
        self._sync(sync_timeout_s)

    def _sync(self, timeout_s: float) -> None:
        # Step 1: drain firmware boot output to silence (300ms of no bytes).
        # Avoids sending multiple pings while setup() is still running and
        # queueing them in the Uno's input buffer.
        deadline = time.monotonic() + timeout_s
        last_byte_at: Optional[float] = None
        while time.monotonic() < deadline:
            self.ser.timeout = 0.1
            chunk = self.ser.read(256)
            if chunk:
                last_byte_at = time.monotonic()
            elif last_byte_at is not None and time.monotonic() - last_byte_at > 0.3:
                break
        self._buf.clear()
        self.ser.reset_input_buffer()

        # Step 2: single ping/pong handshake.
        self.ser.write(b"ping\n")
        self.ser.flush()
        pong_deadline = min(deadline, time.monotonic() + 2.0)
        while time.monotonic() < pong_deadline:
            line = self._read_line(pong_deadline)
            if line == "OK pong":
                return
            if line is None:
                break
        raise R503Timeout(
            f"could not synchronize with firmware (no OK pong within {timeout_s}s)"
        )

    @staticmethod
    def _default_progress(msg: str) -> None:
        print(f"… {msg}", file=sys.stderr, flush=True)

    def close(self) -> None:
        self.ser.close()

    def __enter__(self) -> "R503":
        return self

    def __exit__(self, *a) -> None:
        self.close()

    # ------------------------------------------------------------------ low-level

    def _send(self, cmd: str) -> None:
        self.ser.write((cmd + "\n").encode("ascii"))
        self.ser.flush()

    def _read_line(self, deadline: float) -> Optional[str]:
        """Read one newline-terminated line. Returns None on deadline."""
        while True:
            nl = self._buf.find(b"\n")
            if nl >= 0:
                line = bytes(self._buf[:nl]).decode("ascii", errors="replace").rstrip("\r")
                del self._buf[: nl + 1]
                return line
            now = time.monotonic()
            if now >= deadline:
                return None
            self.ser.timeout = min(0.2, deadline - now)
            chunk = self.ser.read(256)
            if chunk:
                self._buf += chunk

    def _execute(self, cmd: str, timeout_ms: int) -> str:
        """Send command, stream PROGRESS lines to the callback, return the
        final OK/ERR line. Raises R503Timeout if neither arrives."""
        self._send(cmd)
        deadline = time.monotonic() + timeout_ms / 1000.0
        while True:
            line = self._read_line(deadline)
            if line is None:
                raise R503Timeout(f"no final response for: {cmd}")
            if not line:
                continue
            if line.startswith("PROGRESS "):
                self.on_progress(line[len("PROGRESS "):])
                continue
            if line.startswith("OK") or line.startswith("ERR"):
                return line
            # firmware chatter we don't recognize — surface via progress for visibility
            self.on_progress(f"[unhandled] {line}")

    @staticmethod
    def _expect_ok(line: str) -> str:
        if line.startswith("OK"):
            return line[len("OK"):].strip()
        # ERR <code> [<detail words…>]
        parts = line.split(None, 2)
        code = parts[1] if len(parts) > 1 else "unknown"
        detail = parts[2] if len(parts) > 2 else ""
        raise R503CommandError(code, detail)

    @staticmethod
    def _parse_kv(body: str) -> dict[str, str]:
        return {k: v for k, _, v in (p.partition("=") for p in body.split()) if k}

    # ------------------------------------------------------------------ commands

    def info(self) -> SensorInfo:
        kv = self._parse_kv(self._expect_ok(self._execute("info", TIMEOUT_MS["info"])))
        return SensorInfo(
            fw=kv.get("fw", ""),
            capacity=int(kv.get("capacity", "0")),
            enrolled=int(kv.get("enrolled", "0")),
            sysid=kv.get("sysid", ""),
            security=int(kv.get("security", "0")),
            device_addr=kv.get("device_addr", ""),
        )

    def count(self) -> int:
        kv = self._parse_kv(self._expect_ok(self._execute("count", TIMEOUT_MS["count"])))
        return int(kv["count"])

    def enroll(self, slot: int) -> int:
        kv = self._parse_kv(
            self._expect_ok(self._execute(f"enroll {slot}", TIMEOUT_MS["enroll"]))
        )
        return int(kv["enrolled"])

    def verify(self) -> MatchResult:
        kv = self._parse_kv(
            self._expect_ok(self._execute("verify", TIMEOUT_MS["verify"]))
        )
        return MatchResult(slot=int(kv["match"]), confidence=int(kv["confidence"]))

    def identify(self) -> MatchResult:
        kv = self._parse_kv(
            self._expect_ok(self._execute("identify", TIMEOUT_MS["identify"]))
        )
        return MatchResult(slot=int(kv["match"]), confidence=int(kv["confidence"]))

    def delete(self, slot: int) -> int:
        kv = self._parse_kv(
            self._expect_ok(self._execute(f"delete {slot}", TIMEOUT_MS["delete"]))
        )
        return int(kv["deleted"])

    def clear(self) -> None:
        self._expect_ok(self._execute("clear confirm", TIMEOUT_MS["clear"]))

    def wake(self) -> bool:
        kv = self._parse_kv(self._expect_ok(self._execute("wake", TIMEOUT_MS["wake"])))
        return kv["wake"] == "1"

    def ping(self) -> bool:
        line = self._execute("ping", TIMEOUT_MS["ping"])
        return line.startswith("OK pong")

    def led_off(self) -> None:
        self._expect_ok(self._execute("led off", TIMEOUT_MS["led"]))


# ============================================================================ CLI


def _cli() -> int:
    p = argparse.ArgumentParser(prog="r503ctl", description="R503 fingerprint reader CLI")
    p.add_argument("--port", help="serial port; auto-detected if omitted")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("info", help="sensor parameters")
    sub.add_parser("count", help="enrolled template count")
    e = sub.add_parser("enroll", help="enroll a finger into a slot")
    e.add_argument("slot", type=int)
    sub.add_parser("verify", help="capture finger, search all slots")
    sub.add_parser("identify", help="alias for verify")
    d = sub.add_parser("delete", help="erase one slot")
    d.add_argument("slot", type=int)
    sub.add_parser("clear", help="erase all slots")
    sub.add_parser("ping", help="firmware liveness check")
    sub.add_parser("wake", help="read WAKEUP pin state")
    sub.add_parser("led-off", help="turn off the sensor LED ring")
    args = p.parse_args()

    try:
        with R503(port=args.port) as fp:
            if args.cmd == "info":
                i = fp.info()
                print(
                    f"fw={i.fw} capacity={i.capacity} enrolled={i.enrolled} "
                    f"sysid={i.sysid} security={i.security} device_addr={i.device_addr}"
                )
            elif args.cmd == "count":
                print(fp.count())
            elif args.cmd == "enroll":
                print(f"enrolled slot {fp.enroll(args.slot)}")
            elif args.cmd in ("verify", "identify"):
                m = fp.verify()
                print(f"match slot={m.slot} confidence={m.confidence}")
            elif args.cmd == "delete":
                print(f"deleted slot {fp.delete(args.slot)}")
            elif args.cmd == "clear":
                fp.clear()
                print("cleared")
            elif args.cmd == "ping":
                print("pong" if fp.ping() else "no")
            elif args.cmd == "wake":
                print("finger" if fp.wake() else "no finger")
            elif args.cmd == "led-off":
                fp.led_off()
                print("led off")
    except R503CommandError as e:
        print(f"ERR {e.code} {e.detail}".rstrip(), file=sys.stderr)
        return 1
    except R503Timeout as e:
        print(f"TIMEOUT {e}", file=sys.stderr)
        return 2
    except FileNotFoundError as e:
        print(f"NO_DEVICE {e}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(_cli())
