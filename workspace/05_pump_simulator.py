"""Interactive pump simulator for Example 5.

The simulator understands device behavior, not user identities or Cedar roles.
It accepts newline-delimited JSON over a Unix-domain socket and records only
commands that passed device-level validation.
"""

from __future__ import annotations

import argparse
import json
import os
import socketserver
from dataclasses import asdict, dataclass
from pathlib import Path
from threading import Lock
from typing import Any


@dataclass
class PumpState:
    running: bool = False
    flow_rate: float = 0.0
    calibration_offset: float = 0.0


class Pump:
    """Stateful simulated pump with no knowledge of authorization policy."""

    def __init__(self, log_path: Path) -> None:
        self.state = PumpState()
        self.log_path = log_path
        self.lock = Lock()

    def execute(self, message: dict[str, Any]) -> dict[str, Any]:
        device_id = message.get("device_id")
        operation = message.get("operation")
        value = message.get("value")
        if device_id != "pump-1":
            return {"ok": False, "error": "unknown device"}
        if operation not in {"inspect", "start", "stop", "set_flow", "calibrate"}:
            return {"ok": False, "error": "unknown operation"}

        with self.lock:
            before = asdict(self.state)
            error = self._apply(operation, value)
            if error is not None:
                return {"ok": False, "error": error}
            after = asdict(self.state)
            entry = {
                "device_id": device_id,
                "operation": operation,
                "value": value,
                "before": before,
                "after": after,
            }
            with self.log_path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(entry, sort_keys=True) + "\n")
            print(
                f"accepted {operation} device={device_id} value={value!r} "
                f"state={after}",
                flush=True,
            )
            return {
                "ok": True,
                "device_id": device_id,
                "operation": operation,
                "state": after,
            }

    def _apply(self, operation: str, value: object) -> str | None:
        if operation == "inspect":
            return None if value is None else "inspect does not accept a value"
        if operation == "start":
            if value is not None:
                return "start does not accept a value"
            self.state.running = True
            return None
        if operation == "stop":
            if value is not None:
                return "stop does not accept a value"
            self.state.running = False
            return None
        if type(value) not in {int, float}:
            return f"{operation} requires a numeric value"
        numeric = float(value)
        if operation == "set_flow":
            if not 0.0 <= numeric <= 100.0:
                return "flow rate must be between 0 and 100"
            self.state.flow_rate = numeric
            return None
        if not -10.0 <= numeric <= 10.0:
            return "calibration offset must be between -10 and 10"
        self.state.calibration_offset = numeric
        return None


class PumpRequestHandler(socketserver.StreamRequestHandler):
    """Handle one JSON request and response on a local stream connection."""

    def handle(self) -> None:
        try:
            raw = self.rfile.readline(64 * 1024)
            message = json.loads(raw)
            if not isinstance(message, dict):
                raise TypeError("request must be a JSON object")
            response = self.server.pump.execute(message)  # type: ignore[attr-defined]
        except (json.JSONDecodeError, TypeError, UnicodeDecodeError, ValueError) as exc:
            response = {"ok": False, "error": str(exc)}
        self.wfile.write((json.dumps(response, sort_keys=True) + "\n").encode())


class PumpServer(socketserver.UnixStreamServer):
    """Unix server carrying one shared simulated pump."""

    def __init__(self, socket_path: Path, pump: Pump) -> None:
        self.pump = pump
        super().__init__(os.fspath(socket_path), PumpRequestHandler)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--socket", type=Path, default=Path("/tmp/slanggraph-pump.sock")
    )
    parser.add_argument(
        "--log", type=Path, default=Path("/tmp/slanggraph-pump-commands.jsonl")
    )
    args = parser.parse_args()

    args.socket.parent.mkdir(parents=True, exist_ok=True)
    args.log.parent.mkdir(parents=True, exist_ok=True)
    args.socket.unlink(missing_ok=True)
    args.log.write_text("", encoding="utf-8")
    pump = Pump(args.log)
    server = PumpServer(args.socket, pump)
    args.socket.chmod(0o600)
    print(f"pump simulator listening on {args.socket}", flush=True)
    print(f"accepted-command log: {args.log}", flush=True)
    print(f"initial state: {asdict(pump.state)}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("stopping pump simulator", flush=True)
    finally:
        server.server_close()
        args.socket.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
