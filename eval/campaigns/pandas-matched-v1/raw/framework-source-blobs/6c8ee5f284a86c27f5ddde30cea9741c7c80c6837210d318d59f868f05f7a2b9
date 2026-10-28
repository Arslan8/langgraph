"""Isolated standard-library guardian for one trusted Docker lifecycle client.

The controller owns stdin. EOF triggers reclamation, even after controller
SIGKILL. This process must survive and the pinned local daemon must be reachable.
An uncertain creation never becomes confirmed cleanup merely from an empty list.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import select
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


def open_pidfd(pid: int) -> int:
    """Acquire the Linux handle through libc when Python lacks its wrapper."""
    libc = ctypes.CDLL(None, use_errno=True)
    operation = libc.pidfd_open
    operation.argtypes = [ctypes.c_int, ctypes.c_uint]
    operation.restype = ctypes.c_int
    descriptor = operation(pid, 0)
    if descriptor < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return descriptor


class ParentChannel:
    """Watch the controller's transferred pidfd, never a reusable numeric PID."""

    def __init__(self, parent_fd: int) -> None:
        self.parent_fd = parent_fd
        os.set_inheritable(parent_fd, False)
        self.buffer = b""

    def parent_dead(self) -> bool:
        return bool(select.select([self.parent_fd], [], [], 0)[0])

    def read_frame(self, limit: int) -> bytes | None:
        descriptor = sys.stdin.fileno()
        while not self.parent_dead():
            if b"\n" in self.buffer:
                line, self.buffer = self.buffer.split(b"\n", 1)
                if len(line) >= limit:
                    raise ValueError("Guardian frame exceeds limit")
                return line
            if len(self.buffer) >= limit:
                raise ValueError("Guardian frame exceeds limit")
            ready = select.select([descriptor, self.parent_fd], [], [])[0]
            if self.parent_fd in ready:
                return None
            chunk = os.read(descriptor, min(65536, limit - len(self.buffer)))
            if not chunk:
                return None
            self.buffer += chunk
        return None


class Guardian:
    def __init__(self, client: list[str]) -> None:
        self.client = client
        self.owned: dict[str, str] = {}
        self.uncertain: set[str] = set()

    def command(self, arguments: list[str], timeout: float) -> Any:
        return subprocess.run(
            [*self.client, *arguments],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            stdin=subprocess.DEVNULL,
        )

    def ownership(self, name: str) -> bool | None:
        result = self.command(
            [
                "ps",
                "-a",
                "--no-trunc",
                "--filter",
                f"name=^/{name}$",
                "--format",
                "{{.ID}}",
            ],
            10,
        )
        if result.returncode:
            return False
        if not result.stdout.strip():
            return None
        result = self.command(["inspect", "--type", "container", name], 10)
        if result.returncode:
            return False
        values = json.loads(result.stdout)
        return (
            len(values) == 1
            and values[0]["Config"]["Labels"].get("slg.lifecycle.owner")
            == self.owned[name]
        )

    def execute(self, arguments: list[str], timeout: float) -> Any:
        operation = arguments[0]
        name = None
        observed_owner = False
        if operation == "run":
            name = arguments[arguments.index("--name") + 1]
            labels = [
                arguments[i + 1] for i, arg in enumerate(arguments) if arg == "--label"
            ]
            owners = [
                label.split("=", 1)[1]
                for label in labels
                if label.startswith("slg.lifecycle.owner=")
            ]
            if (
                not re.fullmatch(r"slg-session-[0-9a-f]{32}", name)
                or len(owners) != 1
                or not re.fullmatch(r"[0-9a-f]{64}", owners[0])
                or name in self.owned
            ):
                raise ValueError("Invalid container ownership request")
            # Register before submitting creation: controller death cannot leave
            # a successfully created container unknown to the guardian.
            self.owned[name] = owners[0]
        elif operation == "rm":
            name = arguments[-1]
            if name not in self.owned:
                raise ValueError("Container ownership cannot be confirmed")
            observed_owner = self.ownership(name)
            if observed_owner is False:
                raise ValueError("Container ownership cannot be confirmed")
        elif operation not in {"inspect", "ps"}:
            raise ValueError("Unsupported lifecycle command")
        try:
            result = self.command(arguments, timeout)
        except (OSError, subprocess.SubprocessError):
            if operation == "run" and name is not None:
                self.uncertain.add(name)
            raise
        if operation == "rm" and result.returncode == 0:
            if observed_owner:
                self.uncertain.discard(name)
        if operation == "ps" and any(
            f"name=^/{pending}$" in arguments for pending in self.uncertain
        ):
            return subprocess.CompletedProcess(
                arguments, 1, "", "Creation remains uncertain"
            )
        if operation == "ps" and result.returncode == 0 and not result.stdout.strip():
            for pending in tuple(self.owned):
                if f"name=^/{pending}$" in arguments:
                    del self.owned[pending]
        return result

    def reclaim(self) -> None:
        while self.owned:
            for name in tuple(self.owned):
                try:
                    ownership = self.ownership(name)
                    if ownership:
                        result = self.command(["rm", "-f", "--volumes", name], 10)
                        if result.returncode:
                            continue
                        # A previously uncertain create is resolved once that
                        # exact owned container is observed and removed.
                        self.uncertain.discard(name)
                    if self.ownership(name) is None and name not in self.uncertain:
                        del self.owned[name]
                except (
                    OSError,
                    subprocess.SubprocessError,
                    ValueError,
                    KeyError,
                    TypeError,
                ):
                    continue
            if self.owned:
                time.sleep(1)


def main() -> None:
    guardian = None
    channel = ParentChannel(int(sys.argv[1]))
    try:
        initial = channel.read_frame(65536)
        if initial is None:
            return
        configuration = json.loads(initial)
        client = configuration["client"]
        if (
            not isinstance(client, list)
            or len(client) != 3
            or not all(isinstance(part, str) for part in client)
            or not client[0].startswith("/")
            or client[1] != "--host"
            or not client[2].startswith("unix://")
        ):
            raise ValueError("A pinned local Docker client is required")
        guardian = Guardian(client)
        print(
            json.dumps(
                {
                    "status": "ready",
                    "source_digest": hashlib.sha256(
                        Path(__file__).read_bytes()
                    ).hexdigest(),
                }
            ),
            flush=True,
        )
        while True:
            line = channel.read_frame(1048576)
            if line is None:
                break
            request = json.loads(line)
            if request == {"shutdown": True}:
                break
            try:
                command = request["command"]
                if command[:3] != client:
                    raise ValueError("Docker endpoint changed")
                result = guardian.execute(command[3:], float(request["timeout"]))
                response = {
                    "returncode": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                }
            except Exception as exc:
                response = {"error": type(exc).__name__}
            if channel.parent_dead():
                break
            print(json.dumps(response), flush=True)
    finally:
        os.close(channel.parent_fd)
        if guardian is not None:
            guardian.reclaim()


if __name__ == "__main__":
    main()
