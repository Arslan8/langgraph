"""Private framed channel to the Docker lifecycle guardian."""

from __future__ import annotations

import hashlib
import json
import os
import select
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from threading import RLock
from typing import IO, Any

from langgraph.prebuilt.security._container_guardian import open_pidfd
from langgraph.prebuilt.security.linux import _readline_json


def _write_frame(stream: IO[bytes], data: bytes, timeout: float) -> None:
    """Bound the entire pipe write even when the receiver never reads stdin."""
    descriptor = stream.fileno()
    blocking = os.get_blocking(descriptor)
    deadline = time.monotonic() + timeout
    sent = 0
    os.set_blocking(descriptor, False)
    try:
        while sent < len(data):
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([], [descriptor], [], remaining)[1]:
                raise TimeoutError("Worker request write timed out")
            try:
                count = os.write(descriptor, memoryview(data)[sent : sent + 65536])
            except BlockingIOError:
                continue
            if count == 0:
                raise BrokenPipeError("Worker request pipe closed")
            sent += count
    finally:
        os.set_blocking(descriptor, blocking)


class DockerGuardian:
    def __init__(self, client: list[str]) -> None:
        self._lock = RLock()
        self._broken = False
        source = Path(__file__).with_name("_container_guardian.py")
        self.code_digest = hashlib.sha256(source.read_bytes()).hexdigest()
        # Self-acquisition occurs while this process is alive. Passing the
        # descriptor closes the parent-death/PID-reuse race in child-side lookup.
        controller_fd = open_pidfd(os.getpid())
        try:
            self._diagnostics = tempfile.TemporaryFile()
            try:
                self.process = subprocess.Popen(
                    [sys.executable, "-I", "-S", str(source), str(controller_fd)],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=self._diagnostics,
                    bufsize=0,
                    start_new_session=True,
                    pass_fds=(controller_fd,),
                )
            except BaseException:
                self._diagnostics.close()
                raise
        finally:
            os.close(controller_fd)
        try:
            assert self.process.stdin is not None
            _write_frame(
                self.process.stdin, (json.dumps({"client": client}) + "\n").encode(), 5
            )
            if _readline_json(self.process, 5) != {
                "status": "ready",
                "source_digest": self.code_digest,
            }:
                raise RuntimeError("Guardian did not acknowledge startup")
        except BaseException as exc:
            self._disconnect()
            # No lifecycle request has been sent during startup, so this helper
            # cannot own a container yet and can be reaped without losing cleanup.
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
            self._diagnostics.seek(0)
            diagnostic = self._diagnostics.read(8192).decode(errors="replace")
            self._diagnostics.close()
            raise RuntimeError("Guardian startup failed: " + diagnostic) from exc

    def _disconnect(self) -> None:
        self._broken = True
        if self.process.stdin is not None and not self.process.stdin.closed:
            self.process.stdin.close()
        if self.process.stdout is not None and not self.process.stdout.closed:
            self.process.stdout.close()

    def run(
        self, command: list[str], *, timeout: float, **kwargs: Any
    ) -> subprocess.CompletedProcess[str]:
        with self._lock:
            if self._broken or self.process.poll() is not None:
                raise subprocess.SubprocessError("Guardian channel is unavailable")
            try:
                encoded = (
                    json.dumps({"command": command, "timeout": timeout}) + "\n"
                ).encode()
                if len(encoded) > 1048576:
                    raise ValueError("Guardian request exceeds frame limit")
                assert self.process.stdin is not None
                _write_frame(self.process.stdin, encoded, 5)
                response = _readline_json(self.process, timeout + 25)
                if "error" in response:
                    raise subprocess.SubprocessError(
                        "Guardian command failed: " + response["error"]
                    )
                return subprocess.CompletedProcess(
                    command,
                    response["returncode"],
                    response["stdout"],
                    response["stderr"],
                )
            except Exception:
                self._disconnect()
                raise subprocess.SubprocessError("Guardian protocol failed") from None

    def close(self) -> None:
        with self._lock:
            if not self._broken and self.process.poll() is None:
                assert self.process.stdin is not None
                _write_frame(self.process.stdin, b'{"shutdown":true}\n', 5)
            self._disconnect()
            # Never kill a guardian that may still be reclaiming a container.
            self.process.wait(timeout=25)
            self._diagnostics.close()
            if self.process.returncode:
                raise subprocess.SubprocessError("Guardian did not finish cleanly")
