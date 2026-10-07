"""Tool entry points imported only inside Linux sandbox integration tests."""

from __future__ import annotations

import asyncio
import fcntl
import os
import socket
import subprocess
import threading
import time
from pathlib import Path


def read_file(path: str) -> str:
    """Read one file granted by the test profile."""
    return Path(path).read_text()


def probe_file(path: str) -> str:
    """Attempt to read a path so the test can assert kernel denial."""
    return Path(path).read_text()


def hostile_probe(path: str, forbidden_path: str) -> str:
    """Ignore the declared path and attempt an undeclared filesystem read."""
    del path
    return Path(forbidden_path).read_text()


def write_file(path: str, content: str) -> str:
    """Write one file under a granted test directory."""
    Path(path).write_text(content)
    return "written"


async def async_read_file(path: str) -> str:
    """Exercise the asynchronous worker invocation path."""
    await asyncio.sleep(0)
    return Path(path).read_text()


def network_probe() -> str:
    """Attempt an undeclared outbound connection from the isolated namespace."""
    with socket.create_connection(("1.1.1.1", 443), timeout=0.2):
        return "connected"


def exec_probe() -> str:
    """Attempt an undeclared child executable after seccomp activation."""
    subprocess.run(("/usr/bin/true",), check=True)
    return "executed"


def environment_probe() -> dict[str, object]:
    """Return the worker environment and cwd for baseline assertions."""
    return {"cwd": os.getcwd(), "environment": dict(os.environ)}


def fork_probe() -> str:
    """Attempt undeclared process creation after seccomp activation."""
    os.fork()
    return "forked"


def unix_socket_probe() -> str:
    """Attempt an undeclared local IPC socket after seccomp activation."""
    socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    return "socket-created"


def file_limit_probe(size: int) -> str:
    """Attempt to grow one file beyond the configured resource ceiling."""
    try:
        Path("/tmp/oversized").write_bytes(b"x" * size)
    except OSError as exc:
        return f"blocked:{exc.errno}"
    return "written"


def descriptor_probe() -> list[int]:
    """Report unexpected descriptors inherited by the untrusted entry point."""
    inherited = []
    for descriptor in range(3, 64):
        try:
            os.fstat(descriptor)
        except OSError:
            continue
        inherited.append(descriptor)
    return inherited


def thread_probe() -> str:
    """Attempt to create an execution context outside the supervised thread."""
    worker = threading.Thread(target=lambda: None)
    worker.start()
    worker.join()
    return "thread-created"


def noop_path(path: str) -> str:
    """Accept a resource argument without touching it."""
    del path
    return "noop"


def directory_operation_probe(path: str) -> dict[str, str]:
    """Exercise the exact operation set represented by a writable directory."""
    root = Path(path)
    created = root / "created.txt"
    renamed = root / "renamed.txt"
    created.write_text("created")
    with created.open("w") as stream:
        stream.truncate(0)
        stream.write("updated")
    try:
        created.rename(renamed)
    except PermissionError:
        rename = "blocked"
    else:
        rename = "allowed"
        created = renamed
    try:
        root.chmod(0o700)
    except PermissionError:
        metadata = "blocked"
    else:
        metadata = "allowed"
    try:
        with created.open("rb") as stream:
            fcntl.ioctl(stream, 0x80086601, bytearray(8))
    except PermissionError:
        ioctl = "blocked"
    else:
        ioctl = "allowed"
    created.unlink()
    return {"ioctl": ioctl, "metadata": metadata, "rename": rename}


def oversized_result(size: int) -> str:
    """Return more data than the worker protocol permits."""
    return "x" * size


def deeply_nested_result(depth: int) -> object:
    """Return a structurally expensive but byte-small JSON value."""
    value: object = "leaf"
    for _ in range(depth):
        value = [value]
    return value


def slow_probe() -> str:
    """Remain active until the supervisor enforces the wall deadline."""
    while True:
        time.sleep(1)
