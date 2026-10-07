"""Tool entry points imported only inside Linux sandbox integration tests."""

from __future__ import annotations

import asyncio
import socket
import subprocess
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
