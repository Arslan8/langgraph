"""Tool entry points for `ResourceBoundary` Linux integration tests.

These functions know nothing about the policy. Each reports the operating
system's answer to an attempted operation so tests can assert kernel enforcement.
"""

from __future__ import annotations

import errno
import os
from pathlib import Path


def _attempt(operation) -> str:
    try:
        operation()
    except OSError as exc:
        return f"blocked:{errno.errorcode.get(exc.errno or 0, 'unknown')}"
    return "ok"


def read_source(path: str) -> str:
    """Read one source file."""
    return Path(path).read_text()


def annotate_pathlib(path: str) -> dict[str, str]:
    """Read a file, then try to append to it using `pathlib`."""
    content = Path(path).read_text()

    def append() -> None:
        with Path(path).open("a") as handle:
            handle.write("# annotated\n")

    return {"content": content, "write": _attempt(append)}


def annotate_descriptor(file: str) -> dict[str, str]:
    """Read a file, then try to append to it using raw descriptors."""
    descriptor = os.open(file, os.O_RDONLY)
    try:
        content = os.read(descriptor, 65536).decode()
    finally:
        os.close(descriptor)

    def append() -> None:
        handle = os.open(file, os.O_WRONLY | os.O_APPEND)
        try:
            os.write(handle, b"# annotated\n")
        finally:
            os.close(handle)

    return {"content": content, "write": _attempt(append)}


def build_artifacts(directory: str) -> dict[str, str]:
    """Exercise create, write, truncate, read, and delete in one directory."""
    root = Path(directory)
    kept = root / "report.txt"
    scratch = root / "scratch.txt"
    results = {
        "create": _attempt(lambda: kept.write_text("draft report")),
        "truncate": _attempt(lambda: os.truncate(kept, 5)),
        "write": _attempt(lambda: scratch.write_text("temporary")),
    }
    results["read"] = kept.read_text() if kept.exists() else "missing"
    results["delete"] = _attempt(scratch.unlink)
    return results


def probe_read(path: str, target: str) -> str:
    """Ignore the declared path and attempt to read another file."""
    del path
    try:
        return "read:" + Path(target).read_text()
    except OSError as exc:
        return f"blocked:{errno.errorcode.get(exc.errno or 0, 'unknown')}"


def mark_executed(path: str) -> str:
    """Return a marker that proves tool code ran."""
    del path
    return "tool-code-ran"
