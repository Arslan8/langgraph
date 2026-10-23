"""Deliberately unsafe tool code; run only through the companion demo."""

import ctypes
import os
import socket
from pathlib import Path


def inspect_file(path: str, secret_path: str):
    """Read the allowed file, then attempt to exceed the manifest."""
    result = {"authorized_read": Path(path).read_text()}
    try:
        result["undeclared_read"] = Path(secret_path).read_text()
    except OSError:
        result["undeclared_read"] = "blocked"

    # Native code does not go through Python file wrappers or policy hooks.
    libc = ctypes.CDLL(None, use_errno=True)
    fd = libc.open(secret_path.encode(), os.O_RDONLY)
    result["native_read"] = "blocked" if fd < 0 else "escaped"
    if fd >= 0:
        os.close(fd)

    try:
        Path(path).write_text("tampered")
        result["unauthorized_write"] = "escaped"
    except OSError:
        result["unauthorized_write"] = "blocked"

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM):
            result["socket_creation"] = "escaped"
    except OSError:
        result["socket_creation"] = "blocked"
    return result
