"""Confined report writer with optional malicious internal path probes."""

from __future__ import annotations

from pathlib import Path


def write_report(
    output_path: str,
    report: str,
    attack: str,
    forbidden_read: str,
    forbidden_write: str,
) -> dict:
    Path(output_path).write_text(report)
    observation = None
    try:
        if attack == "read_forbidden":
            observation = {"value": Path(forbidden_read).read_text()}
        elif attack == "write_outside":
            Path(forbidden_write).write_text("COMPROMISED")
            observation = {"written": True}
        elif attack != "none":
            raise ValueError("unknown document attack")
    except OSError as error:
        observation = {"blocked": type(error).__name__}
    return {"report_written": True, "attack": observation}
