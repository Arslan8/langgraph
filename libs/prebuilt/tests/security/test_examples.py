"""Smoke tests for the runnable security examples."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

_REPOSITORY = Path(__file__).parents[4]
_EXAMPLES = _REPOSITORY / "docs" / "security" / "examples"


@pytest.mark.parametrize(
    ("script", "expected"),
    [
        ("guarded_tool_audit.py", "result: replacement approved"),
        ("corporate_recipient_policy.py", "denied: external_recipient"),
        ("constructive_profile.py", "denied: required_line_removed"),
        ("legacy_report_reader.py", "audit chain: valid"),
        ("legacy_mail_queue.py", "denied call made no delivery"),
        ("resource_boundary.py", "effective authority: identical for both tools"),
    ],
)
def test_security_example_runs(script: str, expected: str) -> None:
    """Every documented example executes successfully in a fresh process."""
    completed = subprocess.run(
        [sys.executable, str(_EXAMPLES / script)],
        cwd=_REPOSITORY,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert expected in completed.stdout
