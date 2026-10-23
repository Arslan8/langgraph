"""Execute the unsafe-tool and custom-resource workspace demos end to end."""

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from langgraph.prebuilt.security.capabilities import probe_landlock_abi

pytestmark = [
    pytest.mark.skipif(probe_landlock_abi() < 5, reason="Landlock ABI 5 required"),
    pytest.mark.skipif(shutil.which("cedar") is None, reason="Cedar CLI required"),
]


@pytest.mark.parametrize(
    "filename,markers",
    [
        (
            "07_unsafe_tools_demo.py",
            (
                "authorized_read: public report",
                "undeclared_read: blocked",
                "native_read: blocked",
                "unauthorized_write: blocked",
                "socket_creation: blocked",
                "Verified: both fixture files are unchanged.",
            ),
        ),
        (
            "08_resource_adapters_demo.py",
            (
                "invalid_amount: denied",
                "payload_override: denied",
                "optional_resource: denied",
                "direct_access: blocked",
                "Lifecycle: activate:alice -> invoke:inspect -> invoke:increment -> release",
                "Optional unsupported resource: removed before dispatch",
                "Missing required mediator: DENIED before worker execution",
            ),
        ),
    ],
)
def test_workspace_demo(filename, markers):
    repository = Path(__file__).resolve().parents[4]
    completed = subprocess.run(
        [sys.executable, str(repository / "workspace" / filename)],
        cwd=repository,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    for marker in markers:
        assert marker in completed.stdout
