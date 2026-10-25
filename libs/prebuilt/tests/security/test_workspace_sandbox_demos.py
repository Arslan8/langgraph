"""Execute the unsafe-tool and custom-resource workspace demos end to end."""

import ast
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from langgraph.prebuilt.security.capabilities import probe_landlock_abi

sandbox_requirements = [
    pytest.mark.skipif(probe_landlock_abi() < 5, reason="Landlock ABI 5 required"),
    pytest.mark.skipif(shutil.which("cedar") is None, reason="Cedar CLI required"),
]


@pytest.mark.parametrize(
    "filename,markers",
    [
        pytest.param(
            "09_no_internet/demo.py",
            (
                "Required internet: denied by MAC before dispatch",
                "Optional internet: removed by MAC; only fs::read remains",
                "ipv4_tcp: blocked",
                "ipv6_udp: blocked",
            ),
            marks=sandbox_requirements,
        ),
        pytest.param(
            "07_manifest_verification/bypasses.py",
            (
                "Direct library bypass: REJECTED at admission; tool body never runs",
                "Reflection bypass: REJECTED at admission; tool body never runs",
            ),
        ),
        pytest.param(
            "08_custom_mediator/demo.py",
            (
                "Mediator rule: add only 1, 2, or 3",
                "ALLOW: increment(2) -> counter = 2",
                "DENY: increment(-1) -> counter remains 2",
                "Counter is still 2: the mediator rejected the invalid amount.",
            ),
            marks=sandbox_requirements,
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


@pytest.mark.parametrize(
    "read_file,fix_manifest,expected",
    [(False, False, 0), (True, False, 1), (True, True, 0)],
)
def test_static_manifest_demo(tmp_path, read_file, fix_manifest, expected):
    repository = Path(__file__).resolve().parents[4]
    source = (repository / "workspace/07_manifest_verification/demo.py").read_text()
    # Normalize the teaching function in the copy: users edit this demo in class.
    entry = next(
        node
        for node in ast.parse(source).body
        if isinstance(node, ast.FunctionDef) and node.name == "read_report"
    )
    returned = next(node for node in entry.body if isinstance(node, ast.Return))
    lines = source.splitlines(keepends=True)
    lines[returned.lineno - 1 : returned.end_lineno] = [
        "    return read_text(path)\n" if read_file else '    return "nothing"\n'
    ]
    source = "".join(lines)
    if fix_manifest:
        source = source.replace("fs read /tmp/other-report.txt", "fs read @{path}")
    demo = tmp_path / "demo.py"
    demo.write_text(source)
    completed = subprocess.run(
        [sys.executable, str(demo)], capture_output=True, text=True, timeout=30
    )
    assert completed.returncode == expected, completed.stderr
    assert completed.stdout == ""
    if expected == 0:
        assert completed.stderr == ""
    else:
        assert (
            "SecurityConfigurationError: manifest_consistency:mismatch:read_report"
            in completed.stderr
        )
        assert (
            "inferred fs::read on @{path} is not permitted by the manifest"
            in completed.stderr
        )
        assert "Failed subset check: inferred ⊆ manifest" in completed.stderr
        assert "\x1b[" not in completed.stderr
