from __future__ import annotations

import io
import json
from pathlib import Path
from types import SimpleNamespace

from langgraph.prebuilt.security.exec_cli import main
from langgraph.prebuilt.security.execution import HostExecutionResult


class _Input:
    def __init__(self, value: bytes) -> None:
        self.buffer = io.BytesIO(value)


def test_slanggraph_exec_builds_profile_bound_call(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    profile = tmp_path / "profile.slp"
    profile.write_text(
        """
tool hello {
  owner analyst
  grant analyst: call
  runs linux
  syscalls @minimal
}
principal alice {
  roles analyst
}
"""
    )
    artifact = tmp_path / "tool.py"
    artifact.write_text("def hello(name): return 'hello ' + name\n")
    captured = {}

    class FakeExecutor:
        def __init__(self, profiles, tools, *, runtime_roots):
            captured["tools"] = tools
            captured["roots"] = runtime_roots

        def invoke(self, principal, call, constraints):
            captured["principal"] = principal
            captured["call"] = call
            receipt = SimpleNamespace(grant_digest="grant-hash", rule_enforcement=())
            return HostExecutionResult("hello Ada", receipt)

    monkeypatch.setattr(
        "langgraph.prebuilt.security.exec_cli.LandlockSandboxExecutor",
        FakeExecutor,
    )
    monkeypatch.setattr(
        "sys.stdin",
        _Input(
            json.dumps(
                {
                    "args": {"name": "Ada"},
                    "normalized": {"name": "Ada"},
                    "call_id": "call-1",
                }
            ).encode()
            + b"\n"
        ),
    )

    status = main(
        [
            "--profiles",
            str(profile),
            "--tool",
            "hello",
            "--entrypoint",
            "tool:hello",
            "--artifact",
            str(artifact),
            "--runtime-root",
            str(tmp_path),
            "--principal",
            "alice",
            "--session",
            "session-1",
        ]
    )

    assert status == 0
    assert captured["principal"].user_id == "alice"
    assert captured["call"].args == {"name": "Ada"}
    assert json.loads(capsys.readouterr().out) == {
        "grant_hash": "grant-hash",
        "mechanisms": [],
        "result": "hello Ada",
        "status": "ok",
    }
