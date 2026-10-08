from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

from langgraph.prebuilt.security import (
    Principal,
    Tool,
    ToolCall,
    ToolDac,
    TypedPolicyBackend,
    WasiSandboxExecutor,
    WasiToolSpec,
    parse_profiles,
)
from langgraph.prebuilt.security.execution import HostExecutionDenied


def _fake_wasmtime(tmp_path: Path) -> Path:
    runtime = tmp_path / "wasmtime"
    runtime.write_text(
        f"#!{sys.executable}\n"
        "import json,sys\n"
        "request=json.loads(sys.stdin.readline())\n"
        "print(json.dumps({'echo': request['args']}))\n"
    )
    runtime.chmod(0o755)
    return runtime


def _module(tmp_path: Path) -> Path:
    module = tmp_path / "tool.wasm"
    module.write_bytes(b"\\0asm\\x01\\0\\0\\0")
    return module


def _call() -> tuple[Principal, ToolCall]:
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")
    tool = Tool("pure", ToolDac("analyst", {"analyst": "x"}), frozenset(), ())
    return principal, ToolCall(tool, {"value": 7}, {"value": 7}, "call-1", 0)


@pytest.mark.parametrize("asynchronous", [False, True])
async def test_wasi_backend_runs_pure_module_with_no_preopens(
    tmp_path: Path, asynchronous: bool
) -> None:
    module = _module(tmp_path)
    profiles = parse_profiles(
        """
tool pure {
  owner analyst
  grant analyst: call
  runs wasi
  syscalls @minimal
}
principal alice {
  roles analyst
}
"""
    )
    executor = WasiSandboxExecutor(
        profiles,
        {"pure": WasiToolSpec(module, hashlib.sha256(module.read_bytes()).hexdigest())},
        policy_backend=TypedPolicyBackend(),
        wasmtime_path=_fake_wasmtime(tmp_path),
    )
    principal, call = _call()

    result = (
        await executor.ainvoke(principal, call, ())
        if asynchronous
        else executor.invoke(principal, call, ())
    )

    assert result.value == {"echo": {"value": 7}}
    assert {item.mechanism for item in result.receipt.rule_enforcement} == {
        "wasi:no-host-syscalls"
    }


def test_wasi_backend_denies_unrepresentable_filesystem_grant(tmp_path: Path) -> None:
    module = _module(tmp_path)
    profiles = parse_profiles(
        f"""
tool pure {{
  owner analyst
  grant analyst: call
  runs wasi
  syscalls @minimal
  fs read {tmp_path}/** need
}}
principal alice {{
  roles analyst
  fs read {tmp_path}/**
}}
"""
    )
    executor = WasiSandboxExecutor(
        profiles,
        {"pure": WasiToolSpec(module, hashlib.sha256(module.read_bytes()).hexdigest())},
        policy_backend=TypedPolicyBackend(),
        wasmtime_path=_fake_wasmtime(tmp_path),
    )
    principal, call = _call()

    with pytest.raises(HostExecutionDenied, match="unsupported_rule"):
        executor.invoke(principal, call, ())
