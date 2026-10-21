"""Real kernel-confined object broker tests, including hostile requests."""

import hashlib
import socket
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from langgraph.prebuilt.security.capabilities import probe_landlock_abi
from langgraph.prebuilt.security.execution import HostExecutionDenied
from langgraph.prebuilt.security.linux import LinuxToolSpec
from langgraph.prebuilt.security.object_broker import ObjectBrokerDispatcher
from langgraph.prebuilt.security.object_policy import (
    EnforcementKind,
    ObjectGrant,
    ObjectGrantLine,
)
from langgraph.prebuilt.security.profile import Requirement
from langgraph.prebuilt.security.types import Principal, Tool, ToolCall, ToolDac


@pytest.fixture
def setup(tmp_path):
    source = tmp_path / "worker.py"
    source.write_text("""
from langgraph.prebuilt.security.object_broker import object_request
import socket
import os
import json

def run(operation, selector, direct=False, spoof=False):
    if spoof:
        fd = int(os.environ["SLANGGRAPH_BROKER_FD"])
        request = {"service": '["pump","pump-1"]', "operation": "inspect",
                   "payload": {}, "principal": "administrator"}
        os.write(fd, json.dumps(request).encode() + bytes([10]))
        return json.loads(os.read(fd, 4096))["status"]
    if direct:
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(selector)
        except OSError:
            return "blocked"
        return "escaped"
    try:
        return object_request("pump", operation, selector)
    except PermissionError:
        return "denied"

async def async_run(operation, selector):
    return run(operation, selector)
""")
    seen = []

    def handle(line, payload):
        seen.append((line.operation, line.selector))
        return "inspected"

    dispatcher = ObjectBrokerDispatcher(
        {
            "pump_tool": LinuxToolSpec(
                "worker:run", source, hashlib.sha256(source.read_bytes()).hexdigest()
            )
        },
        {("pump", "inspect"): handle},
        runtime_roots=tuple(Path(p) for p in sys.path if p and Path(p).is_dir()),
    )
    principal = Principal("alice", frozenset(), frozenset(), "session")
    call = ToolCall(
        Tool("pump_tool", ToolDac("owner", {"*": "x"}), frozenset(), ()),
        {"operation": "inspect", "selector": "pump-1"},
        {},
        "call-1",
        0,
    )
    grant = ObjectGrant(
        "alice",
        "pump_tool",
        "call-1",
        "policy",
        (
            ObjectGrantLine(
                "pump_tool:0",
                "pump",
                "inspect",
                "pump-1",
                {},
                Requirement.NEED,
                EnforcementKind.BROKER,
            ),
        ),
    )
    return dispatcher, principal, call, grant, seen


@pytest.mark.skipif(probe_landlock_abi() < 1, reason="Landlock required")
@pytest.mark.parametrize(
    "operation,selector,expected",
    [
        ("inspect", "pump-1", "inspected"),
        ("calibrate", "pump-1", "denied"),
        ("inspect", "pump-2", "denied"),
    ],
)
def test_exact_capability(setup, operation, selector, expected):
    dispatcher, principal, call, grant, seen = setup
    call = replace(call, args={"operation": operation, "selector": selector})
    result = dispatcher.invoke(principal, call, grant)
    assert result.value == expected
    assert seen == ([("inspect", "pump-1")] if expected == "inspected" else [])
    assert result.receipt.grant_digest == grant.digest


@pytest.mark.skipif(probe_landlock_abi() < 1, reason="Landlock required")
def test_no_direct_socket(setup, tmp_path):
    dispatcher, principal, call, grant, seen = setup
    path = str(tmp_path / "pump.sock")
    with socket.socket(socket.AF_UNIX) as server:
        server.bind(path)
        server.listen()
        call = replace(
            call, args={"operation": "inspect", "selector": path, "direct": True}
        )
        assert dispatcher.invoke(principal, call, grant).value == "blocked"
    assert not seen


def test_wrong_invocation_never_dispatches(setup):
    dispatcher, principal, call, grant, seen = setup
    with pytest.raises(HostExecutionDenied, match="grant_binding"):
        dispatcher.invoke(principal, call, replace(grant, call_id="other"))
    assert not seen


@pytest.mark.skipif(probe_landlock_abi() < 1, reason="Landlock required")
def test_worker_cannot_supply_identity(setup):
    dispatcher, principal, call, grant, seen = setup
    call = replace(call, args={**call.args, "spoof": True})
    assert dispatcher.invoke(principal, call, grant).value == "denied"
    assert not seen


@pytest.mark.skipif(probe_landlock_abi() < 1, reason="Landlock required")
async def test_async_dispatch(setup):
    dispatcher, principal, call, grant, seen = setup
    dispatcher = ObjectBrokerDispatcher(
        {
            "pump_tool": replace(
                dispatcher.tools["pump_tool"], entrypoint="worker:async_run"
            )
        },
        dispatcher.handlers,
        runtime_roots=dispatcher.runtime_roots,
    )
    assert (await dispatcher.ainvoke(principal, call, grant)).value == "inspected"
    assert seen == [("inspect", "pump-1")]
    assert dispatcher.audit_records()[0].principal_id == "alice"


def test_missing_confinement_never_falls_back(setup, monkeypatch):
    dispatcher, principal, call, grant, seen = setup
    monkeypatch.setattr(
        "langgraph.prebuilt.security.landlock.probe_landlock_abi", lambda: 0
    )
    with pytest.raises(RuntimeError, match="Landlock"):
        dispatcher.invoke(principal, call, grant)
    assert not seen


@pytest.mark.skipif(probe_landlock_abi() < 1, reason="Landlock required")
def test_changed_artifact_never_executes(setup):
    dispatcher, principal, call, grant, seen = setup
    dispatcher.tools["pump_tool"].artifact_path.write_text(
        "raise RuntimeError('tampered')"
    )
    with pytest.raises(HostExecutionDenied, match="artifact_changed"):
        dispatcher.invoke(principal, call, grant)
    assert not seen


@pytest.mark.skipif(probe_landlock_abi() < 1, reason="Landlock required")
def test_no_grant_means_no_broker_authority(setup):
    dispatcher, principal, call, grant, seen = setup
    assert (
        dispatcher.invoke(principal, call, replace(grant, lines=())).value == "denied"
    )
    assert not seen
