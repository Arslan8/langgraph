"""Native container authorization, pre-import activation and cleanup checks."""

import asyncio
import hashlib
import os
import shutil
import subprocess
from dataclasses import replace
from threading import Event

import pytest
from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from langgraph._internal import _runtime_policy
from langgraph.graph import START, MessagesState, StateGraph
from langgraph.runtime import Runtime

from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    LinuxToolSpec,
    Principal,
    Tool,
    ToolCall,
    ToolDac,
    cedar_security,
    container,
    install_mac_policy,
    with_principal,
)
from langgraph.prebuilt.security.container import DockerObjectDispatcher, _write_frame
from langgraph.prebuilt.security.execution import HostExecutionError

IMAGE = "sha256:3bcfa1622e24814afee022c71236dadd92e31a5fff41ad99a23925bc98311504"
SOURCE = """from pathlib import Path
import os
import time

Path('/tmp/imported').write_text('tool module imported')

def run(path, private, mode="read"):
    if mode == "sleep":
        time.sleep(2)
    result = {"allowed": Path(path).read_text(), "prior": Path('/tmp/prior').exists()}
    if mode == "seed":
        Path('/tmp/prior').write_text('A_PRIVATE')
    try:
        result['private'] = Path(private).read_text()
    except OSError as error:
        result['denied'] = type(error).__name__
    if mode == "fork":
        try:
            os.fork()
        except OSError as error:
            result['fork_errno'] = error.errno
    return result
"""


@tool
def native_tool(path: str, private: str, mode: str = "read") -> dict:
    """Read exact inputs in the isolated native runtime."""
    raise AssertionError("Unconfined callback executed")


@pytest.fixture
def container_runtime(tmp_path):
    if shutil.which("docker") is None:
        pytest.skip("Docker is unavailable")
    probe = subprocess.run(
        ["docker", "image", "inspect", IMAGE], capture_output=True, timeout=10
    )
    if probe.returncode:
        pytest.skip("Pinned integration image is unavailable")
    source = tmp_path / "tool.py"
    source.write_text(SOURCE)
    allowed, private = tmp_path / "allowed", tmp_path / "private"
    allowed.write_text("AUTHORIZED")
    private.write_text("BOB_PRIVATE")
    dispatcher = DockerObjectDispatcher(
        {
            "native_tool": LinuxToolSpec(
                "native_tool:run",
                source,
                hashlib.sha256(source.read_bytes()).hexdigest(),
            )
        },
        image=IMAGE,
        private_roots=[tmp_path],
        wall_timeout_s=0.5,
    )
    principal = Principal("alice", frozenset(), frozenset(), "session")

    def invoke(
        mode="read",
        who=principal,
        policy="permit(principal,action,resource);",
        broad=False,
    ):
        manifest = "runs linux\nfs read @{path} need"
        if broad:
            manifest += "\nfs read @{private} need"
        security = cedar_security(
            native_tool, manifest=manifest, policy=policy, dispatcher=dispatcher
        )
        call = ToolCall(
            Tool("native_tool", ToolDac("owner", {"*": "x"}), frozenset(), ()),
            {"path": str(allowed), "private": str(private), "mode": mode},
            {},
            f"call-{len(dispatcher.execution_records())}",
            0,
        )
        return security.host_executor.invoke(who, call, ())

    try:
        yield dispatcher, invoke, principal
    finally:
        dispatcher.close()


def test_native_dispatch_and_identical_authority_reuse(container_runtime):
    dispatcher, invoke, _ = container_runtime
    first = invoke("seed")
    second = invoke()
    assert first.value == {
        "allowed": "AUTHORIZED",
        "prior": False,
        "denied": "FileNotFoundError",
    }
    assert second.value["prior"] is True
    records = dispatcher.execution_records()
    assert records[0]["container_id"] == records[1]["container_id"]
    assert records[1]["reused"]
    assert first.receipt.grant_digest != second.receipt.grant_digest
    assert first.receipt.nonce != second.receipt.nonce


def test_tool_import_waits_for_activation_release(container_runtime, monkeypatch):
    dispatcher, invoke, _ = container_runtime
    original = container._write_frame
    observed = []

    def inspect_before_release(stream, data, timeout):
        if data == b"GO\n":
            record = dispatcher.execution_records()[-1]
            container_id = record["container_id"]
            assert dispatcher.activation_receipts()
            dispatcher._docker(
                "exec", container_id, "/bin/sh", "-c", "test ! -e /tmp/imported"
            )
            observed.append(container_id)
        original(stream, data, timeout)

    monkeypatch.setattr(container, "_write_frame", inspect_before_release)
    invoke()
    assert len(observed) == 1
    dispatcher._docker("exec", observed[0], "/bin/sh", "-c", "test -f /tmp/imported")


@pytest.mark.parametrize("change", ["principal", "policy", "authority"])
def test_changes_clear_whole_container_state(container_runtime, change):
    dispatcher, invoke, principal = container_runtime
    invoke("seed", broad=change == "authority")
    previous = dispatcher.execution_records()[-1]["container_id"]
    if change == "principal":
        result = invoke(who=replace(principal, user_id="bob"))
    elif change == "policy":
        result = invoke(policy="permit(principal,action,resource) when {true};")
    else:
        result = invoke()
    assert result.value["prior"] is False
    assert "private" not in result.value
    assert dispatcher.execution_records()[-1]["container_id"] != previous
    absent = subprocess.run(
        [
            "docker",
            "ps",
            "-a",
            "--no-trunc",
            "--filter",
            f"id={previous}",
            "--format",
            "{{.ID}}",
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert absent.returncode == 0 and not absent.stdout.strip()


def test_worker_cannot_fork_and_timeout_destroys_container(container_runtime):
    dispatcher, invoke, _ = container_runtime
    assert invoke("fork").value["fork_errno"] == 1
    with pytest.raises(HostExecutionError) as caught:
        invoke("sleep")
    assert caught.value.termination_confirmed
    old = dispatcher.execution_records()[-1]["container_id"]
    assert invoke().value["prior"] is False
    assert dispatcher.execution_records()[-1]["container_id"] != old


def test_backend_exception_does_not_confirm_worker_termination(
    container_runtime, monkeypatch
):
    dispatcher, invoke, _ = container_runtime
    original = dispatcher._runtime.destroy

    def unavailable(name):
        raise RuntimeError("unexpected cleanup failure")

    monkeypatch.setattr(dispatcher._runtime, "destroy", unavailable)
    try:
        with pytest.raises(HostExecutionError) as caught:
            invoke("sleep")
        assert not caught.value.termination_confirmed
        assert "cleanup_unconfirmed" in str(caught.value)
    finally:
        monkeypatch.setattr(dispatcher._runtime, "destroy", original)
        dispatcher._invalidate()


@pytest.mark.parametrize("graph_boundary", [False, True])
@pytest.mark.parametrize("asynchronous", [False, True])
def test_runtime_mac_governs_container_at_execution_boundary(
    container_runtime, monkeypatch, graph_boundary, asynchronous
):
    dispatcher, _, principal = container_runtime
    monkeypatch.delenv("LANGGRAPH_MAC_DIR", raising=False)
    monkeypatch.setattr(_runtime_policy, "_policy", None)
    monkeypatch.setattr(_runtime_policy, "_started", False)
    monkeypatch.setattr(_runtime_policy, "_system_loaded", True)
    install_mac_policy(
        'forbid(principal, action == slangGraph::Action::"fs::read", resource) '
        'when {principal == slangGraph::User::"bob"};'
    )
    security = cedar_security(
        native_tool,
        manifest="runs linux\nfs read @{path} need",
        policy="permit(principal,action,resource);",
        dispatcher=dispatcher,
    )
    node = ToolNode([native_tool], security=security)
    if graph_boundary:
        builder = StateGraph(MessagesState)
        builder.add_node("tools", node)
        builder.add_edge(START, "tools")
        target = builder.compile(security=security)
        options = {}
    else:
        target = node
        options = {"runtime": Runtime()}
    root = dispatcher.private_roots[0]
    request = {
        "messages": [
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "native_tool",
                        "args": {
                            "path": str(root / "allowed"),
                            "private": str(root / "private"),
                        },
                        "id": "runtime-mac",
                    }
                ],
            )
        ]
    }
    for who in (principal, replace(principal, user_id="bob")):
        config = with_principal({}, who, modules=security.modules)
        result = (
            asyncio.run(target.ainvoke(request, config=config, **options))
            if asynchronous
            else target.invoke(request, config=config, **options)
        )
        message = result["messages"][-1]
        if who.user_id == "alice":
            assert message.status == "success"
            assert "AUTHORIZED" in message.content
        else:
            assert message.status == "error"
            assert "mac:forbid:" in message.content
    assert len(dispatcher.execution_records()) == 1
    with pytest.raises(RuntimeError, match="already installed"):
        install_mac_policy("forbid(principal, action, resource) when {false};")


def test_request_write_has_deadline_when_worker_never_reads():
    read_fd, write_fd = os.pipe()
    try:
        with os.fdopen(write_fd, "wb", buffering=0) as stream:
            with pytest.raises(TimeoutError):
                _write_frame(stream, b"x" * 1_048_576, 0.02)
            assert os.get_blocking(stream.fileno())
    finally:
        os.close(read_fd)


@pytest.mark.asyncio
async def test_repeated_cancellation_waits_for_cleanup(container_runtime, monkeypatch):

    dispatcher, invoke, principal = container_runtime
    root = dispatcher.private_roots[0]
    security = cedar_security(
        native_tool,
        manifest="runs linux\nfs read @{path} need",
        policy="permit(principal,action,resource);",
        dispatcher=dispatcher,
    )
    call = ToolCall(
        Tool("native_tool", ToolDac("owner", {"*": "x"}), frozenset(), ()),
        {
            "path": str(root / "allowed"),
            "private": str(root / "private"),
            "mode": "sleep",
        },
        {},
        "cancel",
        0,
    )
    cleanup_started, allow_cleanup = Event(), Event()
    original = dispatcher._invalidate

    def held_cleanup():
        cleanup_started.set()
        assert allow_cleanup.wait(5)
        original()

    monkeypatch.setattr(dispatcher, "_invalidate", held_cleanup)
    task = asyncio.create_task(security.host_executor.ainvoke(principal, call, ()))
    async with asyncio.timeout(15):
        while not dispatcher.execution_records():
            await asyncio.sleep(0.02)
        old = dispatcher.execution_records()[-1]["container_id"]
        task.cancel()
        while not cleanup_started.is_set():
            await asyncio.sleep(0.01)
        task.cancel()
        await asyncio.sleep(0.02)
        assert not task.done()
        allow_cleanup.set()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert invoke().value["allowed"] == "AUTHORIZED"
    assert dispatcher.execution_records()[-1]["container_id"] != old
