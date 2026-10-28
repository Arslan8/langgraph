"""Cancellation preserves ownership until native execution and cleanup finish.

The controlled child below tests the asynchronous handoff and cleanup ordering;
it is not evidence that the child is confined or a container has been removed.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

import pytest

from langgraph.prebuilt.security.capabilities import probe_landlock_abi
from langgraph.prebuilt.security.enforcement import ActivationReceipt, EnforcementMode
from langgraph.prebuilt.security.execution import (
    HostExecutionError,
    HostExecutionResult,
)
from langgraph.prebuilt.security.landlock import LandlockSandboxExecutor
from langgraph.prebuilt.security.linux import LinuxSandboxExecutor, LinuxToolSpec
from langgraph.prebuilt.security.policy import TypedPolicyBackend
from langgraph.prebuilt.security.profile import parse_profiles
from langgraph.prebuilt.security.types import (
    ExecutionOutcome,
    Principal,
    Tool,
    ToolCall,
    ToolDac,
)


async def _wait_event(event: threading.Event) -> None:
    assert await asyncio.to_thread(event.wait, 3), "worker test phase was not reached"


async def _cancel_while_pending(invocation: asyncio.Task) -> None:
    assert invocation.cancel()
    # Deliver cancellation and let shield's completion callback run. A second
    # cancellation must not cancel the task which owns the live thread.
    for _ in range(3):
        await asyncio.sleep(0)
    assert not invocation.done()


def _request():
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")
    tool = Tool("controlled", ToolDac("analyst", {"analyst": "x"}), frozenset(), ())
    return principal, ToolCall(tool, {}, {}, "call", 0)


def _receipt():
    # This fixture is only the result of the controlled worker. No production
    # activation verifier or confinement claim is exercised by these tests.
    return ActivationReceipt(
        "grant",
        "plan",
        "host",
        "context",
        "nonce",
        EnforcementMode.ENFORCED,
        (),
        frozenset(),
        1.0,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "executor_type", [LinuxSandboxExecutor, LandlockSandboxExecutor]
)
async def test_repeated_cancellation_waits_for_child_exit_and_remaining_cleanup(
    monkeypatch, executor_type
):
    executor = object.__new__(executor_type)
    principal, call = _request()
    child_started = threading.Event()
    body_release = threading.Event()
    child_stopped = threading.Event()
    cleanup_release = threading.Event()
    cleanup_finished = threading.Event()
    children = []

    def controlled_worker(actual_principal, actual_call, constraints, *, asynchronous):
        assert (actual_principal, actual_call, constraints, asynchronous) == (
            principal,
            call,
            (),
            True,
        )
        process = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        children.append(process)
        child_started.set()
        try:
            assert body_release.wait(5)
            return HostExecutionResult("complete", _receipt())
        finally:
            process.kill()
            process.wait(timeout=3)
            child_stopped.set()
            try:
                assert cleanup_release.wait(5)
            finally:
                cleanup_finished.set()

    monkeypatch.setattr(executor, "_invoke", controlled_worker)
    invocation = asyncio.create_task(executor.ainvoke(principal, call, ()))
    try:
        await _wait_event(child_started)
        assert children[0].poll() is None
        await _cancel_while_pending(invocation)
        await _cancel_while_pending(invocation)
        assert children[0].poll() is None
        assert not cleanup_finished.is_set()

        body_release.set()
        await _wait_event(child_stopped)
        assert children[0].poll() is not None
        await _cancel_while_pending(invocation)
        await _cancel_while_pending(invocation)
        assert not cleanup_finished.is_set()

        cleanup_release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(asyncio.shield(invocation), 3)
        assert cleanup_finished.is_set()
    finally:
        body_release.set()
        cleanup_release.set()
        await asyncio.gather(invocation, return_exceptions=True)
        await _wait_event(cleanup_finished)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "executor_type", [LinuxSandboxExecutor, LandlockSandboxExecutor]
)
@pytest.mark.parametrize("confirmed", [False, True])
async def test_cancellation_preserves_unconfirmed_termination_error(
    monkeypatch, executor_type, confirmed
):
    executor = object.__new__(executor_type)
    principal, call = _request()
    started = threading.Event()
    release = threading.Event()
    error = HostExecutionError(
        "controlled cleanup outcome",
        _receipt(),
        ExecutionOutcome.INDETERMINATE,
        termination_confirmed=confirmed,
    )

    def controlled_worker(*args, **kwargs):
        started.set()
        assert release.wait(5)
        raise error

    monkeypatch.setattr(executor, "_invoke", controlled_worker)
    invocation = asyncio.create_task(executor.ainvoke(principal, call, ()))
    try:
        await _wait_event(started)
        await _cancel_while_pending(invocation)
        await _cancel_while_pending(invocation)
        release.set()
        if confirmed:
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(asyncio.shield(invocation), 3)
        else:
            with pytest.raises(HostExecutionError) as raised:
                await asyncio.wait_for(asyncio.shield(invocation), 3)
            assert raised.value is error
            assert not raised.value.termination_confirmed
    finally:
        release.set()
        await asyncio.gather(invocation, return_exceptions=True)


@pytest.mark.parametrize("existing_error", [False, True])
def test_landlock_wait_failure_keeps_lifetime_unknown_and_runs_remaining_cleanup(
    monkeypatch, existing_error
):
    executor = object.__new__(LandlockSandboxExecutor)
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    original_kill, original_wait = process.kill, process.wait
    descriptor = os.open(os.devnull, os.O_RDONLY)
    private = tempfile.TemporaryDirectory()
    artifact = tempfile.TemporaryDirectory()
    broker_closed = []

    class StoppedBroker:
        terminated = True

        def close_parent(self):
            broker_closed.append(True)

    def failed_wait(*args, **kwargs):
        raise subprocess.TimeoutExpired("controlled child", 2)

    # Keep an actual child alive while termination observation fails. A waited
    # thread alone must not authorize releasing the caller's flow reservation.
    monkeypatch.setattr(process, "kill", lambda: None)
    monkeypatch.setattr(process, "wait", failed_wait)
    prior = (
        HostExecutionError(
            "prior indeterminate outcome", _receipt(), ExecutionOutcome.INDETERMINATE
        )
        if existing_error
        else None
    )
    try:
        arguments = dict(
            process=process,
            ruleset=None,
            worker_broker_fd=descriptor,
            pidfd=None,
            cgroup=None,
            broker_session=StoppedBroker(),
            private_tmp=private,
            artifact_tmp=artifact,
            receipt=_receipt(),
            active_error=prior,
        )
        if prior is None:
            with pytest.raises(HostExecutionError) as caught:
                executor._cleanup_worker(**arguments)
            failure = caught.value
        else:
            executor._cleanup_worker(**arguments)
            failure = prior
        assert failure.outcome is ExecutionOutcome.INDETERMINATE
        assert not failure.termination_confirmed
        assert process.poll() is None
        assert broker_closed == [True]
        assert all(
            stream.closed for stream in (process.stdin, process.stdout, process.stderr)
        )
        assert not Path(private.name).exists()
        assert not Path(artifact.name).exists()
        with pytest.raises(OSError, match="Bad file descriptor"):
            os.fstat(descriptor)
    finally:
        original_kill()
        original_wait(timeout=3)
        private.cleanup()
        artifact.cleanup()


@pytest.mark.parametrize("unconfirmed", ["broker", "cgroup"])
def test_landlock_other_live_authority_prevents_success(unconfirmed):
    executor = object.__new__(LandlockSandboxExecutor)
    closed = []

    class Broker:
        terminated = unconfirmed != "broker"

        def close_parent(self):
            closed.append("broker")

    class Cgroup:
        def close(self):
            closed.append("cgroup")
            if unconfirmed == "cgroup":
                raise OSError("controlled cgroup remains populated")

    class Directory:
        def cleanup(self):
            closed.append("directory")

    with pytest.raises(HostExecutionError) as caught:
        executor._cleanup_worker(
            process=None,
            ruleset=None,
            worker_broker_fd=None,
            pidfd=None,
            cgroup=Cgroup(),
            broker_session=Broker(),
            private_tmp=Directory(),
            artifact_tmp=Directory(),
            receipt=_receipt(),
            active_error=None,
        )
    assert not caught.value.termination_confirmed
    assert caught.value.outcome is ExecutionOutcome.INDETERMINATE
    assert closed == ["cgroup", "broker", "directory", "directory"]


@pytest.mark.skipif(probe_landlock_abi() < 1, reason="Landlock is unavailable")
@pytest.mark.parametrize("entrypoint", ["fork_probe", "thread_probe"])
def test_direct_landlock_without_cgroup_forbids_descendant_creation(
    monkeypatch, entrypoint
):
    fixture = Path(__file__).with_name("fixtures") / "linux_tools.py"
    profiles = parse_profiles("""
tool controlled {
  owner analyst
  grant analyst: call
  runs linux
  syscalls @minimal
}
principal alice {
  roles analyst
}
""")
    executor = LandlockSandboxExecutor(
        profiles,
        {
            "controlled": LinuxToolSpec(
                f"linux_tools:{entrypoint}",
                fixture,
                hashlib.sha256(fixture.read_bytes()).hexdigest(),
            )
        },
        runtime_roots=(fixture.parent,),
        policy_backend=TypedPolicyBackend(),
    )
    # Exercise the actual production worker and installed filter, with no cgroup
    # available to provide an alternative descendant lifetime guarantee.
    monkeypatch.setattr(executor, "_cgroup_root", None)
    principal, call = _request()
    with pytest.raises(HostExecutionError, match="sandboxed tool failed") as caught:
        executor.invoke(principal, call, ())
    assert len(executor.activation_receipts()) == 1
    assert caught.value.termination_confirmed
    assert caught.value.outcome is ExecutionOutcome.FAILED
