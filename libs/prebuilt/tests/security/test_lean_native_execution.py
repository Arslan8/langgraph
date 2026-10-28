"""Opt-in selected Lean route with real bubblewrap, seccomp, and cleanup.

No activation, confinement, receipt, lifecycle decision, or termination function
is mocked. These finite native observations do not prove Python/OS refinement.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from langgraph.prebuilt.security import Effect, Principal, ResourceArg, ToolCall
from langgraph.prebuilt.security.enforcement import EnforcementMode
from langgraph.prebuilt.security.execution import HostExecutionError
from langgraph.prebuilt.security.lean_lifecycle import LeanLifecycleChecker
from langgraph.prebuilt.security.linux import LinuxSandboxExecutor, LinuxToolSpec
from langgraph.prebuilt.security.policy import TypedPolicyBackend
from langgraph.prebuilt.security.profile import parse_profiles
from langgraph.prebuilt.security.types import ExecutionOutcome, Tool, ToolDac
from tests.security.test_linux_execution import _FIXTURES, _profile

pytestmark = pytest.mark.skipif(
    os.environ.get("LANGGRAPH_REQUIRE_LEAN_NATIVE") != "1",
    reason="set LANGGRAPH_REQUIRE_LEAN_NATIVE=1 on a host supporting bubblewrap",
)


@pytest.fixture(scope="module")
def checker():
    default = (
        Path(__file__).resolve().parents[4]
        / "proofs/worker-route/.lake/build/bin/workerRoute"
    )
    binary = Path(
        os.environ.get("LANGGRAPH_LEAN_WORKER_BINARY", str(default))
    ).resolve()
    if not binary.is_file():
        pytest.fail("requested native Lean route requires the compiled executable")
    return LeanLifecycleChecker(
        str(binary), hashlib.sha256(binary.read_bytes()).hexdigest()
    )


def _executor(checker, profile, entrypoint):
    artifact = _FIXTURES / "linux_tools.py"
    return LinuxSandboxExecutor(
        parse_profiles(profile, source="lean-native-test.slp"),
        {
            "read_file": LinuxToolSpec(
                entrypoint, artifact, hashlib.sha256(artifact.read_bytes()).hexdigest()
            )
        },
        runtime_roots=(_FIXTURES,),
        policy_backend=TypedPolicyBackend(),
        lifecycle_checker=checker,
    )


def _request(args, *, filesystem):
    resources = (ResourceArg("path", "path", "realpath"),) if filesystem else ()
    target = Tool(
        "read_file",
        ToolDac("analyst", {"analyst": "x", "*": "-"}),
        frozenset({Effect.READ}) if filesystem else frozenset(),
        resources,
    )
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "lean-native")
    resolved = {"path": args["path"]} if filesystem else {}
    return principal, ToolCall(target, args, resolved, "native-call", 0)


def _evidence(case, checker, receipt, *, outcome, termination_confirmed):
    assert receipt.mode is EnforcementMode.ENFORCED
    assert receipt.evidence
    assert all(item.adapter_id == "linux-bubblewrap-v1" for item in receipt.evidence)
    print(
        json.dumps(
            {
                "case": case,
                "binary_sha256": checker.binary_sha256,
                "route": "LinuxSandboxExecutor with LeanLifecycleChecker",
                "activation_mode": receipt.mode.value,
                "artifact_digest": receipt.artifact_digest,
                "grant_digest": receipt.grant_digest,
                "plan_digest": receipt.plan_digest,
                "context_digest": receipt.context_digest,
                "adapter_ids": [item.adapter_id for item in receipt.evidence],
                "activated_obligations": sorted(receipt.activated_obligations),
                "outcome": outcome,
                "termination_confirmed": termination_confirmed,
            },
            sort_keys=True,
        )
    )


def test_selected_native_route_reads_granted_file(checker, tmp_path):
    allowed = tmp_path / "allowed.txt"
    allowed.write_text("lean-native-useful-result")
    executor = _executor(checker, _profile(tmp_path), "linux_tools:read_file")
    principal, call = _request({"path": str(allowed)}, filesystem=True)
    result = executor.invoke(principal, call, ())
    assert result.value == "lean-native-useful-result"
    assert executor.activation_receipts() == (result.receipt,)
    assert executor.unresolved_terminations() == ()
    _evidence(
        "useful-file-read",
        checker,
        result.receipt,
        outcome="success",
        termination_confirmed=True,
    )


@pytest.mark.parametrize("attack", ["undeclared-file", "fork"])
def test_selected_native_route_denies_hostile_effect(checker, tmp_path, attack):
    allowed = tmp_path / "allowed.txt"
    allowed.write_text("granted")
    forbidden = tmp_path / "forbidden.txt"
    forbidden.write_text("must-not-cross-worker-boundary")
    if attack == "undeclared-file":
        executor = _executor(checker, _profile(tmp_path), "linux_tools:hostile_probe")
        principal, call = _request(
            {"path": str(allowed), "forbidden_path": str(forbidden)}, filesystem=True
        )
        expected_error = "FileNotFoundError"
    else:
        profile = """
tool read_file {
  owner analyst
  grant analyst: call
  runs linux
  syscalls @minimal
}
principal alice {
  roles analyst
}
"""
        executor = _executor(checker, profile, "linux_tools:fork_probe")
        principal, call = _request({}, filesystem=False)
        expected_error = "PermissionError"
    with pytest.raises(HostExecutionError, match=expected_error) as caught:
        executor.invoke(principal, call, ())
    failure = caught.value
    assert failure.outcome is ExecutionOutcome.FAILED
    assert failure.termination_confirmed is True
    assert failure.recovery is None
    assert "must-not-cross-worker-boundary" not in str(failure)
    assert executor.activation_receipts() == (failure.receipt,)
    assert executor.unresolved_terminations() == ()
    _evidence(
        attack,
        checker,
        failure.receipt,
        outcome=f"failed:{expected_error}",
        termination_confirmed=failure.termination_confirmed,
    )
