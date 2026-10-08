"""Check discovery and conformance accounting using pure local fixtures."""

import asyncio
from unittest.mock import Mock

import pytest

from langgraph.prebuilt.security import tool_api_verifier as verifier
from langgraph.prebuilt.security.binding import principal_from
from langgraph.prebuilt.security.execution import HostExecutionDenied
from langgraph.prebuilt.security.guarded import _GuardedExecutor
from langgraph.prebuilt.security.types import ToolCall
from langgraph.prebuilt.tool_node import ToolCallRequest


def test_unknown_inherited_entrypoint_is_not_silently_ignored() -> None:
    class Parent:
        def future_execute(self, value):
            return value

    class Child(Parent):
        def invoke(self, value):
            return value

    entries = {item["name"]: item for item in verifier.inventory(Child)}
    assert entries["future_execute"]["classification"] == "unclassified"
    assert entries["invoke"]["classification"] == "execution"
    assert entries["future_execute"]["source_sha256"]


@pytest.mark.parametrize("mode", verifier._MODES)
@pytest.mark.parametrize("family", verifier._FAMILIES)
@pytest.mark.parametrize("backend", ["in_process", "host"])
@pytest.mark.parametrize("api", ["invoke", "ainvoke", "batch", "abatch"])
def test_real_entrypoints_match_each_authorization(family, api, mode, backend) -> None:
    result = asyncio.run(verifier._case(family, "identity", api, mode, "v2", backend))
    assert result["status"] == "passed", result
    expected = (2 if "batch" in api else 1) if mode == "allow" else 0
    assert result["execution_count"] == expected
    assert not result["unused_authorizations"]
    if backend == "host":
        assert result["host_dispatch_count"] == expected
        assert result["local_dispatch_count"] == 0


def test_body_counter_detects_missing_fresh_authorization() -> None:
    policy = verifier._ProbePolicy("allow")
    policy.execute("fixture-A")
    assert policy.errors == ["execution lacked matching fresh authorization"]


def test_full_inventory_gate_includes_every_reported_failure() -> None:
    report = asyncio.run(verifier.verify_tool_apis())
    assert len(report["surfaces"]) >= 68
    assert len(report["cases"]) >= 4752
    assert report["complete"], report["summary"]
    assert report["complete"] == all(
        [
            report["inventory_complete"],
            report["conformance_passed"],
            report["source_claims_passed"],
            report["source_evidence_ready"],
            not report["background_errors"],
        ]
    )
    assert report["conformance_passed"] == all(
        case["status"] == "passed" for case in report["cases"]
    )
    for surface in report["surfaces"]:
        exercised = {
            case["api"]
            for case in report["cases"]
            if case["family"] == surface["family"]
            and case["factory"] == surface["factory"]
        }
        assert exercised == set(surface["exercised_apis"])
        for api in exercised:
            backends = {
                case["backend"]
                for case in report["cases"]
                if case["family"] == surface["family"]
                and case["factory"] == surface["factory"]
                and case["api"] == api
            }
            assert backends == set(verifier._BACKENDS)


@pytest.mark.parametrize("family", verifier._FAMILIES)
@pytest.mark.parametrize("api", ["invoke", "ainvoke", "astream_events"])
def test_host_activation_denial_never_falls_back(family, api) -> None:
    result = asyncio.run(
        verifier._case(family, "identity", api, "allow", "v2", "host_denied")
    )
    assert result["status"] == "passed", result
    assert result["host_dispatch_count"] == 1
    assert result["local_dispatch_count"] == result["execution_count"] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("family", verifier._FAMILIES)
@pytest.mark.parametrize("asynchronous", [False, True])
async def test_host_mode_disables_private_local_dispatch_methods(family, asynchronous):
    """Local-only entry points enforce their own mode precondition."""
    fixture = verifier._Fixture(family, "allow", "host")
    principal = principal_from(fixture.config)
    args = {"value": "fixture-A"}
    try:
        with pytest.raises(HostExecutionDenied, match="in_process_execution_disabled"):
            if family.startswith("guarded"):
                executor = next(
                    cell.cell_contents
                    for cell in fixture.base.func.__closure__
                    if isinstance(cell.cell_contents, _GuardedExecutor)
                )
                call = ToolCall(executor.tool, args, {}, "call", 0)
                if asynchronous:
                    await executor._ainvoke_in_process(principal, call, fixture.config)
                else:
                    executor._invoke_in_process(principal, call, fixture.config)
            else:
                node = fixture.base
                call = ToolCall(
                    node._security_tools_by_name["probe"], args, {}, "call", 0
                )
                request = ToolCallRequest(
                    tool_call={"name": "probe", "args": args, "id": "call"},
                    tool=node.tools_by_name["probe"],
                    state={},
                    runtime=Mock(),
                    principal=principal,
                )
                if asynchronous:
                    await node._invoke_secured_tool_async(
                        principal, call, request, fixture.config
                    )
                else:
                    node._invoke_secured_tool_sync(
                        principal, call, request, fixture.config
                    )
        assert fixture.policy.executions == 0
        assert fixture.policy.host_attempts == 0
    finally:
        fixture.close()
