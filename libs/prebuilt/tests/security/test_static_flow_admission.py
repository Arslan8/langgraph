"""Static IFC is an admission requirement, not a report the caller must inspect."""

import pytest
from langchain_core.tools import tool

from langgraph.prebuilt.analysis.static_flow import StaticFlowPolicy
from langgraph.prebuilt.security import (
    HostExecutionDenied,
    SecurityConfigurationError,
    cedar_security,
)
from langgraph.prebuilt.security.inprocess import read_text


@tool("static_reader")
def reader_implementation() -> str:
    """Read through the approved API."""
    return read_text("report.txt")


@tool
async def async_static_reader() -> str:
    """Read through the approved API from an asynchronous body."""
    return read_text("report.txt")


@tool
def unsupported_reader() -> str:
    """An unmodeled operation cannot be statically admitted."""
    return eval("'not admitted'")


def configure(
    candidate=reader_implementation, *, clearance=frozenset({"secret"}), **kwargs
):
    return cedar_security(
        candidate,
        manifest="runs inprocess\nfs read report.txt need",
        policy="permit(principal, action, resource);",
        static_flow=StaticFlowPolicy(
            read_labels={("fs", "report.txt"): {"secret"}},
            input_labels=set(),
            return_clearance=clearance,
        ),
        **kwargs,
    )


@pytest.mark.parametrize("candidate", [reader_implementation, async_static_reader])
@pytest.mark.parametrize(
    "clearance, status", [(set(), "potential_flow"), (None, "unknown")]
)
def test_ifc_rejects_setup_before_tool_or_cedar_execution(
    candidate, clearance, status, tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    assert not (tmp_path / "report.txt").exists()
    with pytest.raises(SecurityConfigurationError, match=f"static_flow:{status}"):
        configure(
            candidate, clearance=clearance, executable="no-cedar-needed-for-admission"
        )
    assert not (tmp_path / "report.txt").exists()


@pytest.mark.parametrize("candidate", [reader_implementation, async_static_reader])
def test_compatible_tool_gets_source_bound_admission(candidate):
    security = configure(candidate)
    admission = security.host_executor.dispatcher.admission
    assert admission.flow_reports[0]["status"] == "compatible"
    assert admission.flow_reports[0]["source_check"]["consistent"]
    admission.validate()


def test_static_admission_does_not_supply_a_runtime_resource_grant(
    tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "report.txt").write_text("secret")
    admission = configure().host_executor.dispatcher.admission
    with pytest.raises(HostExecutionDenied, match="resource_not_granted"):
        admission.invoke({})


def test_admitted_body_cannot_be_swapped_after_the_check(monkeypatch):
    admission = configure().host_executor.dispatcher.admission

    def replacement():
        return "different body"

    monkeypatch.setattr(reader_implementation.func, "__code__", replacement.__code__)
    with pytest.raises(HostExecutionDenied, match="binding_changed"):
        admission.invoke({})


def test_unknown_source_cannot_bypass_static_gate():
    with pytest.raises(
        SecurityConfigurationError, match="manifest_consistency:unknown"
    ):
        configure(unsupported_reader)


def test_policy_snapshots_mutable_classifications():
    labels = {"secret"}
    mapping = {("fs", "report.txt"): labels}
    policy = StaticFlowPolicy(
        read_labels=mapping, input_labels=set(), return_clearance=set()
    )
    labels.clear()
    mapping.clear()
    with pytest.raises(SecurityConfigurationError, match="static_flow:potential_flow"):
        cedar_security(
            reader_implementation,
            manifest="runs inprocess\nfs read report.txt need",
            policy="permit(principal, action, resource);",
            static_flow=policy,
        )


def test_custom_dispatcher_cannot_silently_ignore_ifc():
    with pytest.raises(ValueError, match="requires in-process"):
        configure(dispatcher=object())
