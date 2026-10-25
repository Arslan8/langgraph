from unittest.mock import Mock

import pytest
from langchain_core.messages import AIMessage
from langchain_core.tools import tool

from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    Decision,
    Principal,
    SecurityConfig,
    SecurityDeniedError,
    SecurityModule,
    Verdict,
    dac,
    guarded_tool,
    with_principal,
)
from langgraph.prebuilt.security.modules.analysis_gate import AnalysisGate
from tests.analysis.test_runtime_access import setup_runtime


class DepartmentPolicy(AnalysisGate):
    name = "department"

    def tool_call_permission(self, principal, call):
        base = super().tool_call_permission(principal, call)
        if base.verdict is not Verdict.ALLOW:
            return base
        snapshot = self.snapshot(principal, call)
        if any(
            "example.department.restricted" in value.risks for value in snapshot.flow
        ):
            return Decision(Verdict.DENY, "department:restricted")
        return base


class Deny(SecurityModule):
    name = "deny"

    def tool_call_permission(self, principal, call):
        return Decision(Verdict.DENY, "other:deny")


def principal_config():
    principal = Principal("owner", frozenset({"user"}), frozenset(), "session")
    return with_principal(
        {
            "configurable": {
                "__pregel_runtime": Mock(
                    store=None, context=None, stream_writer=lambda _: None
                )
            }
        },
        principal,
    )


@pytest.mark.parametrize("direct", [False, True])
def test_effects_gate_later_finding_fixed_policy_and_denial(direct):
    runtime, adapter, client, _ = setup_runtime()
    gate = DepartmentPolicy(runtime.config.policy_version)
    security = SecurityConfig(modules=(gate,), analysis=runtime)
    effects = []

    @tool
    @dac(owner="user", grants={"user": "x"})
    def record_analysis_test(message: str) -> str:
        """Record a harmless test message."""
        effects.append(message)
        return message

    target = (
        guarded_tool(record_analysis_test, security=security)
        if direct
        else ToolNode([record_analysis_test], security=security)
    )

    def invoke(message):
        if direct:
            return target.invoke({"message": message}, principal_config())
        return target.invoke(
            {
                "messages": [
                    AIMessage(
                        content="",
                        tool_calls=[
                            {
                                "name": "record_analysis_test",
                                "args": {"message": message},
                                "id": "call",
                            }
                        ],
                    )
                ]
            },
            principal_config(),
        )

    invoke("safe")
    assert effects == ["safe"]
    version = runtime.config.policy_version
    adapter.before("input.admit", (adapter.value("restricted document"),))
    if direct:
        with pytest.raises(SecurityDeniedError, match="department:restricted"):
            invoke("blocked")
    else:
        result = invoke("blocked")
        assert "department:restricted" in result["messages"][0].content
    assert effects == ["safe"]
    assert runtime.config.policy_version == version
    snapshots = [
        s for s in runtime.journal.snapshots() if s.event.event_name == "tool.dispatch"
    ]
    assert snapshots[-1].request_digest != snapshots[0].request_digest
    assert (
        client.get_snapshot(snapshots[-1].snapshot_id).snapshot.findings
        == snapshots[-1].findings
    )
    runtime.close()


def test_another_module_denial_wins():
    runtime, _, _, _ = setup_runtime()
    security = SecurityConfig(
        modules=(AnalysisGate(runtime.config.policy_version), Deny()), analysis=runtime
    )
    effects = []

    @guarded_tool(security=security)
    @dac(owner="user", grants={"user": "x"})
    def denied_analysis_test(message: str) -> str:
        """Never execute."""
        effects.append(message)
        return message

    with pytest.raises(SecurityDeniedError, match="other:deny"):
        denied_analysis_test.invoke({"message": "x"}, principal_config())
    assert effects == []
    runtime.close()
