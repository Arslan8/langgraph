"""Finite separated-model protocol; protected outputs never become planner text."""

from typing import Literal

import pytest
from pydantic import ValidationError

from langgraph.prebuilt.analysis.contracts import Record
from langgraph.prebuilt.analysis.provenance.records import ValueRecord
from langgraph.prebuilt.security import Principal
from langgraph.prebuilt.security.modules.analysis_flow import AnalysisFlowPolicy
from langgraph.prebuilt.security.objects import (
    LabeledValue,
    ModelInvocationRequest,
    SecurityLabels,
)
from langgraph.prebuilt.security.stack import SecurityStack
from langgraph.prebuilt.security.types import Verdict
from tests.analysis.test_runtime_access import setup_runtime


class Extraction(Record):
    value: str


class PlannerStatus(Record):
    status: Literal["complete", "failed"]
    category: Literal["none", "invalid_output", "execution_failed"]
    operation_id: Literal["extract_record"]


class SeparatedRoles:
    def __init__(self, adapter, planner, extractor, authorize):
        self.adapter, self.planner, self.extractor, self.authorize = (
            adapter,
            planner,
            extractor,
            authorize,
        )

    def extract(self, ref):
        self.authorize("extractor", ref)
        try:
            response = self.extractor(self.adapter.runtime.store.resolve(ref))
            extraction = Extraction.model_validate(response)
            stored = self.adapter.value(
                extraction.model_dump(), (ref,), "extractor.response"
            )
            status = PlannerStatus(
                status="complete", category="none", operation_id="extract_record"
            )
        except Exception:
            # No exception strings, explanation or untrusted structured keys escape.
            stored = None
            status = PlannerStatus(
                status="failed",
                category="invalid_output",
                operation_id="extract_record",
            )
        return stored, status

    def plan(self, trusted_task, refs, status):
        for ref in refs:
            # The trusted fixed protocol releases a fresh opaque handle, not a
            # container holding the protected value. The reference map stays here.
            runtime = self.adapter.runtime
            handle = runtime.store.register(
                ValueRecord(
                    runtime.tenant_id,
                    runtime.session_id,
                    runtime.run_id,
                    b'"opaque handle"',
                )
            )
            self.authorize("planner", handle)
        # Opaque IDs and bounded protocol status only; no raw source or extractor text.
        return self.planner(
            {
                "task": trusted_task,
                "references": [ref.value_id for ref in refs],
                "status": status.model_dump(),
            }
        )


def test_model_role_visibility_and_safe_errors():
    runtime, adapter, _, _ = setup_runtime()
    sentinel = "SECRET-SENTINEL-DO-NOT-EXPOSE"
    source = runtime.store.register(
        ValueRecord(
            "tenant",
            "session",
            "run",
            sentinel.encode(),
            labels=SecurityLabels(frozenset({"secret"}), "low"),
        )
    )
    principal = Principal("owner", frozenset(), frozenset(), "session")
    flow = AnalysisFlowPolicy(
        runtime.config.policy_version,
        runtime.store.domains,
        {"planner": (), "extractor": ("secret",)},
    )
    stack = SecurityStack((flow,), analysis=runtime)
    requests = []
    checked = []

    def authorize(role, ref):
        checked.append((role, ref))
        with runtime.influence_scope((ref,)):
            result = stack.object_permission(
                principal,
                ModelInvocationRequest(
                    role, (LabeledValue("input", "protected reference"),), role
                ),
            )
        if result.decision.verdict is not Verdict.ALLOW:
            raise PermissionError(result.decision.reason)

    roles = SeparatedRoles(
        adapter, requests.append, lambda _: {"value": sentinel}, authorize
    )
    ref, status = roles.extract(source)
    roles.plan("Inspect the opaque record", (ref,), status)
    assert sentinel not in str(requests)
    assert runtime.store.resolve(ref).decode().find(sentinel) >= 0
    # Tool-shaped extractor output cannot execute and fails structured validation.
    roles.extractor = lambda _: {
        "tool_calls": [{"name": "sink", "args": {"message": sentinel}}]
    }
    ref, status = roles.extract(source)
    assert ref is None and status.status == "failed"
    roles.plan("Retry", (), status)
    assert sentinel not in str(requests)
    assert {role for role, _ in checked} == {"planner", "extractor"}
    with pytest.raises(ValidationError):
        PlannerStatus(status="failed", category=sentinel, operation_id="extract_record")
    with pytest.raises(PermissionError):
        authorize("planner", source)
    stack.close()
    runtime.close()
