"""Finite trusted select/concat/conditional/loop/guarded-call integration fixture."""

import pytest

from langgraph.prebuilt.analysis.adapters.interpreter import (
    InterpreterBinding,
    InterpreterBoundary,
)
from langgraph.prebuilt.analysis.provenance.domains import (
    AllowedReadersDomain,
    DomainRegistry,
)
from langgraph.prebuilt.analysis.provenance.records import DependencyEdge, ValueRecord
from langgraph.prebuilt.analysis.provenance.store import MemoryProvenanceStore
from langgraph.prebuilt.security import (
    SecurityConfig,
    SecurityDeniedError,
    dac,
    guarded_tool,
)
from langgraph.prebuilt.security.modules.analysis_flow import AnalysisFlowPolicy
from tests.analysis.test_policy_bridge import principal_config
from tests.analysis.test_runtime_access import setup_runtime


def test_precise_fields_control_effects_and_opaque_fallback():
    runtime, _, _, _ = setup_runtime()
    # This fixture's root fixes the domain set before starting any operation.
    runtime.store.close()
    store = MemoryProvenanceStore(domains=DomainRegistry((AllowedReadersDomain(),)))
    runtime.store = store
    runtime.journal = type(runtime.journal)(store)
    policy = AnalysisFlowPolicy(
        runtime.config.policy_version,
        store.domains,
        {"interpreter_sink": ()},
        read_bounds={"interpreter_sink": ()},
    )
    security = SecurityConfig(modules=(policy,), analysis=runtime)
    effects = []

    @guarded_tool(security=security)
    @dac(owner="user", grants={"user": "x"})
    def interpreter_sink(message: str) -> str:
        """A mediated fixture effect."""
        effects.append(message)
        return "recorded"

    def dispatch(principal, ref, controls):
        with runtime.influence_scope((ref, *controls)):
            return interpreter_sink.invoke({"message": "literal"}, principal_config())

    boundary = InterpreterBoundary(
        runtime,
        InterpreterBinding(
            "fixture",
            "1",
            frozenset(
                {"select", "concatenate", "conditional", "bounded_loop", "guarded_call"}
            ),
        ),
        dispatch,
    )
    secret = store.register(
        ValueRecord(
            "tenant",
            "session",
            "run",
            b'"sentinel"',
            domains_json='{"analysis.allowed_readers":["cleared"]}',
        )
    )
    public = boundary.register("public")
    container = store.derive(
        (),
        ValueRecord("tenant", "session", "run", b"{}"),
        "container",
        edges=(
            DependencyEdge(parent=secret, kind="containment", selector="secret"),
            DependencyEdge(parent=public, kind="containment", selector="public"),
        ),
    )
    selector = boundary.register("public")
    selected = boundary.derive("select", "public", (public,), (selector,))
    with pytest.raises(SecurityDeniedError):
        boundary.guarded_call(None, container)
    assert secret not in store.ancestors(selected)
    assert selector in store.ancestors(selected)
    boundary.guarded_call(None, selected)
    assert effects == ["literal"]
    joined = boundary.derive("concatenate", "joined", (selected, secret))
    with pytest.raises(SecurityDeniedError):
        boundary.guarded_call(None, joined)
    with pytest.raises(SecurityDeniedError):
        with boundary.control(secret):
            boundary.guarded_call(None, selected)
    for _ in range(2):
        with boundary.control(secret):
            constant = boundary.derive("bounded_loop", "constant", ())
            assert any(
                edge.kind == "control" for edge in store.get(constant).dependencies
            )
    opaque = boundary.derive("unsupported", "opaque", (selected, secret))
    assert secret in store.ancestors(opaque)
    assert store.get(container).dependencies[0].kind == "containment"
    # Exception-safe exit restores the prior task scope.
    boundary.guarded_call(None, selected)
    assert effects == ["literal", "literal"]
    runtime.close()
