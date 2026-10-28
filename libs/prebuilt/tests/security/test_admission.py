"""Closed admission refuses unsupported graph bodies before any candidate call."""

from __future__ import annotations

import hashlib
import operator
import shutil
from dataclasses import replace
from pathlib import Path
from typing import Annotated, Any

import pytest
from langchain_core.messages import AnyMessage
from langchain_core.runnables import Runnable
from langchain_core.tools import tool
from langgraph._internal import _runtime_policy
from langgraph._internal._runnable import RunnableCallable
from langgraph.channels import BinaryOperatorAggregate, LastValue
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.graph.message import add_messages
from langgraph.pregel._read import PregelNode
from langgraph.types import CachePolicy, RetryPolicy, TracePolicy
from typing_extensions import TypedDict

from langgraph.prebuilt import ToolNode, tools_condition
from langgraph.prebuilt.security import (
    DacOverrides,
    LinuxSandboxExecutor,
    LinuxToolSpec,
    SecurityConfig,
    SecurityConfigurationError,
    TypedPolicyBackend,
    cedar_security,
    install_mac_policy,
    parse_profiles,
)
from langgraph.prebuilt.security.admission import (
    AdmittedDescriptor,
    AdmittedKind,
    admit_branch,
    admit_node,
    describe,
    recheck,
)
from langgraph.prebuilt.security.inprocess import read_text
from langgraph.prebuilt.security.mac import _graph_boundaries, _MacBoundary
from langgraph.prebuilt.security.object_broker import ObjectBrokerDispatcher
from langgraph.prebuilt.security.placement import MediatedBranch, MediatedNode
from tests.security.test_manifest_admission import MANIFEST, PERMIT

FORBID = 'forbid(principal, action == slangGraph::Action::"fs::read", resource);'
_FIXTURES = Path(__file__).with_name("fixtures").resolve()
requires_cedar = pytest.mark.skipif(
    shutil.which("cedar") is None, reason="Cedar CLI required"
)


@pytest.fixture(autouse=True)
def isolated_runtime(monkeypatch):
    monkeypatch.delenv("LANGGRAPH_MAC_DIR", raising=False)
    # Tests simulate separate interpreters. Production exposes no reset API.
    monkeypatch.setattr(_runtime_policy, "_policy", None)
    monkeypatch.setattr(_runtime_policy, "_started", False)
    monkeypatch.setattr(_runtime_policy, "_system_loaded", True)


class Marker(Runnable[Any, Any]):
    """Record every protocol touch on a candidate body; never execute it."""

    name = "marker"

    def __init__(self) -> None:
        self.__dict__["touches"] = []

    def __getattr__(self, name: str) -> Any:
        self.__dict__["touches"].append(name)
        raise AttributeError(name)

    def get_name(self, suffix: str | None = None, *, name: str | None = None) -> str:
        self.__dict__["touches"].append("get_name")
        return "marker"

    def invoke(self, input: Any, config: Any = None, **kwargs: Any) -> Any:
        raise AssertionError("candidate body executed")


class CallableMarker:
    """A plain callable whose attribute protocol records every access."""

    def __init__(self) -> None:
        self.__dict__["touches"] = []

    def __getattr__(self, name: str) -> Any:
        self.__dict__["touches"].append(name)
        raise AttributeError(name)

    def __call__(self, state: Any) -> Any:
        raise AssertionError("candidate body executed")


def local_tool():
    @tool
    def admitted_reader(path: str) -> str:
        """Read through the official resource API."""
        return read_text(path)

    return admitted_reader


def language_security(candidate, *, closed: bool = True) -> SecurityConfig:
    security = cedar_security(candidate, manifest=MANIFEST, policy=PERMIT)
    return replace(security, closed_admission=closed)


def graph_for(node, security, *, branch=None, name="tools"):
    builder = StateGraph(MessagesState)
    builder.add_node(name, node)
    builder.add_edge(START, name)
    if branch is not None:
        builder.add_conditional_edges(name, branch)
    return builder.compile(security=security)


def test_closed_admission_is_a_validated_opt_in() -> None:
    assert SecurityConfig().closed_admission is False
    assert SecurityConfig(closed_admission=True).closed_admission is True
    with pytest.raises(TypeError):
        SecurityConfig(closed_admission="yes")  # type: ignore[arg-type]


@requires_cedar
def test_language_sandbox_tool_node_and_framework_branch_are_admitted() -> None:
    candidate = local_tool()
    node = ToolNode([candidate])
    graph = graph_for(node, language_security(candidate), branch=tools_condition)

    inventory = graph.builder._security_admission
    assert type(inventory) is tuple and len(inventory) == 2
    by_name = {descriptor.name: descriptor for descriptor in inventory}
    program = by_name["tools"]
    branch = by_name["tools:branch:tools_condition"]
    assert program.kind is AdmittedKind.LANGUAGE_PROGRAM
    assert branch.kind is AdmittedKind.FRAMEWORK_BRANCH
    assert program.implementation.node is node
    assert type(graph.builder.nodes["tools"].runnable) is MediatedNode
    assert graph.builder.nodes["tools"].runnable.runnable is node
    mediated_branch = graph.builder.branches["tools"]["tools_condition"].path
    assert type(mediated_branch) is MediatedBranch
    assert mediated_branch.runnable is branch.implementation.path

    evidence = describe(program)
    assert evidence["kind"] == "language_program"
    assert evidence["details"]["tool"] == "admitted_reader"
    assert evidence["details"]["programs"]["func"]["terminals"] == ["read_text"]
    assert len(program.identity) == 64 and len(program.source_sha256) == 64
    assert describe(branch)["details"]["function"] == (
        "langgraph.prebuilt.tool_node:tools_condition"
    )
    assert describe(branch)["details"]["ends"] == [
        ["__end__", "__end__"],
        ["tools", "tools"],
    ]
    for descriptor in inventory:
        recheck(descriptor)


@requires_cedar
def test_recheck_refuses_replaced_program_or_wrapper() -> None:
    candidate = local_tool()
    node = ToolNode([candidate])
    graph = graph_for(node, language_security(candidate), branch=tools_condition)
    program, branch = graph.builder._security_admission

    def other(path: str) -> str:
        return path

    original = candidate.func
    candidate.func = other
    try:
        with pytest.raises(PermissionError, match="admission:descriptor_changed"):
            recheck(program)
    finally:
        candidate.func = original
    recheck(program)

    node._wrap_tool_call = lambda request, execute: execute(request)
    try:
        with pytest.raises(PermissionError, match="admission:descriptor_changed"):
            recheck(program)
    finally:
        node._wrap_tool_call = None
    recheck(program)

    spec = graph.builder.branches["tools"]["tools_condition"]
    assert spec.ends is not None
    spec.ends["tools"] = "elsewhere"
    try:
        with pytest.raises(PermissionError, match="admission:descriptor_changed"):
            recheck(branch)
    finally:
        spec.ends["tools"] = "tools"
    recheck(branch)

    forged = AdmittedDescriptor(
        program.kind, program.name, "0" * 64, program.implementation, "0" * 64
    )
    with pytest.raises(PermissionError, match="admission:descriptor_changed"):
        recheck(forged)
    with pytest.raises(PermissionError, match="admission:descriptor_changed"):
        recheck(object())  # type: ignore[arg-type]


@requires_cedar
def test_exact_tool_node_with_broker_dispatch_is_admitted(tmp_path: Path) -> None:
    source = tmp_path / "worker.py"
    source.write_text("def run(path):\n    return open(path).read()\n")
    dispatcher = ObjectBrokerDispatcher(
        {
            "read_record": LinuxToolSpec(
                "worker:run", source, hashlib.sha256(source.read_bytes()).hexdigest()
            )
        },
        runtime_roots=(tmp_path,),
    )

    @tool
    def read_record(path: str) -> str:
        """Trusted schema only; body must never execute."""
        raise AssertionError("coordinator execution")

    security = replace(
        cedar_security(
            read_record,
            manifest="runs linux\nfs read @{path} need",
            policy=PERMIT,
            dispatcher=dispatcher,
        ),
        closed_admission=True,
    )
    node = ToolNode([read_record])
    graph = graph_for(node, security)
    (descriptor,) = graph.builder._security_admission
    assert descriptor.kind is AdmittedKind.TOOL_NODE
    evidence = describe(descriptor)
    assert evidence["details"]["host"] == "broker"
    assert evidence["details"]["specs"][0]["artifact_sha256"] == (
        hashlib.sha256(source.read_bytes()).hexdigest()
    )
    recheck(descriptor)

    wrapped = ToolNode([read_record], wrap_tool_call=lambda request, execute: None)
    with pytest.raises(PermissionError, match="admission:unsupported_node_body"):
        graph_for(wrapped, security)


def test_native_linux_deployment_is_admitted(tmp_path: Path) -> None:
    artifact = _FIXTURES / "linux_tools.py"
    profiles = parse_profiles(
        f"""
tool read_file {{
  owner analyst
  grant analyst: call
  runs linux
  syscalls @minimal
  fs read ${{path}} need
}}
principal alice {{
  roles analyst
  fs read {tmp_path}/**
}}
""",
        source="admission-test.slp",
    )
    try:
        executor = LinuxSandboxExecutor(
            profiles,
            {
                "read_file": LinuxToolSpec(
                    "linux_tools:read_file",
                    artifact,
                    hashlib.sha256(artifact.read_bytes()).hexdigest(),
                )
            },
            runtime_roots=(_FIXTURES,),
            policy_backend=TypedPolicyBackend(),
        )
    except RuntimeError as exc:
        pytest.skip(f"Linux host execution unavailable: {exc}")

    @tool
    def read_file(path: str) -> str:
        """Schema only; the body never runs in the coordinator."""
        raise AssertionError("coordinator execution")

    security = SecurityConfig(
        dac_overrides=DacOverrides(profiles=profiles.tools),
        host_executor=executor,
        closed_admission=True,
    )
    node = ToolNode([read_file])
    graph = graph_for(node, security)
    (descriptor,) = graph.builder._security_admission
    assert descriptor.kind is AdmittedKind.NATIVE_DEPLOYMENT
    evidence = describe(descriptor)
    assert evidence["details"]["host"] == "linux"
    assert evidence["details"]["specs"][0]["entrypoint"] == "linux_tools:read_file"
    recheck(descriptor)


@requires_cedar
@pytest.mark.parametrize(
    "shape",
    [
        "plain_function",
        "metadata_promoted",
        "wrapper_with_tool_node",
        "runnable_subclass",
        "async_function",
        "callable_marker",
    ],
)
def test_unsupported_node_bodies_refuse_before_any_candidate_protocol(
    shape: str,
) -> None:
    candidate = local_tool()
    security = language_security(candidate)
    builder = StateGraph(MessagesState)
    builder.add_node("tools", ToolNode([candidate]))
    builder.add_edge(START, "tools")
    marker: Any = None
    metadata = None
    if shape == "plain_function":

        def body(state):
            raise AssertionError("candidate body executed")

    elif shape == "metadata_promoted":
        marker = body = Marker()
        metadata = {"security_trust": "trusted", "security_promotion_reason": "ok"}
    elif shape == "wrapper_with_tool_node":
        marker = body = Marker()
        marker.__dict__["runnable"] = ToolNode([candidate])
    elif shape == "runnable_subclass":

        class Arbitrary(Runnable[Any, Any]):
            def invoke(self, input, config=None, **kwargs):
                raise AssertionError("candidate body executed")

        body = Arbitrary()
    elif shape == "async_function":

        async def body(state):
            raise AssertionError("candidate body executed")

    else:
        marker = body = CallableMarker()
    builder.add_node("body", body, metadata=metadata)
    builder.add_edge("tools", "body")
    touched = None if marker is None else list(marker.__dict__["touches"])

    with pytest.raises(PermissionError, match="admission:unsupported_node_body"):
        builder.compile(security=security)
    if marker is not None:
        assert marker.__dict__["touches"] == touched
    assert type(builder.nodes["tools"].runnable) is ToolNode


@requires_cedar
def test_unsupported_branches_refuse_with_exact_codes() -> None:
    candidate = local_tool()
    security = language_security(candidate)

    async def async_route(state):
        raise AssertionError("candidate body executed")

    with pytest.raises(PermissionError, match="admission:unsupported_async"):
        graph_for(ToolNode([candidate]), security, branch=async_route)

    def local_route(state) -> str:
        raise AssertionError("candidate body executed")

    with pytest.raises(PermissionError, match="admission:unsupported_branch"):
        graph_for(ToolNode([candidate]), security, branch=local_route)

    marker = Marker()
    builder = StateGraph(MessagesState)
    builder.add_node("tools", ToolNode([candidate]))
    builder.add_edge(START, "tools")
    builder.add_conditional_edges("tools", marker, {"tools": "tools", END: END})
    touched = list(marker.__dict__["touches"])
    with pytest.raises(PermissionError, match="admission:unsupported_branch"):
        builder.compile(security=security)
    assert marker.__dict__["touches"] == touched


@requires_cedar
def test_coordinator_tool_node_and_foreign_config_are_refused() -> None:
    candidate = local_tool()
    node = ToolNode([candidate])
    with pytest.raises(PermissionError, match="admission:unsupported_node_body"):
        admit_node("tools", node, config=SecurityConfig(closed_admission=True))
    with pytest.raises(PermissionError, match="admission:unsupported_node_body"):
        admit_node("tools", node, config=object())
    with pytest.raises(PermissionError, match="admission:unsupported_node_body"):
        admit_node("", node, config=language_security(candidate))
    with pytest.raises(PermissionError, match="admission:unsupported_branch"):
        admit_branch("b", object(), config=language_security(candidate))
    with pytest.raises(PermissionError, match="admission:unsupported_node_body"):
        graph_for(node, SecurityConfig(closed_admission=True))


@requires_cedar
def test_default_configuration_compiles_the_same_graphs_as_before() -> None:
    candidate = local_tool()
    security = language_security(candidate, closed=False)
    wrapper = Marker()
    wrapper.__dict__["runnable"] = ToolNode([candidate])

    def route(state) -> str:
        return END

    builder = StateGraph(MessagesState)
    builder.add_node("tools", ToolNode([candidate]))
    builder.add_node("local", lambda state: {})
    builder.add_node("wrapper", wrapper)
    builder.add_edge(START, "tools")
    builder.add_edge("tools", "local")
    builder.add_edge("local", "wrapper")
    builder.add_conditional_edges("wrapper", route)
    graph = builder.compile(security=security)
    assert all(
        type(spec.runnable) is MediatedNode for spec in graph.builder.nodes.values()
    )
    assert not hasattr(graph.builder, "_security_admission")
    assert graph.builder._security_config.closed_admission is False

    plain = StateGraph(MessagesState)
    plain.add_node("local", lambda state: {})
    plain.add_edge(START, "local")
    compiled = plain.compile(security=SecurityConfig())
    assert type(compiled.builder.nodes["local"].runnable) is MediatedNode
    assert not hasattr(compiled.builder, "_security_admission")


@requires_cedar
def test_runtime_mac_binds_admitted_inventory_and_keeps_the_legacy_shape() -> None:
    candidate = local_tool()
    closed = graph_for(
        ToolNode([candidate]), language_security(candidate), branch=tools_condition
    )
    legacy_node = ToolNode([candidate])
    legacy = graph_for(legacy_node, language_security(candidate, closed=False))

    def local_route(state) -> str:
        return END

    legacy_with_branch = graph_for(
        ToolNode([candidate]),
        language_security(candidate, closed=False),
        branch=local_route,
    )
    install_mac_policy(FORBID)

    _runtime_policy.check_runtime_policy(closed)
    boundary = _graph_boundaries[closed]
    assert type(boundary) is _MacBoundary
    assert [entry[2].kind for entry in boundary.nodes] == [
        AdmittedKind.LANGUAGE_PROGRAM
    ]
    assert [(entry[1], entry[3].kind) for entry in boundary.branches] == [
        ("tools", AdmittedKind.FRAMEWORK_BRANCH)
    ]

    # The legacy path is the pre-admission boundary: the wrapped ToolNodes for
    # the exact shape, None (unconfined) for anything else, nothing admitted.
    legacy_boundary = _graph_boundaries[legacy]
    assert type(legacy_boundary) is tuple and len(legacy_boundary) == 1
    assert legacy_boundary[0] is legacy_node
    _runtime_policy.check_runtime_policy(legacy)
    assert _graph_boundaries[legacy_with_branch] is None
    with pytest.raises(SecurityConfigurationError, match="mac:unconfined_graph_body"):
        _runtime_policy.check_runtime_policy(legacy_with_branch)
    for graph in (legacy, legacy_with_branch):
        assert not hasattr(graph.builder, "_security_admission")

    mediated = closed.builder.nodes["tools"].runnable
    original = mediated.runnable
    mediated.runnable = ToolNode([candidate])
    try:
        with pytest.raises(PermissionError, match="admission:descriptor_changed"):
            _runtime_policy.check_runtime_policy(closed)
    finally:
        mediated.runnable = original
    _runtime_policy.check_runtime_policy(closed)


@requires_cedar
def test_runtime_mac_binds_the_compiled_pregel_nodes() -> None:
    candidate = local_tool()
    closed = graph_for(
        ToolNode([candidate]), language_security(candidate), branch=tools_condition
    )
    install_mac_policy(FORBID)
    _runtime_policy.check_runtime_policy(closed)
    effects: list[str] = []
    marker = RunnableCallable(lambda state: effects.append("bound") or {})
    proc = closed.nodes["tools"]
    assert type(proc) is PregelNode
    assert proc.bound is closed.builder.nodes["tools"].runnable

    def refused() -> None:
        with pytest.raises(PermissionError, match="admission:descriptor_changed"):
            _runtime_policy.check_runtime_policy(closed)

    # Swapping the compiled body the scheduler invokes refuses before any work.
    original = proc.bound
    proc.bound = marker
    try:
        refused()
        with pytest.raises(PermissionError, match="admission:descriptor_changed"):
            closed.invoke({"messages": []})
    finally:
        proc.bound = original
    _runtime_policy.check_runtime_policy(closed)

    # An added or removed compiled node changes the inventory.
    closed.nodes["extra"] = PregelNode(
        channels=["messages"], triggers=["messages"], bound=marker
    )
    try:
        refused()
    finally:
        del closed.nodes["extra"]
    removed = closed.nodes.pop("tools")
    try:
        refused()
    finally:
        closed.nodes["tools"] = removed
    _runtime_policy.check_runtime_policy(closed)

    # The compiled branch writer must dispatch the captured MediatedBranch, and
    # no writer outside ChannelWrite/admitted branches may be present.
    writer = proc.writers[-1]
    assert type(writer) is RunnableCallable
    original_func = writer.func
    writer.func = lambda *args, **kwargs: effects.append("branch")
    try:
        refused()
    finally:
        writer.func = original_func
    proc.writers.remove(writer)
    try:
        refused()
    finally:
        proc.writers.append(writer)
    proc.writers.append(RunnableCallable(lambda state: effects.append("writer")))
    try:
        refused()
    finally:
        proc.writers.pop()
    _runtime_policy.check_runtime_policy(closed)

    # A cached execution plan cannot outlive the check.
    proc.__dict__["node"] = marker
    _runtime_policy.check_runtime_policy(closed)
    assert "node" not in proc.__dict__
    assert effects == []


@requires_cedar
@pytest.mark.parametrize(
    "kind", ["reducer", "custom_channel", "cache", "retry", "retry_sequence", "trace"]
)
def test_author_callbacks_refuse_under_closed_admission_before_any_protocol(
    kind: str,
) -> None:
    candidate = local_tool()
    calls: list[str] = []

    def marker(*args: Any, **kwargs: Any) -> Any:
        calls.append(kind)
        raise AssertionError("author callback executed")

    def reducer(left: Any, right: Any) -> Any:
        return marker(left, right)

    # Functional TypedDicts keep the closure-bound annotations as objects; the
    # module's postponed annotations would otherwise hide `marker`.
    messages = Annotated[list[AnyMessage], add_messages]
    state: Any = MessagesState
    options: dict[str, Any] = {}
    if kind == "reducer":
        state = TypedDict(  # noqa: UP013
            "Reduced", {"messages": messages, "notes": Annotated[list, reducer]}
        )
    elif kind == "custom_channel":

        class Custom(LastValue):
            def update(self, values):
                marker(values)
                return False

        state = TypedDict(  # noqa: UP013
            "Channelled",
            {"messages": messages, "notes": Annotated[list, Custom(list)]},
        )
    elif kind == "cache":
        options["cache_policy"] = CachePolicy(key_func=marker)
    elif kind == "retry":
        options["retry_policy"] = RetryPolicy(retry_on=lambda exc: marker(exc))
    elif kind == "retry_sequence":
        options["retry_policy"] = [RetryPolicy(), RetryPolicy(retry_on=ValueError)]
    else:
        options["trace_policy"] = TracePolicy(process_inputs=marker)
    node = ToolNode([candidate])
    builder = StateGraph(state)
    builder.add_node("tools", node, **options)
    builder.add_edge(START, "tools")

    with pytest.raises(PermissionError, match="admission:unsupported_callback"):
        builder.compile(security=language_security(candidate))
    assert calls == []
    assert builder.nodes["tools"].runnable is node
    assert not hasattr(builder, "_security_admission")

    # The default configuration compiles the same graph unchanged (the legacy
    # classification path, not the admission module, places the node).
    graph = builder.compile(security=language_security(candidate, closed=False))
    assert type(graph.builder.nodes["tools"].runnable) is MediatedNode
    assert not hasattr(graph.builder, "_security_admission")
    assert calls == []


@requires_cedar
def test_pinned_reducers_and_default_policies_remain_admitted() -> None:
    candidate = local_tool()

    class Noted(MessagesState):
        notes: Annotated[list[str], operator.add]

    builder = StateGraph(Noted)
    builder.add_node(
        "tools",
        ToolNode([candidate]),
        cache_policy=CachePolicy(),
        retry_policy=RetryPolicy(),
    )
    builder.add_edge(START, "tools")
    builder.add_conditional_edges("tools", tools_condition)
    graph = builder.compile(security=language_security(candidate))
    assert len(graph.builder._security_admission) == 2
    channels = graph.builder.channels
    assert type(channels["messages"]) is BinaryOperatorAggregate
    assert type(channels["notes"]) is BinaryOperatorAggregate
    assert channels["notes"].operator is operator.add


def test_runtime_mac_still_refuses_unconfined_default_bodies() -> None:
    builder = StateGraph(MessagesState)
    builder.add_node("body", lambda state: {}, metadata={"security_trust": "trusted"})
    builder.add_edge(START, "body")
    graph = builder.compile(security=SecurityConfig())
    install_mac_policy(FORBID)
    with pytest.raises(SecurityConfigurationError, match="mac:unconfined_graph_body"):
        _runtime_policy.check_runtime_policy(graph)
