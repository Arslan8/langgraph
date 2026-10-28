"""Descriptor-bound dispatch: admitted wrappers run only their captured plan."""

from __future__ import annotations

import operator
import shutil
from dataclasses import replace
from functools import partial
from pathlib import Path
from typing import Annotated, Any

import pytest
from langchain_core.messages import AIMessage
from langchain_core.runnables import Runnable
from langchain_core.tools import tool
from langgraph._internal import _runtime_policy
from langgraph._internal._runnable import RunnableCallable, run_in_executor
from langgraph.graph import END, START, MessagesState, StateGraph
from typing_extensions import TypedDict

from langgraph.prebuilt import ToolNode, tools_condition
from langgraph.prebuilt.security import (
    Decision,
    Principal,
    SecurityConfig,
    SecurityModule,
    Verdict,
    cedar_security,
    with_principal,
)
from langgraph.prebuilt.security.admission import AdmittedDescriptor
from langgraph.prebuilt.security.inprocess import read_text
from langgraph.prebuilt.security.object_policy import ObjectPolicyHostExecutor
from langgraph.prebuilt.security.placement import (
    MediatedBranch,
    MediatedNode,
    NodeKind,
    NodeTrust,
    PlacementSpec,
    _bounded_input,
    _narrowed_config,
)
from tests.security.test_manifest_admission import MANIFEST, PERMIT

requires_cedar = pytest.mark.skipif(
    shutil.which("cedar") is None, reason="Cedar CLI required"
)


@pytest.fixture(autouse=True)
def isolated_runtime(monkeypatch):
    monkeypatch.delenv("LANGGRAPH_MAC_DIR", raising=False)
    monkeypatch.setattr(_runtime_policy, "_policy", None)
    monkeypatch.setattr(_runtime_policy, "_started", False)
    monkeypatch.setattr(_runtime_policy, "_system_loaded", True)


class State(TypedDict):
    value: str


class Record(SecurityModule):
    """Record mediation effects (dispatch transfers and state writes)."""

    name = "record"

    def __init__(self) -> None:
        self.transfers: list[str] = []
        self.writes: list[str] = []
        self.models: list[str] = []

    def cred_transfer(self, parent, child, slot):
        self.transfers.append(child.user_id)
        return Decision(Verdict.ALLOW, "record:dispatch")

    def state_write(self, principal, request):
        self.writes.append(request.resource)
        return Decision(Verdict.ALLOW, "record:write")

    def model_invoke(self, principal, request):
        self.models.append(request.node)
        return Decision(Verdict.DENY, "witness:no-model")


def local_tool():
    @tool
    def admitted_reader(path: str) -> str:
        """Read through the official resource API."""
        return read_text(path)

    return admitted_reader


def language_security(candidate, record: Record, *, closed: bool = True):
    security = cedar_security(
        candidate, manifest=MANIFEST, policy=PERMIT, modules=(record,)
    )
    return replace(security, closed_admission=closed)


def principal_config(security: SecurityConfig):
    return with_principal(
        {},
        Principal("alice", frozenset(), frozenset(), "session"),
        modules=security.modules,
    )


def tool_request(candidate, path: Path) -> dict[str, Any]:
    return {
        "messages": [
            AIMessage(
                content="",
                tool_calls=[
                    {"name": candidate.name, "args": {"path": str(path)}, "id": "read"}
                ],
            )
        ]
    }


def admitted_graph(candidate, record: Record):
    node = ToolNode([candidate])
    builder = StateGraph(MessagesState)
    builder.add_node("tools", node)
    builder.add_edge(START, "tools")
    builder.add_conditional_edges("tools", tools_condition)
    security = language_security(candidate, record)
    graph = builder.compile(security=security)
    return graph, node, security


# --- acceptance check 1: literal refusal before the retained marker ---------


class ForeignNode(Runnable[Any, Any]):
    """Metadata-promoted foreign body; its marker must never run."""

    def __init__(self, calls: list[str]) -> None:
        self.calls = calls

    def invoke(self, input: Any, config: Any = None, **kwargs: Any) -> Any:
        self.calls.append("coordinator-effect")
        return {"value": input["value"]}


class WrapperNode(Runnable[Any, Any]):
    """Wrapper that merely contains an otherwise valid `ToolNode`."""

    def __init__(self, calls: list[str], node: ToolNode) -> None:
        self.calls = calls
        self.runnable = node

    def invoke(self, input: Any, config: Any = None, **kwargs: Any) -> Any:
        self.calls.append("coordinator-effect")
        return {}


@requires_cedar
@pytest.mark.parametrize(
    "shape", ["plain_function", "metadata_promoted", "wrapper_with_tool_node"]
)
def test_marker_witness_refuses_before_the_marker(shape: str) -> None:
    candidate = local_tool()
    calls: list[str] = []

    def ordinary_node(state):
        calls.append("coordinator-effect")
        return {"value": state["value"]}

    def build(security: SecurityConfig):
        metadata = None
        if shape == "plain_function":
            builder = StateGraph(State)
            body: Any = ordinary_node
        elif shape == "metadata_promoted":
            builder = StateGraph(State)
            body = ForeignNode(calls)
            metadata = {"security_trust": "trusted", "security_promotion_reason": "ok"}
        else:
            builder = StateGraph(MessagesState)
            body = WrapperNode(calls, ToolNode([candidate]))
        builder.add_node("ordinary", body, metadata=metadata)
        builder.add_edge(START, "ordinary")
        builder.add_edge("ordinary", END)
        return builder.compile(security=security)

    # Retained witness: the legacy default still runs the marker in process
    # (module-name trust, metadata promotion, or ToolNode discovery under a
    # host executor).
    control = Record()
    legacy = build(
        language_security(candidate, control, closed=False)
        if shape == "wrapper_with_tool_node"
        else SecurityConfig(modules=(control,))
    )
    request: Any = {"value": "useful"} if shape != "wrapper_with_tool_node" else {}
    legacy.invoke(request, principal_config(legacy.builder._security_config))
    assert calls == ["coordinator-effect"]
    assert legacy.builder.nodes["ordinary"].runnable.descriptor is None
    calls.clear()

    # Closed admission refuses literally, before the marker and before any
    # mediation effect.
    record = Record()
    with pytest.raises(PermissionError, match="admission:unsupported_node_body"):
        build(language_security(candidate, record))
    assert calls == []
    assert record.transfers == [] and record.writes == [] and record.models == []


# --- positive: admitted ToolNode and language-sandbox tool do useful work ----


@requires_cedar
@pytest.mark.parametrize("asynchronous", [False, True])
async def test_admitted_graph_does_useful_work_end_to_end(
    tmp_path: Path, asynchronous: bool
) -> None:
    path = tmp_path / "data"
    path.write_text("fixture")
    candidate = local_tool()
    record = Record()
    graph, node, security = admitted_graph(candidate, record)

    program, branch = graph.builder._security_admission
    mediated = graph.builder.nodes["tools"].runnable
    mediated_branch = graph.builder.branches["tools"]["tools_condition"].path
    assert type(mediated) is MediatedNode and mediated.descriptor is program
    assert type(mediated_branch) is MediatedBranch
    assert mediated_branch.descriptor is branch
    assert mediated.runnable is node is program.implementation.node

    config = principal_config(security)
    request = tool_request(candidate, path)
    result = (
        await graph.ainvoke(request, config)
        if asynchronous
        else graph.invoke(request, config)
    )
    assert result["messages"][-1].content == "fixture"
    # Node dispatch and the ToolNode's own tool-call transfer are both mediated.
    assert record.transfers and set(record.transfers) == {"alice"}
    assert record.writes == ["messages"]
    with pytest.raises(PermissionError, match="resource_not_granted"):
        read_text(str(path))


@requires_cedar
async def test_pinned_reducer_channel_is_admitted_and_works_end_to_end(
    tmp_path: Path,
) -> None:
    class Noted(MessagesState):
        notes: Annotated[list[str], operator.add]

    path = tmp_path / "data"
    path.write_text("fixture")
    candidate = local_tool()
    record = Record()
    node = ToolNode([candidate])
    builder = StateGraph(Noted)
    builder.add_node("tools", node)
    builder.add_edge(START, "tools")
    builder.add_conditional_edges("tools", tools_condition)
    security = language_security(candidate, record)
    graph = builder.compile(security=security)
    assert len(graph.builder._security_admission) == 2

    request = {**tool_request(candidate, path), "notes": ["started"]}
    result = graph.invoke(request, principal_config(security))
    assert result["messages"][-1].content == "fixture"
    assert result["notes"] == ["started"]
    result = await graph.ainvoke(request, principal_config(security))
    assert result["messages"][-1].content == "fixture"
    assert result["notes"] == ["started"]


@requires_cedar
async def test_framework_branch_dispatches_the_pinned_function_inline(
    tmp_path: Path,
) -> None:
    candidate = local_tool()
    record = Record()
    graph, _, security = admitted_graph(candidate, record)
    mediated_branch = graph.builder.branches["tools"]["tools_condition"].path
    config = principal_config(security)
    calling = tool_request(candidate, tmp_path / "data")
    done = {"messages": [AIMessage(content="done")]}

    assert mediated_branch.invoke(calling, config) == "tools"
    assert mediated_branch.invoke(done, config) == END
    assert await mediated_branch.ainvoke(calling, config) == "tools"
    assert await mediated_branch.ainvoke(done, config) == END
    with pytest.raises(PermissionError, match="admission:descriptor_changed"):
        mediated_branch.invoke(calling, config, messages_key="other")
    with pytest.raises(PermissionError, match="admission:descriptor_changed"):
        await mediated_branch.ainvoke(calling, config, messages_key="other")
    assert record.transfers == []


# --- acceptance check 4: post-admission replacement is refused before effects


@requires_cedar
async def test_post_admission_replacement_refuses_before_effects(
    tmp_path: Path,
) -> None:
    path = tmp_path / "data"
    path.write_text("fixture")
    candidate = local_tool()
    record = Record()
    graph, node, security = admitted_graph(candidate, record)
    program, branch = graph.builder._security_admission
    mediated = graph.builder.nodes["tools"].runnable
    mediated_branch = graph.builder.branches["tools"]["tools_condition"].path
    spec = graph.builder.branches["tools"]["tools_condition"]
    path_runnable = branch.implementation.path
    assert spec.path is mediated_branch and mediated_branch.runnable is path_runnable
    config = principal_config(security)
    request = tool_request(candidate, path)

    def other_function(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("replacement executed")

    async def other_coroutine(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("replacement executed")

    forged = AdmittedDescriptor(
        program.kind, program.name, "0" * 64, program.implementation, "0" * 64
    )
    original_func = node.func
    original_afunc = node.afunc
    original_tool = candidate.func
    original_branch_func = path_runnable.func
    original_branch_afunc = path_runnable.afunc

    def refuses(target: Any) -> None:
        with pytest.raises(PermissionError, match="admission:descriptor_changed"):
            target.invoke(request, config)
        assert record.transfers == [] and record.writes == []

    # (a) captured callable replaced on the wrapper
    mediated.runnable = ToolNode([candidate])
    try:
        refuses(mediated)
    finally:
        mediated.runnable = node
    # (b) descriptor replaced on the wrapper
    mediated.descriptor = forged
    try:
        refuses(mediated)
    finally:
        mediated.descriptor = program
    mediated.descriptor = object()
    try:
        refuses(mediated)
    finally:
        mediated.descriptor = program
    # (c) pre/post wrapper added after admission
    node._wrap_tool_call = lambda req, execute: execute(req)
    try:
        refuses(mediated)
    finally:
        node._wrap_tool_call = None
    # (d) mutable func/afunc aliases replaced
    node.func = other_function
    try:
        refuses(mediated)
    finally:
        node.func = original_func
    node.afunc = other_coroutine
    try:
        with pytest.raises(PermissionError, match="admission:descriptor_changed"):
            await mediated.ainvoke(request, config)
        assert record.transfers == []
    finally:
        node.afunc = original_afunc
    node.afunc = node.func
    try:
        with pytest.raises(PermissionError, match="admission:descriptor_changed"):
            await mediated.ainvoke(request, config)
        assert record.transfers == []
    finally:
        node.afunc = original_afunc
    # (e) instance attribute shadowing a class-level helper
    node._run_one = other_function
    try:
        refuses(mediated)
    finally:
        del node._run_one
    # (f) admitted program replaced underneath the tool
    candidate.func = other_function
    try:
        refuses(mediated)
    finally:
        candidate.func = original_tool
    # (g) branch: wrapper runnable, routing map, pinned function and shim
    mediated_branch.runnable = RunnableCallable(other_function)
    try:
        refuses(mediated_branch)
    finally:
        mediated_branch.runnable = path_runnable
    assert spec.ends is not None
    spec.ends["tools"] = "elsewhere"
    try:
        refuses(mediated_branch)
    finally:
        spec.ends["tools"] = "tools"
    path_runnable.func = other_function
    try:
        refuses(mediated_branch)
    finally:
        path_runnable.func = original_branch_func
    path_runnable.afunc = partial(run_in_executor, None, other_function)
    try:
        refuses(mediated_branch)
    finally:
        path_runnable.afunc = original_branch_afunc
    mediated_branch.descriptor = program
    try:
        refuses(mediated_branch)
    finally:
        mediated_branch.descriptor = branch

    # Restored links dispatch the captured plan again.
    result = graph.invoke(request, config)
    assert result["messages"][-1].content == "fixture"
    assert record.transfers and set(record.transfers) == {"alice"}


@requires_cedar
async def test_override_dictionaries_foreign_containers_and_config_are_refused(
    tmp_path: Path,
) -> None:
    path = tmp_path / "data"
    path.write_text("fixture")
    candidate = local_tool()
    record = Record()
    graph, node, security = admitted_graph(candidate, record)
    mediated = graph.builder.nodes["tools"].runnable
    config = principal_config(security)
    request = tool_request(candidate, path)

    class ForeignState(dict):
        def __getitem__(self, key):
            raise AssertionError("foreign container protocol ran")

    class ForeignPrincipal:
        user_id = "root"
        roles = frozenset({"admin"})

    # Candidate-supplied override dictionaries.
    with pytest.raises(PermissionError, match="admission:descriptor_changed"):
        mediated.invoke(request, config, principal=ForeignPrincipal())
    with pytest.raises(PermissionError, match="admission:descriptor_changed"):
        await mediated.ainvoke(request, config, config_override={})
    # Foreign input containers never reach the framework primitive.
    with pytest.raises(PermissionError, match="admission:descriptor_changed"):
        mediated.invoke(ForeignState(request), config)
    with pytest.raises(PermissionError, match="admission:descriptor_changed"):
        await mediated.ainvoke(ForeignState(request), config)
    with pytest.raises(PermissionError, match="admission:descriptor_changed"):
        mediated.invoke({1: "x"}, config)
    with pytest.raises(PermissionError, match="admission:descriptor_changed"):
        mediated.invoke(("messages",), config)
    # Candidate-supplied principal or config: state keys and foreign principal
    # objects establish nothing; the native configurable is the only source.
    smuggled = {**request, "configurable": {"__principal__": ForeignPrincipal()}}
    with pytest.raises(PermissionError, match="placement:missing_principal"):
        mediated.invoke(smuggled, {})
    with pytest.raises(TypeError, match="reserved principal config"):
        mediated.invoke(
            request, {"configurable": {"__principal__": ForeignPrincipal()}}
        )
    # A native principal without the framework Runtime: refused before dispatch.
    with pytest.raises(PermissionError, match="admission:descriptor_changed"):
        mediated.invoke(request, config)
    assert record.transfers == [] and record.writes == []

    # The framework primitive receives a narrowed config: no callbacks, run
    # name or run id, and copies of the native containers.
    class Handler:
        pass

    bound = {
        "configurable": {"__principal__": "x", "thread_id": "t"},
        "metadata": {"m": 1},
        "tags": ["t"],
        "callbacks": [Handler()],
        "run_name": "candidate",
        "run_id": "r",
        "max_concurrency": 2,
        "recursion_limit": "25",
    }
    narrowed = _narrowed_config(bound)  # type: ignore[arg-type]
    assert set(narrowed) == {"configurable", "metadata", "tags", "max_concurrency"}
    assert narrowed["configurable"] == bound["configurable"]
    assert narrowed["configurable"] is not bound["configurable"]
    assert narrowed["metadata"] is not bound["metadata"]
    assert narrowed["tags"] is not bound["tags"]
    copied = _bounded_input(request)
    assert copied == request and copied is not request
    messages = _bounded_input(request["messages"])
    assert messages == request["messages"] and messages is not request["messages"]


@requires_cedar
async def test_async_refuses_before_starting_without_a_native_route(
    tmp_path: Path, monkeypatch
) -> None:
    path = tmp_path / "data"
    path.write_text("fixture")
    candidate = local_tool()
    record = Record()
    graph, node, security = admitted_graph(candidate, record)
    mediated = graph.builder.nodes["tools"].runnable
    config = principal_config(security)
    request = tool_request(candidate, path)

    def not_a_coroutine(self, principal, call, constraints):
        raise AssertionError("async route started")

    monkeypatch.setattr(ObjectPolicyHostExecutor, "ainvoke", not_a_coroutine)
    with pytest.raises(PermissionError, match="admission:unsupported_async"):
        await mediated.ainvoke(request, config)
    assert record.transfers == [] and record.writes == []
    monkeypatch.undo()
    result = await graph.ainvoke(request, config)
    assert result["messages"][-1].content == "fixture"


@requires_cedar
def test_default_wrappers_carry_no_descriptor_and_foreign_bindings_refuse(
    tmp_path: Path,
) -> None:
    candidate = local_tool()
    record = Record()
    graph, node, security = admitted_graph(candidate, record)
    program, branch = graph.builder._security_admission
    mediated = graph.builder.nodes["tools"].runnable
    router = mediated.router
    spec = PlacementSpec("tools", NodeTrust.TRUSTED, NodeKind.STANDARD)

    legacy = StateGraph(MessagesState)
    legacy.add_node("tools", ToolNode([candidate]))
    legacy.add_node("local", lambda state: {})
    legacy.add_edge(START, "tools")
    legacy.add_edge("tools", "local")
    legacy.add_conditional_edges("local", lambda state: END)
    compiled = legacy.compile(
        security=language_security(candidate, Record(), closed=False)
    )
    assert all(
        spec_.runnable.descriptor is None for spec_ in compiled.builder.nodes.values()
    )
    assert (
        compiled.builder.branches["local"][
            next(iter(compiled.builder.branches["local"]))
        ].path.descriptor
        is None
    )

    with pytest.raises(PermissionError, match="admission:descriptor_changed"):
        MediatedNode(node, spec, router, descriptor=object())  # type: ignore[arg-type]
    with pytest.raises(PermissionError, match="admission:descriptor_changed"):
        MediatedNode(ToolNode([candidate]), spec, router, descriptor=program)
    with pytest.raises(PermissionError, match="admission:descriptor_changed"):
        MediatedNode(
            node,
            PlacementSpec("tools", NodeTrust.TRUSTED, NodeKind.MODEL),
            router,
            descriptor=program,
        )
    with pytest.raises(PermissionError, match="admission:descriptor_changed"):
        MediatedNode(node, spec, router, descriptor=branch)
    path = branch.implementation.path
    with pytest.raises(PermissionError, match="admission:descriptor_changed"):
        MediatedBranch(path, "b", router, trust=NodeTrust.UNTRUSTED, descriptor=branch)
    with pytest.raises(PermissionError, match="admission:descriptor_changed"):
        MediatedBranch(
            RunnableCallable(tools_condition),
            "b",
            router,
            trust=NodeTrust.TRUSTED,
            descriptor=branch,
        )
    assert type(MediatedNode(node, spec, router, descriptor=program)) is MediatedNode
    assert (
        type(
            MediatedBranch(
                path, "b", router, trust=NodeTrust.TRUSTED, descriptor=branch
            )
        )
        is MediatedBranch
    )
