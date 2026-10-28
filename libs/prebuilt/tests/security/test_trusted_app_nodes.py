"""Closed admission of declared trusted application nodes (advisor decision D11).

Developer node functions are trusted code: a deployer declares them by exact
name and closed admission binds their identity into the inventory. Tool
implementations stay contained (they run only through `HostRouter`), and an
allowlisted model keeps its model hook. Binding identity is not a claim that
the trusted code is safe.
"""

from __future__ import annotations

import shutil
from dataclasses import replace
from functools import partial
from pathlib import Path
from typing import Any

import pytest
from langchain_core.language_models.fake_chat_models import FakeListChatModel
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langchain_core.runnables import RunnableConfig, RunnableLambda
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
    install_mac_policy,
    with_principal,
)
from langgraph.prebuilt.security.admission import (
    AdmittedKind,
    admit_node,
    describe,
    recheck,
)
from langgraph.prebuilt.security.host_router import HostRouter
from langgraph.prebuilt.security.inprocess import read_text
from langgraph.prebuilt.security.mac import _graph_boundaries, _MacBoundary
from langgraph.prebuilt.security.placement import MediatedNode, NodeKind, NodeTrust
from tests.security.test_manifest_admission import MANIFEST, PERMIT

requires_cedar = pytest.mark.skipif(
    shutil.which("cedar") is None, reason="Cedar CLI required"
)
TRUSTED = frozenset({"prepare", "route", "finish"})


@pytest.fixture(autouse=True)
def isolated_runtime(monkeypatch):
    monkeypatch.delenv("LANGGRAPH_MAC_DIR", raising=False)
    monkeypatch.setattr(_runtime_policy, "_policy", None)
    monkeypatch.setattr(_runtime_policy, "_started", False)
    monkeypatch.setattr(_runtime_policy, "_system_loaded", True)


def spy_router(monkeypatch) -> list[str]:
    """Record every tool call that reaches `HostRouter`.

    Installed after compile: compile verifies the exact router source.
    """
    seen: list[str] = []
    invoke = HostRouter.invoke
    ainvoke = HostRouter.ainvoke

    def spy(self, principal, call):
        seen.append(call.tool.name)
        return invoke(self, principal, call)

    async def aspy(self, principal, call):
        seen.append(call.tool.name)
        return await ainvoke(self, principal, call)

    monkeypatch.setattr(HostRouter, "invoke", spy)
    monkeypatch.setattr(HostRouter, "ainvoke", aspy)
    return seen


class State(MessagesState):
    path: str
    answer: str


class Record(SecurityModule):
    """Allow and record dispatch, state writes and model invocations."""

    name = "record"

    def __init__(self) -> None:
        self.transfers: list[str] = []
        self.writes: list[str] = []
        self.models: list[str] = []
        self.tools: list[str] = []

    def cred_transfer(self, parent, child, slot):
        self.transfers.append(child.user_id)
        return Decision(Verdict.ALLOW, "record:dispatch")

    def state_write(self, principal, request):
        self.writes.append(request.resource)
        return Decision(Verdict.ALLOW, "record:write")

    def model_invoke(self, principal, request):
        self.models.append(request.model)
        return Decision(Verdict.ALLOW, "record:model")

    def tool_call_permission(self, principal, call):
        self.tools.append(call.tool.name)
        return Decision(Verdict.ALLOW, "record:tool")


def local_tool():
    @tool
    def admitted_reader(path: str) -> str:
        """Read through the official resource API."""
        return read_text(path)

    return admitted_reader


class App:
    """The developer's graph: trusted node functions around a model and a tool."""

    def __init__(self, candidate: Any, *, asynchronous_finish: bool) -> None:
        self.calls: list[str] = []
        self.configs: list[Any] = []
        self.model = FakeListChatModel(responses=["read the file", "unused"])
        self.tools = ToolNode([candidate])
        calls = self.calls
        configs = self.configs
        name = candidate.name

        def prepare(state: State, config: RunnableConfig) -> dict[str, Any]:
            calls.append("prepare")
            configs.append(config)
            return {"messages": [HumanMessage("summarize " + state["path"])]}

        def route(state: State) -> dict[str, Any]:
            calls.append("route")
            reply = state["messages"][-1].content
            call = {"name": name, "args": {"path": state["path"]}, "id": "read"}
            return {"messages": [AIMessage(content=reply, tool_calls=[call])]}

        def finish(state: State) -> dict[str, Any]:
            calls.append("finish")
            return {"answer": state["messages"][-1].content}

        async def afinish(state: State) -> dict[str, Any]:
            calls.append("afinish")
            return {"answer": state["messages"][-1].content}

        self.prepare = prepare
        self.route = route
        self.finish = afinish if asynchronous_finish else finish

    def builder(self) -> StateGraph:
        builder = StateGraph(State)
        builder.add_node("prepare", self.prepare)
        builder.add_node("model", self.model)
        builder.add_node("route", self.route)
        builder.add_node("tools", self.tools)
        builder.add_node("finish", self.finish)
        builder.add_edge(START, "prepare")
        builder.add_edge("prepare", "model")
        builder.add_edge("model", "route")
        builder.add_edge("route", "tools")
        builder.add_edge("tools", "finish")
        builder.add_edge("finish", END)
        return builder


def security_for(candidate, record: Record, declared: frozenset[str] = TRUSTED):
    security = cedar_security(
        candidate, manifest=MANIFEST, policy=PERMIT, modules=(record,)
    )
    return replace(security, closed_admission=True, trusted_application_nodes=declared)


def principal_config(security: SecurityConfig) -> Any:
    return with_principal(
        {},
        Principal("alice", frozenset(), frozenset(), "session"),
        modules=security.modules,
    )


async def run(graph, security, path: Path, asynchronous: bool) -> Any:
    state = {"messages": [], "path": str(path), "answer": ""}
    config = principal_config(security)
    if asynchronous:
        return await graph.ainvoke(state, config)
    return graph.invoke(state, config)


def compiled(tmp_path: Path, *, asynchronous: bool = False, declared=TRUSTED):
    path = tmp_path / "data"
    path.write_text("fixture")
    candidate = local_tool()
    app = App(candidate, asynchronous_finish=asynchronous)
    record = Record()
    security = security_for(candidate, record, declared)
    graph = app.builder().compile(security=security)
    return graph, security, app, record, path


# --- positive: the whole application runs under closed admission ------------


@requires_cedar
@pytest.mark.parametrize("asynchronous", [False, True])
async def test_declared_application_runs_end_to_end(
    tmp_path: Path, asynchronous: bool, monkeypatch
) -> None:
    graph, security, app, record, path = compiled(tmp_path, asynchronous=asynchronous)
    routed = spy_router(monkeypatch)

    kinds = {d.name: d.kind for d in graph.builder._security_admission}
    assert kinds == {
        "prepare": AdmittedKind.TRUSTED_APPLICATION,
        "model": AdmittedKind.MODEL_CALL,
        "route": AdmittedKind.TRUSTED_APPLICATION,
        "tools": AdmittedKind.LANGUAGE_PROGRAM,
        "finish": AdmittedKind.TRUSTED_APPLICATION,
    }
    for name in TRUSTED:
        mediated = graph.builder.nodes[name].runnable
        assert type(mediated) is MediatedNode
        assert mediated.spec.trust is NodeTrust.TRUSTED
        assert mediated.spec.kind is NodeKind.STANDARD
        assert mediated.descriptor.implementation.node is mediated.runnable

    result = await run(graph, security, path, asynchronous)

    assert result["answer"] == "fixture"
    assert type(result["messages"][-1]) is ToolMessage
    finish = "afinish" if asynchronous else "finish"
    assert app.calls == ["prepare", "route", finish]
    # The trusted body received the normal (not narrowed) config.
    assert "configurable" in app.configs[0]
    assert "callbacks" in app.configs[0]
    # The model ran once behind its hook; the tool ran only through HostRouter.
    assert app.model.i == 1 and record.models == ["model"]
    assert routed == ["admitted_reader"]
    assert record.tools == ["admitted_reader"]
    assert set(record.transfers) == {"alice"}
    assert {"messages", "answer"} <= set(record.writes)
    with pytest.raises(PermissionError, match="resource_not_granted"):
        read_text(str(path))


@requires_cedar
def test_sync_run_of_an_async_only_trusted_body_refuses(tmp_path: Path) -> None:
    graph, security, app, _, path = compiled(tmp_path, asynchronous=True)
    state = {"messages": [], "path": str(path), "answer": ""}
    with pytest.raises(PermissionError, match="admission:unsupported_async"):
        graph.invoke(state, principal_config(security))
    assert "afinish" not in app.calls


# --- refusals: nothing is inferred, tools are never trusted ------------------


@requires_cedar
def test_undeclared_function_refuses_before_any_body_runs(tmp_path: Path) -> None:
    with pytest.raises(PermissionError, match="admission:unsupported_node_body"):
        compiled(tmp_path, declared=frozenset({"prepare", "finish"}))


@requires_cedar
def test_declaring_a_tool_node_trusted_refuses(tmp_path: Path) -> None:
    candidate = local_tool()
    app = App(candidate, asynchronous_finish=False)
    record = Record()
    security = security_for(candidate, record, TRUSTED | {"tools"})
    with pytest.raises(PermissionError, match="admission:unsupported_node_body"):
        app.builder().compile(security=security)
    with pytest.raises(PermissionError, match="admission:unsupported_node_body"):
        admit_node("tools", app.tools, config=security)
    assert app.calls == [] and record.transfers == []


@requires_cedar
def test_declared_model_keeps_its_model_kind_and_hook(tmp_path: Path) -> None:
    graph, security, app, record, path = compiled(
        tmp_path, declared=TRUSTED | {"model"}
    )
    mediated = graph.builder.nodes["model"].runnable
    assert mediated.descriptor.kind is AdmittedKind.MODEL_CALL
    assert mediated.spec.kind is NodeKind.MODEL
    graph.invoke(
        {"messages": [], "path": str(path), "answer": ""}, principal_config(security)
    )
    assert record.models == ["model"]


@requires_cedar
def test_declared_name_that_is_not_a_node_refuses(tmp_path: Path) -> None:
    with pytest.raises(PermissionError, match="admission:unsupported_node_body"):
        compiled(tmp_path, declared=TRUSTED | {"missing"})


def plain(state: dict[str, Any]) -> dict[str, Any]:
    return {}


class Holder:
    def method(self, state: dict[str, Any]) -> dict[str, Any]:
        return {}

    def __call__(self, state: dict[str, Any]) -> dict[str, Any]:
        return {}


def generator(state: dict[str, Any]):
    yield {}


@pytest.mark.parametrize(
    "body",
    [
        RunnableLambda(plain),
        RunnableCallable(Holder().method),
        RunnableCallable(partial(plain)),
        RunnableCallable(Holder()),
        RunnableCallable(plain, plain),
        RunnableCallable(plain, explode_args=True),
        RunnableCallable(plain, extra=1),
        RunnableLambda(generator),
        FakeListChatModel(responses=["x"]).bind(stop=["never"]),
    ],
    ids=[
        "lambda-runnable",
        "bound-method",
        "partial",
        "callable-object",
        "foreign-afunc",
        "explode-args",
        "bound-kwargs",
        "generator",
        "binding",
    ],
)
def test_declared_bodies_outside_the_plain_function_shape_refuse(body) -> None:
    config = SecurityConfig(
        closed_admission=True, trusted_application_nodes=frozenset({"node"})
    )
    with pytest.raises(PermissionError, match="admission:unsupported_node_body"):
        admit_node("node", body, config=config)


def test_identity_binds_name_and_code_not_safety() -> None:
    def other(state: dict[str, Any]) -> dict[str, Any]:
        return {"x": 1}

    config = SecurityConfig(
        closed_admission=True, trusted_application_nodes=frozenset({"a", "b"})
    )
    first = admit_node("a", RunnableCallable(plain, partial_shim(plain)), config=config)
    again = admit_node("a", RunnableCallable(plain, partial_shim(plain)), config=config)
    renamed = admit_node(
        "b", RunnableCallable(plain, partial_shim(plain)), config=config
    )
    changed = admit_node(
        "a", RunnableCallable(other, partial_shim(other)), config=config
    )
    assert first.kind is AdmittedKind.TRUSTED_APPLICATION
    assert first.identity == again.identity
    assert len({first.identity, renamed.identity, changed.identity}) == 3
    details = describe(first)["details"]
    assert details["name"] == "a"
    assert details["module"] == __name__
    assert details["qualname"] == "plain"
    assert details["async"] is False
    recheck(first)
    # Undeclared names still refuse even with a non-empty declaration.
    with pytest.raises(PermissionError, match="admission:unsupported_node_body"):
        admit_node("c", RunnableCallable(plain, partial_shim(plain)), config=config)


def partial_shim(function):
    return partial(run_in_executor, None, function)


# --- post-compile swaps refuse before the trusted body runs ------------------


def _swap_func(graph, app) -> None:
    def replacement(state, config: RunnableConfig):
        app.calls.append("replacement")
        return {}

    graph.builder.nodes["prepare"].runnable.runnable.func = replacement


def _swap_code(graph, app) -> None:
    calls = app.calls
    configs = app.configs

    def replacement(state, config: RunnableConfig):
        calls.append("replacement")
        configs.append(config)
        return {}

    app.prepare.__code__ = replacement.__code__


def _swap_runnable(graph, app) -> None:
    def replacement(state):
        app.calls.append("replacement")
        return {}

    graph.builder.nodes["prepare"].runnable.runnable = RunnableCallable(replacement)


def _bind_kwargs(graph, app) -> None:
    graph.builder.nodes["prepare"].runnable.runnable.kwargs["extra"] = 1


@requires_cedar
@pytest.mark.parametrize("swap", [_swap_func, _swap_code, _swap_runnable, _bind_kwargs])
@pytest.mark.parametrize("asynchronous", [False, True])
async def test_swapped_trusted_body_refuses_before_it_runs(
    tmp_path: Path, swap, asynchronous: bool
) -> None:
    graph, security, app, record, path = compiled(tmp_path, asynchronous=asynchronous)
    swap(graph, app)
    with pytest.raises(PermissionError, match="admission:descriptor_changed"):
        await run(graph, security, path, asynchronous)
    assert app.calls == []
    assert app.model.i == 0 and record.models == []


# --- runtime MAC ---------------------------------------------------------------


@requires_cedar
def test_runtime_mac_accepts_and_binds_trusted_application_nodes(
    tmp_path: Path,
) -> None:
    graph, security, app, _, path = compiled(tmp_path)
    install_mac_policy(
        'forbid(principal, action == slangGraph::Action::"fs::write", resource);'
    )
    _runtime_policy.check_runtime_policy(graph)
    boundary = _graph_boundaries[graph]
    assert type(boundary) is _MacBoundary
    kinds = sorted(entry[2].kind.value for entry in boundary.nodes)
    assert kinds.count(AdmittedKind.TRUSTED_APPLICATION.value) == 3
    result = graph.invoke(
        {"messages": [], "path": str(path), "answer": ""}, principal_config(security)
    )
    assert result["answer"] == "fixture"

    # A compiled node rebound to another wrapper is refused.
    original = graph.nodes["route"].bound
    graph.nodes["route"].bound = graph.nodes["prepare"].bound
    with pytest.raises(PermissionError, match="admission:descriptor_changed"):
        _runtime_policy.check_runtime_policy(graph)
    graph.nodes["route"].bound = original
    _runtime_policy.check_runtime_policy(graph)

    # A swapped trusted function is refused by the MAC recheck too.
    def replacement(state):
        return {}

    graph.builder.nodes["route"].runnable.runnable.func = replacement
    with pytest.raises(PermissionError, match="admission:descriptor_changed"):
        _runtime_policy.check_runtime_policy(graph)


# --- default path ------------------------------------------------------------


def test_default_path_is_unchanged() -> None:
    assert SecurityConfig().trusted_application_nodes == frozenset()
    calls: list[str] = []

    def node(state: State) -> dict[str, Any]:
        calls.append("node")
        return {"answer": "done"}

    builder = StateGraph(State)
    builder.add_node("node", node)
    builder.add_edge(START, "node")
    builder.add_edge("node", END)
    security = SecurityConfig()
    graph = builder.compile(security=security)
    mediated = graph.builder.nodes["node"].runnable
    assert type(mediated) is MediatedNode and mediated.descriptor is None
    assert not hasattr(graph.builder, "_security_admission")
    result = graph.invoke(
        {"messages": [], "path": "", "answer": ""}, principal_config(security)
    )
    assert result["answer"] == "done" and calls == ["node"]


# --- trusted application branches ---------------------------------------------


class Route(TypedDict):
    value: str
    taken: str


ROUTER = "start:branch:router_chart_or_table"
LAMBDA = "table:branch:condition"
BRANCH_NODES = frozenset({"start", "chart", "table", "fix"})


class RoutedApp:
    """Developer graph whose conditional edges are a closure and a lambda."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        calls = self.calls

        def make_router():
            def router_chart_or_table(state: Route) -> str:
                calls.append("router")
                return "chart" if state["value"] == "chart" else "table"

            return router_chart_or_table

        self.router = make_router()
        self.condition = lambda state: (
            "fix_code" if state["value"] == "broken" else "explain_code"
        )

        def start(state: Route) -> dict[str, Any]:
            calls.append("start")
            return {"taken": "start"}

        def chart(state: Route) -> dict[str, Any]:
            calls.append("chart")
            return {"taken": "chart"}

        def table(state: Route) -> dict[str, Any]:
            calls.append("table")
            return {"taken": "table"}

        def fix(state: Route) -> dict[str, Any]:
            calls.append("fix")
            return {"taken": "fix"}

        self.nodes = {"start": start, "chart": chart, "table": table, "fix": fix}

    def builder(self) -> StateGraph:
        builder = StateGraph(Route)
        for name, function in self.nodes.items():
            builder.add_node(name, function)
        builder.add_edge(START, "start")
        builder.add_conditional_edges(
            "start", self.router, {"chart": "chart", "table": "table"}
        )
        builder.add_conditional_edges(
            "table", self.condition, {"fix_code": "fix", "explain_code": END}
        )
        builder.add_edge("chart", END)
        builder.add_edge("fix", END)
        return builder


def branch_security(
    branches=frozenset({ROUTER, LAMBDA}), *, closed: bool = True
) -> SecurityConfig:
    if not closed:
        return SecurityConfig(modules=(Record(),))
    return SecurityConfig(
        modules=(Record(),),
        closed_admission=True,
        trusted_application_nodes=BRANCH_NODES,
        trusted_application_branches=branches,
    )


async def route(graph, security, value: str, asynchronous: bool) -> Any:
    state = {"value": value, "taken": ""}
    config = principal_config(security)
    if asynchronous:
        return await graph.ainvoke(state, config)
    return graph.invoke(state, config)


@pytest.mark.parametrize("asynchronous", [False, True])
async def test_declared_closure_and_lambda_branches_route(asynchronous: bool) -> None:
    app = RoutedApp()
    security = branch_security()
    graph = app.builder().compile(security=security)
    kinds = {d.name: d.kind for d in graph.builder._security_admission}
    assert kinds[ROUTER] is AdmittedKind.TRUSTED_APPLICATION_BRANCH
    assert kinds[LAMBDA] is AdmittedKind.TRUSTED_APPLICATION_BRANCH
    details = describe(
        graph.builder.branches["start"]["router_chart_or_table"].path.descriptor
    )
    assert details["details"]["qualname"].endswith(
        "make_router.<locals>.router_chart_or_table"
    )
    assert details["details"]["ends"] == [["chart", "chart"], ["table", "table"]]

    assert (await route(graph, security, "chart", asynchronous))["taken"] == "chart"
    assert app.calls == ["start", "router", "chart"]
    app.calls.clear()
    assert (await route(graph, security, "broken", asynchronous))["taken"] == "fix"
    assert app.calls == ["start", "router", "table", "fix"]
    app.calls.clear()
    assert (await route(graph, security, "ok", asynchronous))["taken"] == "table"
    assert app.calls == ["start", "router", "table"]


@pytest.mark.parametrize("declared", [frozenset({ROUTER}), frozenset({LAMBDA})])
def test_undeclared_custom_branch_refuses(declared) -> None:
    with pytest.raises(PermissionError, match="admission:unsupported_branch"):
        RoutedApp().builder().compile(security=branch_security(declared))


@pytest.mark.parametrize(
    "declared",
    [
        frozenset({ROUTER, LAMBDA, "start:branch:missing"}),
        frozenset({ROUTER, LAMBDA, "start:router_chart_or_table"}),
        frozenset({ROUTER, LAMBDA, "start"}),
    ],
    ids=["missing-branch", "wrong-format", "node-name"],
)
def test_declarations_naming_no_branch_refuse(declared) -> None:
    with pytest.raises(PermissionError, match="admission:unsupported_branch"):
        RoutedApp().builder().compile(security=branch_security(declared))


def test_declared_framework_or_async_branch_refuses() -> None:
    def agent(state: MessagesState) -> dict[str, Any]:
        return {}

    async def arouter(state: MessagesState) -> str:
        return END

    for path, branch in ((tools_condition, "tools_condition"), (arouter, "arouter")):
        builder = StateGraph(MessagesState)
        builder.add_node("agent", agent)
        builder.add_edge(START, "agent")
        builder.add_conditional_edges("agent", path, [END])
        security = SecurityConfig(
            closed_admission=True,
            trusted_application_nodes=frozenset({"agent"}),
            trusted_application_branches=frozenset({f"agent:branch:{branch}"}),
        )
        with pytest.raises(PermissionError, match="admission:unsupported_branch"):
            builder.compile(security=security)


def _swap_path_func(graph, app) -> None:
    def replacement(state):
        app.calls.append("replacement")
        return "table"

    graph.builder.branches["start"][
        "router_chart_or_table"
    ].path.runnable.func = replacement


def _swap_branch_code(graph, app) -> None:
    calls = app.calls

    def replacement(state):
        calls.append("replacement")
        return "table"

    app.router.__code__ = replacement.__code__


def _swap_ends(graph, app) -> None:
    graph.builder.branches["start"]["router_chart_or_table"].ends["chart"] = "fix"


def _swap_mediated_path(graph, app) -> None:
    def replacement(state):
        app.calls.append("replacement")
        return "table"

    mediated = graph.builder.branches["start"]["router_chart_or_table"].path
    mediated.runnable = RunnableCallable(replacement, partial_shim(replacement))


@pytest.mark.parametrize(
    "swap", [_swap_path_func, _swap_branch_code, _swap_ends, _swap_mediated_path]
)
@pytest.mark.parametrize("asynchronous", [False, True])
async def test_swapped_trusted_branch_refuses_before_it_runs(
    swap, asynchronous: bool
) -> None:
    app = RoutedApp()
    security = branch_security()
    graph = app.builder().compile(security=security)
    swap(graph, app)
    with pytest.raises(PermissionError, match="admission:descriptor_changed"):
        await route(graph, security, "chart", asynchronous)
    assert "router" not in app.calls and "replacement" not in app.calls
    assert "chart" not in app.calls


@requires_cedar
def test_runtime_mac_binds_trusted_branches_through_compiled_writers() -> None:
    app = RoutedApp()
    security = branch_security()
    graph = app.builder().compile(security=security)
    install_mac_policy(
        'forbid(principal, action == slangGraph::Action::"fs::write", resource);'
    )
    _runtime_policy.check_runtime_policy(graph)
    boundary = _graph_boundaries[graph]
    assert type(boundary) is _MacBoundary
    assert sorted((entry[0], entry[1]) for entry in boundary.branches) == [
        ("start:branch:router_chart_or_table", "start"),
        ("table:branch:condition", "table"),
    ]
    assert {entry[3].kind for entry in boundary.branches} == {
        AdmittedKind.TRUSTED_APPLICATION_BRANCH
    }
    assert route_sync(graph, security, "chart")["taken"] == "chart"

    # A compiled writer that no longer carries the captured branch is refused.
    writers = graph.nodes["table"].writers
    graph.nodes["table"].writers = [
        w for w in writers if type(w) is not RunnableCallable
    ]
    with pytest.raises(PermissionError, match="admission:descriptor_changed"):
        _runtime_policy.check_runtime_policy(graph)
    graph.nodes["table"].writers = writers
    _runtime_policy.check_runtime_policy(graph)

    def replacement(state):
        return "table"

    graph.builder.branches["start"][
        "router_chart_or_table"
    ].path.runnable.func = replacement
    with pytest.raises(PermissionError, match="admission:descriptor_changed"):
        _runtime_policy.check_runtime_policy(graph)


def route_sync(graph, security, value: str) -> Any:
    return graph.invoke({"value": value, "taken": ""}, principal_config(security))


def test_default_path_routes_custom_branches_unchanged() -> None:
    app = RoutedApp()
    security = branch_security(closed=False)
    graph = app.builder().compile(security=security)
    mediated = graph.builder.branches["start"]["router_chart_or_table"].path
    assert mediated.descriptor is None
    assert route_sync(graph, security, "chart")["taken"] == "chart"
    assert app.calls == ["start", "router", "chart"]
