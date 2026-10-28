"""Closed admission of LLM calls: an allowlisted chat model behind the model hook.

The hook decides the capability to call the model (allow/deny before the call);
it makes no claim about prompt or reply content.
"""

from __future__ import annotations

import shutil
from typing import Any

import pytest
from langchain_core.language_models.fake_chat_models import (
    FakeListChatModel,
    GenericFakeChatModel,
)
from langchain_core.messages import AIMessage, HumanMessage
from langgraph._internal import _runtime_policy
from langgraph.graph import END, START, MessagesState, StateGraph

from langgraph.prebuilt.security import (
    Decision,
    Principal,
    SecurityConfig,
    SecurityModule,
    Verdict,
    install_mac_policy,
    with_principal,
)
from langgraph.prebuilt.security.admission import (
    AdmittedKind,
    admit_node,
    describe,
    recheck,
)
from langgraph.prebuilt.security.errors import SecurityConfigurationError
from langgraph.prebuilt.security.mac import _graph_boundaries, _MacBoundary
from langgraph.prebuilt.security.placement import (
    MediatedNode,
    NodeKind,
    NodeTrust,
    resolve_placement,
)

requires_cedar = pytest.mark.skipif(
    shutil.which("cedar") is None, reason="Cedar CLI required"
)
FAKE_ID = "langchain_core.language_models.fake_chat_models:FakeListChatModel"


@pytest.fixture(autouse=True)
def isolated_runtime(monkeypatch):
    monkeypatch.delenv("LANGGRAPH_MAC_DIR", raising=False)
    monkeypatch.setattr(_runtime_policy, "_policy", None)
    monkeypatch.setattr(_runtime_policy, "_started", False)
    monkeypatch.setattr(_runtime_policy, "_system_loaded", True)


class ModelPolicy(SecurityModule):
    """Decide the capability to call the model; record every hook call."""

    name = "model_policy"

    def __init__(self, verdict: Verdict) -> None:
        self.verdict = verdict
        self.models: list[str] = []

    def model_invoke(self, principal, request):
        self.models.append(request.model)
        return Decision(self.verdict, f"test:model-{self.verdict.value}")


def secured(node: Any, policy: ModelPolicy, *, closed: bool = True):
    builder = StateGraph(MessagesState)
    builder.add_node("model", node)
    builder.add_edge(START, "model")
    builder.add_edge("model", END)
    security = SecurityConfig(modules=(policy,), closed_admission=closed)
    return builder.compile(security=security), security


def principal_config(security: SecurityConfig):
    return with_principal(
        {},
        Principal("alice", frozenset(), frozenset(), "session"),
        modules=security.modules,
    )


async def run(graph, security, asynchronous: bool) -> Any:
    state = {"messages": [HumanMessage("hello")]}
    config = principal_config(security)
    if asynchronous:
        return await graph.ainvoke(state, config)
    return graph.invoke(state, config)


def fake() -> FakeListChatModel:
    # `i` counts completed model calls (it advances once per response).
    return FakeListChatModel(responses=["first", "second", "third"])


@pytest.mark.parametrize("asynchronous", [False, True])
async def test_policy_allow_runs_the_admitted_model(asynchronous: bool) -> None:
    model = fake()
    policy = ModelPolicy(Verdict.ALLOW)
    graph, security = secured(model, policy)

    mediated = graph.builder.nodes["model"].runnable
    assert type(mediated) is MediatedNode
    assert mediated.runnable is model
    assert mediated.spec.kind is NodeKind.MODEL
    assert mediated.spec.trust is NodeTrust.TRUSTED
    assert mediated.descriptor.kind is AdmittedKind.MODEL_CALL

    result = await run(graph, security, asynchronous)

    reply = result["messages"][-1]
    assert type(reply) is AIMessage
    assert reply.content == "first"
    assert model.i == 1
    assert policy.models == ["model"]


@pytest.mark.parametrize("asynchronous", [False, True])
async def test_policy_deny_refuses_before_the_model_is_called(
    asynchronous: bool,
) -> None:
    model = fake()
    policy = ModelPolicy(Verdict.DENY)
    graph, security = secured(model, policy)

    with pytest.raises(PermissionError, match="test:model-deny"):
        await run(graph, security, asynchronous)

    assert model.i == 0
    assert policy.models == ["model"]


def test_function_node_calling_an_llm_is_refused_at_compile() -> None:
    model = fake()

    def call_llm(state: MessagesState) -> dict[str, Any]:
        return {"messages": [model.invoke(state["messages"])]}

    with pytest.raises(PermissionError, match="admission:unsupported_node_body"):
        secured(call_llm, ModelPolicy(Verdict.ALLOW))
    assert model.i == 0


class LocalChatModel(FakeListChatModel):
    """A subclass of an allowlisted class: not the class by identity."""


class MyLLMChatModel(GenericFakeChatModel):
    """Name heuristics ("llm"/"chatmodel") must not admit it."""


@pytest.mark.parametrize(
    "build",
    [
        lambda: LocalChatModel(responses=["x"]),
        lambda: MyLLMChatModel(messages=iter([AIMessage("x")])),
        lambda: fake().bind(stop=["never"]),
        lambda: fake() | (lambda message: {"messages": [message]}),
    ],
    ids=["subclass", "name-heuristic", "binding", "sequence"],
)
def test_non_allowlisted_model_shapes_are_refused(build) -> None:
    with pytest.raises(PermissionError, match="admission:unsupported_node_body"):
        secured(build(), ModelPolicy(Verdict.ALLOW))


def test_model_with_callbacks_is_refused() -> None:
    model = FakeListChatModel(responses=["x"], callbacks=[])
    with pytest.raises(PermissionError, match="admission:unsupported_node_body"):
        admit_node("model", model, config=SecurityConfig(closed_admission=True))


def test_descriptor_identity_covers_class_and_endpoint_fields() -> None:
    config = SecurityConfig(closed_admission=True)
    first = admit_node("model", fake(), config=config)
    second = admit_node("model", fake(), config=config)
    assert first.kind is AdmittedKind.MODEL_CALL
    assert first.identity == second.identity
    projected = describe(first)
    assert projected["details"]["class"] == FAKE_ID
    assert projected["details"]["endpoint"] == {}
    other = admit_node(
        "model", GenericFakeChatModel(messages=iter([AIMessage("x")])), config=config
    )
    assert other.identity != first.identity
    recheck(first)


def _swap_model(graph, model) -> None:
    graph.builder.nodes["model"].runnable.runnable = fake()


def _swap_class(graph, model) -> None:
    object.__setattr__(model, "__class__", LocalChatModel)


def _swap_endpoint(graph, model) -> None:
    model.__dict__["base_url"] = "http://attacker.invalid"


def _set_callbacks(graph, model) -> None:
    model.__dict__["callbacks"] = []


@pytest.mark.parametrize(
    "swap", [_swap_model, _swap_class, _swap_endpoint, _set_callbacks]
)
@pytest.mark.parametrize("asynchronous", [False, True])
async def test_post_admission_swap_refuses_before_any_call(
    swap, asynchronous: bool
) -> None:
    model = fake()
    policy = ModelPolicy(Verdict.ALLOW)
    graph, security = secured(model, policy)
    swap(graph, model)

    with pytest.raises(PermissionError, match="admission:descriptor_changed"):
        await run(graph, security, asynchronous)

    assert model.i == 0
    assert policy.models == []


@pytest.mark.parametrize("asynchronous", [False, True])
async def test_openai_endpoint_change_refuses_before_any_call(
    asynchronous: bool,
) -> None:
    openai = pytest.importorskip("langchain_openai")
    model = openai.ChatOpenAI(
        model="gpt-4o-mini", api_key="test", base_url="http://127.0.0.1:9/v1"
    )
    policy = ModelPolicy(Verdict.ALLOW)
    graph, security = secured(model, policy)
    descriptor = graph.builder.nodes["model"].runnable.descriptor
    assert describe(descriptor)["details"]["endpoint"]["model_name"] == "gpt-4o-mini"

    model.__dict__["model_name"] = "gpt-4o"

    with pytest.raises(PermissionError, match="admission:descriptor_changed"):
        await run(graph, security, asynchronous)
    assert policy.models == []


def test_default_path_keeps_the_legacy_model_placement() -> None:
    # Without closed admission the legacy heuristics still place an imported
    # model as untrusted, which needs a separate-process host.
    with pytest.raises(
        SecurityConfigurationError, match="untrusted node requires a separate"
    ):
        secured(fake(), ModelPolicy(Verdict.ALLOW), closed=False)
    assert resolve_placement("model", fake(), None).kind is NodeKind.MODEL


@requires_cedar
def test_runtime_mac_binds_the_admitted_model_node() -> None:
    model = fake()
    graph, _ = secured(model, ModelPolicy(Verdict.ALLOW))
    install_mac_policy(
        'forbid(principal, action == slangGraph::Action::"fs::read", resource);'
    )
    _runtime_policy.check_runtime_policy(graph)
    boundary = _graph_boundaries[graph]
    assert type(boundary) is _MacBoundary
    assert [entry[2].kind for entry in boundary.nodes] == [AdmittedKind.MODEL_CALL]

    model.__dict__["base_url"] = "http://attacker.invalid"
    with pytest.raises(PermissionError, match="admission:descriptor_changed"):
        _runtime_policy.check_runtime_policy(graph)
