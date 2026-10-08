from __future__ import annotations

from typing import Any

import pytest
from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.runnables import Runnable, RunnableConfig
from langchain_core.tools import tool
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Send
from typing_extensions import NotRequired, TypedDict

from langgraph.prebuilt import create_react_agent
from langgraph.prebuilt.security import (
    Decision,
    EscalationRequest,
    LabeledValue,
    MemoryAuditSink,
    Principal,
    SecurityConfig,
    SecurityConfigurationError,
    SecurityLabels,
    SecurityModule,
    Verdict,
    with_principal,
)
from langgraph.prebuilt.security.placement import (
    MediatedBranch,
    MediatedNode,
    OutputApprovalRequired,
)
from tests.model import FakeToolCallingModel


class PlacementState(TypedDict):
    value: NotRequired[str]
    public: NotRequired[str]
    secret: NotRequired[str]
    seen: NotRequired[str]


def _principal() -> Principal:
    return Principal("alice", frozenset({"user"}), frozenset(), "session")


def _config() -> RunnableConfig:
    return with_principal(
        {"configurable": {"thread_id": "placement-thread"}}, _principal()
    )


class RecordPlacement(SecurityModule):
    name = "record"

    def __init__(self) -> None:
        self.transfers: list[str] = []
        self.writes: list[str] = []
        self.outputs = 0

    def cred_transfer(self, parent, child, slot):
        self.transfers.append(child.user_id)
        return Decision(Verdict.ALLOW, "record:dispatch")

    def state_write(self, principal, request):
        self.writes.append(request.resource)
        return Decision(Verdict.ALLOW, "record:write")

    def output_emit(self, principal, request):
        self.outputs += 1
        return Decision(Verdict.ALLOW, "record:output")


def update_value(state: PlacementState) -> PlacementState:
    return {"value": state.get("value", "") + "!"}


def test_secured_react_agent_places_hooks_nodes_and_conditional_edges() -> None:
    @tool
    def lookup(query: str) -> str:
        """Look up one test value."""
        return query

    def pre_model_hook(state):
        return None

    def post_model_hook(state):
        return None

    graph = create_react_agent(
        FakeToolCallingModel(),
        [lookup],
        pre_model_hook=pre_model_hook,
        post_model_hook=post_model_hook,
        security=SecurityConfig(untrusted_node_host=FakeProcessHost()),
    )

    assert all(
        isinstance(node.runnable, MediatedNode) for node in graph.builder.nodes.values()
    )
    assert all(
        isinstance(branch.path, MediatedBranch)
        for branches in graph.builder.branches.values()
        for branch in branches.values()
    )


@pytest.mark.parametrize("asynchronous", [False, True])
async def test_compile_places_dispatch_state_write_and_every_output(
    asynchronous: bool,
) -> None:
    record = RecordPlacement()
    builder = StateGraph(PlacementState)
    builder.add_node("update", update_value)
    builder.add_edge(START, "update")
    builder.add_edge("update", END)
    graph = builder.compile(security=SecurityConfig(modules=(record,)))

    result = (
        await graph.ainvoke({"value": "a"}, _config())
        if asynchronous
        else graph.invoke({"value": "a"}, _config())
    )

    assert result["value"] == "a!"
    assert record.transfers == ["alice"]
    assert record.writes == ["value"]
    assert record.outputs >= 1


class DenyWrites(SecurityModule):
    name = "deny_writes"

    def state_write(self, principal, request):
        return Decision(Verdict.DENY, "test:no_state_write")


def test_state_write_hook_refuses_graph_update() -> None:
    builder = StateGraph(PlacementState)
    builder.add_node("update", update_value)
    builder.add_edge(START, "update")
    builder.add_edge("update", END)
    graph = builder.compile(security=SecurityConfig(modules=(DenyWrites(),)))

    with pytest.raises(PermissionError, match="test:no_state_write"):
        graph.invoke({"value": "a"}, _config())


class StripModelSecret(SecurityModule):
    name = "strip_model_secret"

    def model_invoke(self, principal, request):
        context = tuple(item for item in request.context if item.name != "secret")
        return Decision(
            Verdict.TRANSFORM,
            "test:strip",
            new_args={"context": context},
        )


def model_node(state: PlacementState) -> PlacementState:
    assert "secret" not in state
    return {"seen": state["public"]}


@pytest.mark.parametrize("asynchronous", [False, True])
async def test_model_node_context_is_stripped_before_prompt_assembly(
    asynchronous: bool,
) -> None:
    builder = StateGraph(PlacementState)
    builder.add_node("model", model_node, metadata={"security_kind": "model"})
    builder.add_edge(START, "model")
    builder.add_edge("model", END)
    graph = builder.compile(
        security=SecurityConfig(
            modules=(StripModelSecret(),),
            output_clearance=frozenset({"secret"}),
        )
    )
    initial = {
        "public": "hello",
        "secret": LabeledValue(
            "secret",
            "token",
            SecurityLabels(confidentiality=frozenset({"secret"})),
        ),
    }

    result = (
        await graph.ainvoke(initial, _config())
        if asynchronous
        else graph.invoke(initial, _config())
    )

    assert result["seen"] == "hello"


class RedactSecretOutput(SecurityModule):
    name = "redact_secret_output"

    def output_emit(self, principal, request):
        if "secret" not in request.labels.confidentiality:
            return Decision(Verdict.ALLOW, "test:public")
        return Decision(
            Verdict.REDACT,
            "test:redact",
            new_args={"content": "[redacted]", "labels": SecurityLabels()},
        )


class CaptureChainEnd(BaseCallbackHandler):
    def __init__(self) -> None:
        self.outputs: list[Any] = []

    def on_chain_end(self, outputs: Any, **kwargs: Any) -> None:
        self.outputs.append(outputs)


def produce_secret(state: PlacementState) -> PlacementState:
    return {
        "secret": LabeledValue(
            "secret",
            "token",
            SecurityLabels(confidentiality=frozenset({"secret"})),
        )
    }


@pytest.mark.parametrize("asynchronous", [False, True])
async def test_secret_is_redacted_on_sync_and_async_graph_output(
    asynchronous: bool,
) -> None:
    builder = StateGraph(PlacementState)
    builder.add_node("secret", produce_secret)
    builder.add_edge(START, "secret")
    builder.add_edge("secret", END)
    graph = builder.compile(security=SecurityConfig(modules=(RedactSecretOutput(),)))

    result = (
        await graph.ainvoke({}, _config())
        if asynchronous
        else graph.invoke({}, _config())
    )

    assert result == "[redacted]"


@pytest.mark.parametrize("asynchronous", [False, True])
async def test_final_callback_receives_mediated_output(asynchronous: bool) -> None:
    handler = CaptureChainEnd()
    builder = StateGraph(PlacementState)
    builder.add_node("secret", produce_secret)
    builder.add_edge(START, "secret")
    builder.add_edge("secret", END)
    graph = builder.compile(security=SecurityConfig(modules=(RedactSecretOutput(),)))
    config = with_principal(
        {
            "callbacks": [handler],
            "configurable": {"thread_id": "callback-output-thread"},
        },
        _principal(),
    )

    result = (
        await graph.ainvoke({}, config) if asynchronous else graph.invoke({}, config)
    )

    assert result == "[redacted]"
    assert handler.outputs[-1] == "[redacted]"


class ApproveOutput(SecurityModule):
    name = "approve_output"
    can_escalate = True

    def output_emit(self, principal, request):
        return Decision(
            Verdict.ESCALATE,
            "test:approval",
            escalation=EscalationRequest(
                "output-request-1",
                "release output",
                "output",
                request.output_id,
            ),
        )


@pytest.mark.parametrize("asynchronous", [False, True])
async def test_output_escalation_withholds_then_reruns_complete_chain(
    asynchronous: bool,
) -> None:
    builder = StateGraph(PlacementState)
    builder.add_node("update", update_value)
    builder.add_edge(START, "update")
    builder.add_edge("update", END)
    graph = builder.compile(
        checkpointer=InMemorySaver(),
        security=SecurityConfig(modules=(ApproveOutput(),)),
    )

    with pytest.raises(OutputApprovalRequired) as caught:
        if asynchronous:
            await graph.ainvoke({"value": "a"}, _config())
        else:
            graph.invoke({"value": "a"}, _config())

    request = caught.value
    assert request.payload["type"] == "security_approval"
    response = {
        "request_id": request.payload["request_id"],
        "subject_digest": request.payload["subject_digest"],
        "approved": True,
        "approver": "reviewer",
    }
    released = (
        await request.aresume(response) if asynchronous else request.resume(response)
    )
    assert released == ("values", {"value": "a"})

    with pytest.raises(PermissionError, match="approval_replay"):
        if asynchronous:
            await request.aresume(response)
        else:
            request.resume(response)


class ImportedRunnable(Runnable[PlacementState, PlacementState]):
    def invoke(
        self,
        input: PlacementState,
        config: RunnableConfig | None = None,
        **kwargs: Any,
    ) -> PlacementState:
        return {"value": "in-process"}


def _imported_builder(metadata: dict[str, Any] | None = None) -> StateGraph:
    builder = StateGraph(PlacementState)
    builder.add_node("imported", ImportedRunnable(), metadata=metadata)
    builder.add_edge(START, "imported")
    builder.add_edge("imported", END)
    return builder


def test_untrusted_imported_node_is_rejected_without_process_host() -> None:
    with pytest.raises(SecurityConfigurationError, match="separate-process host"):
        _imported_builder().compile(security=SecurityConfig())


class FakeProcessHost:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def invoke(self, node_name: str, value: Any, principal_id: str) -> Any:
        self.calls.append((node_name, principal_id))
        return {"value": "separate-process"}

    async def ainvoke(self, node_name: str, value: Any, principal_id: str) -> Any:
        self.calls.append((node_name, principal_id))
        return {"value": "separate-process"}


@pytest.mark.parametrize("asynchronous", [False, True])
async def test_untrusted_imported_node_uses_process_host_only(
    asynchronous: bool,
) -> None:
    host = FakeProcessHost()
    graph = _imported_builder().compile(
        security=SecurityConfig(untrusted_node_host=host)
    )

    result = (
        await graph.ainvoke({}, _config())
        if asynchronous
        else graph.invoke({}, _config())
    )

    assert result["value"] == "separate-process"
    assert host.calls == [("imported", "alice")]


def test_imported_node_promotion_requires_reason_and_is_audited() -> None:
    with pytest.raises(SecurityConfigurationError, match="requires a reason"):
        _imported_builder({"security_trust": "trusted"}).compile(
            security=SecurityConfig()
        )

    audit = MemoryAuditSink()
    graph = _imported_builder(
        {
            "security_trust": "trusted",
            "security_promotion_reason": "operator-reviewed pinned component",
        }
    ).compile(security=SecurityConfig(audit_sink=audit))

    assert graph.invoke({}, _config())["value"] == "in-process"
    promotion = next(
        item for item in audit.records() if item.module == "node_trust_override"
    )
    assert promotion.reason == "operator_promotion"


class DenyDispatch(SecurityModule):
    name = "deny_dispatch"

    def __init__(self) -> None:
        self.transfers = 0

    def cred_transfer(self, parent, child, slot):
        self.transfers += 1
        return Decision(Verdict.DENY, "test:dispatch_denied")


@pytest.mark.parametrize("asynchronous", [False, True])
async def test_send_dispatch_denial_executes_zero_children_with_one_check_each(
    asynchronous: bool,
) -> None:
    module = DenyDispatch()
    executed: list[int] = []

    def route(state: PlacementState):
        return [Send("child", {"value": "a"}), Send("child", {"value": "b"})]

    def child(state: PlacementState) -> PlacementState:
        executed.append(1)
        return state

    builder = StateGraph(PlacementState)
    builder.add_node("child", child)
    builder.add_conditional_edges(START, route)
    builder.add_edge("child", END)
    graph = builder.compile(security=SecurityConfig(modules=(module,)))

    with pytest.raises(PermissionError, match="test:dispatch_denied"):
        if asynchronous:
            await graph.ainvoke({}, _config())
        else:
            graph.invoke({}, _config())

    assert executed == []
    assert module.transfers == 2


@pytest.mark.parametrize("asynchronous", [False, True])
async def test_subgraph_dispatch_denial_executes_zero_child_nodes(
    asynchronous: bool,
) -> None:
    module = DenyDispatch()
    executed: list[int] = []

    def child_node(state: PlacementState) -> PlacementState:
        executed.append(1)
        return {"value": "child"}

    child_builder = StateGraph(PlacementState)
    child_builder.add_node("child", child_node)
    child_builder.add_edge(START, "child")
    child_builder.add_edge("child", END)
    child_graph = child_builder.compile()

    parent = StateGraph(PlacementState)
    parent.add_node(
        "subgraph",
        child_graph,
        metadata={
            "security_kind": "subgraph",
            "security_trust": "trusted",
            "security_promotion_reason": "operator-built local subgraph",
        },
    )
    parent.add_edge(START, "subgraph")
    parent.add_edge("subgraph", END)
    graph = parent.compile(security=SecurityConfig(modules=(module,)))

    with pytest.raises(PermissionError, match="test:dispatch_denied"):
        if asynchronous:
            await graph.ainvoke({}, _config())
        else:
            graph.invoke({}, _config())

    assert executed == []
    assert module.transfers == 1
