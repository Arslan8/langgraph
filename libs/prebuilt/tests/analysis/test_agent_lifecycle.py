import pytest
from langchain_core.messages import HumanMessage
from langgraph.checkpoint.memory import InMemorySaver

from langgraph.prebuilt import create_react_agent
from langgraph.prebuilt.security import Principal, SecurityConfig, with_principal
from langgraph.prebuilt.security.modules.analysis_gate import AnalysisGate
from tests.analysis.test_runtime_access import setup_runtime
from tests.model import FakeToolCallingModel


@pytest.mark.parametrize("dynamic", [False, True])
@pytest.mark.parametrize("structured", [False, True])
async def test_agent_sync_async_final_request(dynamic, structured):
    runtime, _, _, _ = setup_runtime()
    model = FakeToolCallingModel(structured_response={"answer": "ok"})
    selected = (lambda state, runtime: model) if dynamic else model
    security = SecurityConfig(
        modules=(AnalysisGate(runtime.config.policy_version),), analysis=runtime
    )
    graph = create_react_agent(
        selected,
        [],
        prompt="fixed system instruction",
        security=security,
        response_format={
            "title": "Answer",
            "type": "object",
            "properties": {"answer": {"type": "string"}},
        }
        if structured
        else None,
    )
    config = with_principal(
        {},
        Principal("owner", frozenset(), frozenset(), "session"),
        modules=security.modules,
    )
    graph.invoke({"messages": [HumanMessage("hello")]}, config)
    await graph.ainvoke({"messages": [HumanMessage("hello async")]}, config)
    snapshots = runtime.journal.snapshots()
    requests = [
        snapshot
        for snapshot in snapshots
        if snapshot.event.event_name == "model.request"
        and snapshot.status == "complete"
    ]
    assert len(requests) == (4 if structured else 2)
    contents = [
        runtime.store.resolve(snapshot.event.input_refs[0]).decode()
        for snapshot in requests
    ]
    assert any("fixed system instruction" in content for content in contents)
    runtime.close()


def test_graph_checkpoint_restores_analysis_into_new_run():
    runtime, adapter, _, _ = setup_runtime()
    source = adapter.value("restricted prior context")
    adapter.before("input.admit", (source,))
    saver = InMemorySaver()
    principal = Principal("owner", frozenset(), frozenset(), "session")
    config = with_principal(
        {"configurable": {"thread_id": "analysis-thread"}}, principal
    )
    security = SecurityConfig(
        modules=(AnalysisGate(runtime.config.policy_version),),
        analysis=runtime,
        checkpoint_key=b"stable-analysis-key",
    )
    graph = create_react_agent(
        FakeToolCallingModel(), [], security=security, checkpointer=saver
    )
    graph.invoke({"messages": [HumanMessage("hello")]}, config)
    resumed, _, _, _ = setup_runtime()
    resumed.run_id = "resumed-run"
    resumed_security = SecurityConfig(
        modules=(AnalysisGate(resumed.config.policy_version),),
        analysis=resumed,
        checkpoint_key=b"stable-analysis-key",
    )
    next_graph = create_react_agent(
        FakeToolCallingModel(), [], security=resumed_security, checkpointer=saver
    )
    next_graph.invoke(None, config)
    refs = resumed.store.run_refs("tenant", "resumed-run")
    assert refs
    assert any(
        "example.department.restricted" in resumed.journal.flow(ref).risks
        for ref in refs
    )
    runtime.close()
    resumed.close()
