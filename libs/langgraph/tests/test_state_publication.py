"""State inspection keeps the caller's publication boundary across subgraphs."""

from types import SimpleNamespace

import pytest
from langgraph.checkpoint.memory import InMemorySaver

from langgraph.graph import END, START, StateGraph
from langgraph.types import StateSnapshot

pytestmark = pytest.mark.anyio


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("history", [False, True])
@pytest.mark.parametrize("deny", [False, True])
async def test_delegated_snapshot_is_mediated_and_history_closed(
    monkeypatch, asynchronous, history, deny
):
    builder = StateGraph(dict)
    builder.add_edge(START, END)
    graph = builder.compile(checkpointer=InMemorySaver()).with_config(
        configurable={"authority": "caller"}
    )
    original = StateSnapshot(
        {"public": 1},
        ("secret-node",),
        {"secret": "metadata"},
        None,
        None,
        None,
        (),
        (),
    )
    closed = []
    seen = []

    def get_state(*args, **kwargs):
        return original

    async def aget_state(*args, **kwargs):
        return original

    def get_history(*args, **kwargs):
        try:
            yield original
            yield original
        finally:
            closed.append(True)

    async def aget_history(*args, **kwargs):
        try:
            yield original
            yield original
        finally:
            closed.append(True)

    child = SimpleNamespace(
        get_state=get_state,
        aget_state=aget_state,
        get_state_history=get_history,
        aget_state_history=aget_history,
    )

    async def aget_subgraphs(**kwargs):
        yield "child", child

    monkeypatch.setattr(graph, "get_subgraphs", lambda **kw: iter([("child", child)]))
    monkeypatch.setattr(graph, "aget_subgraphs", aget_subgraphs)

    def mediate(value, config):
        assert config["configurable"]["authority"] == "caller"
        seen.append(value)
        if deny:
            raise PermissionError("withheld")
        return "effective"

    async def amediate(value, config):
        return mediate(value, config)

    graph._set_output_filter(mediate, amediate)
    config = {"configurable": {"thread_id": "t", "checkpoint_ns": "child:task"}}
    stream = None

    async def fetch():
        nonlocal stream
        if history:
            stream = (
                graph.aget_state_history(config)
                if asynchronous
                else graph.get_state_history(config)
            )
            return await anext(stream) if asynchronous else next(stream)
        return (
            await graph.aget_state(config) if asynchronous else graph.get_state(config)
        )

    if deny:
        with pytest.raises(PermissionError, match="withheld"):
            await fetch()
    else:
        result = await fetch()
        assert result == StateSnapshot("effective", (), {}, None, None, None, (), ())
    if stream is not None:
        await stream.aclose() if asynchronous else stream.close()
        assert closed == [True]
    assert seen == [original]
