"""Injected admission callbacks run before all graph work, with no prebuilt import."""

import pytest

from langgraph.graph import START, StateGraph

pytestmark = pytest.mark.anyio


async def test_admission_precedes_nodes_and_preserves_async_cancellation():
    effects = []
    graph = StateGraph(dict)
    graph.add_node("effect", lambda state: effects.append("effect") or state)
    graph.add_edge(START, "effect")
    compiled = graph.compile()

    def deny(value, config):
        effects.append("admit")
        raise PermissionError("denied")

    async def adeny(value, config):
        deny(value, config)

    compiled._set_input_guard(deny, adeny)
    with pytest.raises(PermissionError):
        compiled.invoke({"value": 1})
    with pytest.raises(PermissionError):
        await compiled.ainvoke({"value": 1})
    assert effects == ["admit", "admit"]
    with pytest.raises(ValueError):
        compiled._set_input_guard(deny, adeny)


async def test_successful_guard_does_not_transform_input():
    observed = []
    graph = StateGraph(dict)
    graph.add_node("identity", lambda state: state)
    graph.add_edge(START, "identity")
    compiled = graph.compile()

    def admit(value, config):
        observed.append(value.copy())

    async def aadmit(value, config):
        admit(value, config)

    compiled._set_input_guard(admit, aadmit)
    assert compiled.invoke({"value": 2}) == {"value": 2}
    assert await compiled.ainvoke({"value": 3}) == {"value": 3}
    assert observed == [{"value": 2}, {"value": 3}]
