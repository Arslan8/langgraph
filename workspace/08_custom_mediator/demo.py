"""Example 8: extend the framework with an app-owned custom mediator.

Run: python workspace/08_custom_mediator/demo.py
Requires Linux Landlock ABI 5+, libseccomp, and Cedar on PATH.
See mediators/api.py for the contract and mediators/counter.py for the backend.
"""

from __future__ import annotations

# Controller imports stay in main; the sandbox loads only the tool and its API.
# ruff: noqa: PLC0415
from mediators.api import counter


def increment_counter(amount: int) -> int:
    """Increment the counter through its official mediator."""
    return counter.increment(amount)


def main() -> None:
    import hashlib
    import json
    import sys
    from pathlib import Path

    from langchain_core.messages import AIMessage
    from langchain_core.tools import tool
    from langgraph.graph import START, MessagesState, StateGraph
    from langgraph.prebuilt import ToolNode
    from langgraph.prebuilt.security import (
        HostExecutionError,
        LinuxToolSpec,
        ObjectBrokerDispatcher,
        Principal,
        cedar_security,
        with_principal,
    )
    from mediators.api import COUNTER
    from mediators.counter import CounterBackend, CounterMediator

    # The tool runs in a worker; only the parent holds the actual counter.
    backend = CounterBackend()
    resource = COUNTER.bind(
        implementation=backend,
        mediator=CounterMediator(),  # Owns lowering support and amount validation.
    )
    increment = tool(increment_counter)
    artifact = Path(__file__).resolve()
    dispatcher = ObjectBrokerDispatcher(
        {
            increment.name: LinuxToolSpec(
                "counter_demo:increment_counter",
                artifact,
                hashlib.sha256(artifact.read_bytes()).hexdigest(),
            )
        },
        runtime_roots=tuple(
            Path(p).resolve() for p in sys.path if p and Path(p).is_dir()
        ),
        resources=(resource,),  # Register the bound resource.
    )
    security = cedar_security(
        increment,
        manifest="runs linux\n" + resource.permission("increment"),
        policy='permit(principal == slangGraph::User::"alice", action, resource);',
        dispatcher=dispatcher,
    )
    builder = StateGraph(MessagesState)
    builder.add_node(
        "tools", ToolNode([increment], handle_tool_errors=(HostExecutionError,))
    )
    builder.add_edge(START, "tools")
    graph = builder.compile(security=security)
    # Demo identity; production applications obtain this from authentication.
    config = with_principal(
        {},
        Principal("alice", frozenset(), frozenset(), "counter-demo"),
        modules=security.modules,
    )

    print("Mediator rule: add only 1, 2, or 3 to the counter.")
    print("Counter starts at 0. Alice has permission to increment it.\n")
    for amount in (2, -1):
        result = graph.invoke(
            {
                "messages": [
                    AIMessage(
                        content="",
                        tool_calls=[
                            {
                                "name": increment.name,
                                "args": {"amount": amount},
                                "id": f"add-{amount}",
                            }
                        ],
                    )
                ]
            },
            config=config,
        )
        message = result["messages"][-1]
        if amount == 2:
            assert getattr(message, "status", None) != "error", message.content
            assert json.loads(str(message.content)) == 2
            print("ALLOW: increment(2) -> counter = 2")
        else:
            assert getattr(message, "status", None) == "error", message.content
            assert "PermissionError" in str(message.content), message.content
            print("DENY: increment(-1) -> counter remains 2")
        assert backend.value == 2
    print("Counter is still 2: the mediator rejected the invalid amount.")


if __name__ == "__main__":
    main()
