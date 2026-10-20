"""Example 2: bind a Cedar DAC policy directly to a tool."""

from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from langgraph.graph import START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    Effect,
    Principal,
    cedar_security,
    effects,
    with_principal,
)


# This is an unnamed SLP manifest body. It describes how the bound tool runs,
# but does not repeat the tool's Python name.
MANIFEST = """
runs inprocess
returns normal
"""

# This Cedar policy says that only the principal named `alice` may call the
# tool to which the policy is attached. It does not repeat that tool's name.
POLICY = """
permit (
  principal == slangGraph::User::"alice",
  action == slangGraph::Action::"call",
  resource
);
"""


@tool
# This metadata describes what the tool does. It is separate from Cedar DAC.
@effects(Effect.READ, sensitivity="normal")
def greet(name: str) -> str:
    """Return a greeting for a person."""
    return f"Hello, {name}!"


# Passing the actual tool object creates the binding. The framework derives
# `greet.name` for ToolNode routing, Cedar's internal Tool entity, and auditing.
# It also generates the internal owner-side ceiling, so the application author
# only writes the caller-facing POLICY above.
security = cedar_security(greet, manifest=MANIFEST, policy=POLICY)

builder = StateGraph(MessagesState)
builder.add_node("tools", ToolNode([greet]))
builder.add_edge(START, "tools")
graph = builder.compile(security=security)

# This is the identity Cedar sees as `slangGraph::User::"alice"`.
principal = Principal("alice", frozenset(), frozenset(), "session-1")
# Put that identity and the active security modules into the invocation config.
config = with_principal({}, principal, modules=security.modules)
result = graph.invoke(
    {
        "messages": [
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "greet",
                        "args": {"name": "Alice"},
                        "id": "call-1",
                    }
                ],
            )
        ]
    },
    config=config,
)

print(result["messages"][-1].content)
