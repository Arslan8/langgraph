"""Example 3: supply the invocation principal interactively.

Run this script and enter `alice` to allow the tool call or another identity to
see Cedar deny it. Reading a principal from terminal input is suitable only for
this demonstration. A deployed application must construct the principal from
an authenticated session or verified token.
"""

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


MANIFEST = """
runs inprocess
returns normal
"""

# Only the authenticated principal `alice` may call the bound tool.
POLICY = """
permit (
  principal == slangGraph::User::"alice",
  action == slangGraph::Action::"call",
  resource
);
"""


@tool
@effects(Effect.READ, sensitivity="normal")
def greet(name: str) -> str:
    """Return a greeting for a person."""
    return f"Hello, {name}!"


security = cedar_security(greet, manifest=MANIFEST, policy=POLICY)

builder = StateGraph(MessagesState)
builder.add_node("tools", ToolNode([greet]))
builder.add_edge(START, "tools")
graph = builder.compile(security=security)

# Demo only: this trusts what was typed. In production, obtain this value from
# authentication middleware after it verifies a session, API key, or token.
principal_id = input("Principal ID (enter alice to allow): ").strip()
if not principal_id:
    raise SystemExit("Principal ID cannot be empty")

# The principal belongs to this graph invocation, not permanently to the node.
principal = Principal(principal_id, frozenset(), frozenset(), "cli-session")
config = with_principal({}, principal, modules=security.modules)

result = graph.invoke(
    {
        "messages": [
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "greet",
                        "args": {"name": "World"},
                        "id": "call-1",
                    }
                ],
            )
        ]
    },
    config=config,
)

print(result["messages"][-1].content)
