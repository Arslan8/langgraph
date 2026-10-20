"""Example 1: a minimal ToolNode graph without security policy."""

from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from langgraph.graph import START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode


@tool
def greet(name: str) -> str:
    """Return a greeting for a person."""
    return f"Hello, {name}!"


builder = StateGraph(MessagesState)
builder.add_node("tools", ToolNode([greet]))
builder.add_edge(START, "tools")

graph = builder.compile()

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
    }
)

print(result["messages"][-1].content)
