"""Demo 11: receive an event from a real tool call."""

from langchain_core.tools import tool
from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.analysis import Analysis, BuiltinEvent
from langgraph.runtime import Runtime


@tool
def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b


def on_result(message):
    print(f"Tool {message.name} returned: {message.content}")


def main():
    with Analysis() as analysis:
        analysis.on(BuiltinEvent.TOOL_RESULT, on_result)
        tools = ToolNode([add], analysis=analysis)
        tools.invoke(
            [
                {
                    "name": "add",
                    "args": {"a": 2, "b": 3},
                    "id": "call-1",
                    "type": "tool_call",
                }
            ],
            runtime=Runtime(),
        )


if __name__ == "__main__":
    main()
