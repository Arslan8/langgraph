"""Demo 12: extend demo 11 to observe the tool lifecycle."""

from langchain_core.tools import tool
from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.analysis import Analysis, BuiltinEvent
from langgraph.runtime import Runtime


@tool
def add(a: int, b: int) -> int:
    """Add two numbers, rejecting negative inputs for the error example."""
    print("  add executes")
    if a < 0 or b < 0:
        raise ValueError("Use non-negative numbers")
    return a + b


def on_proposal(call):
    print(f"  tool.propose: {call['name']}")


def on_prepare(call):
    print(f"  tool.prepare: {call['name']}")


def on_dispatch(call):
    print(f"  tool.dispatch: {call['name']}")


def on_result(message):
    print(f"  tool.result: {message.content}")


def on_error(message):
    print(f"  tool.error: {message.content.splitlines()[0]}")


def main():
    with Analysis() as analysis:
        analysis.on(BuiltinEvent.TOOL_PROPOSE, on_proposal)
        analysis.on(BuiltinEvent.TOOL_PREPARE, on_prepare)
        analysis.on(BuiltinEvent.TOOL_DISPATCH, on_dispatch)
        analysis.on(BuiltinEvent.TOOL_RESULT, on_result)
        analysis.on(BuiltinEvent.TOOL_ERROR, on_error)
        tools = ToolNode([add], analysis=analysis, handle_tool_errors=True)
        for label, a in (("Success", 2), ("Failure", -1)):
            print(label)
            tools.invoke(
                [
                    {
                        "name": "add",
                        "args": {"a": a, "b": 3},
                        "id": label,
                        "type": "tool_call",
                    }
                ],
                runtime=Runtime(),
            )


if __name__ == "__main__":
    main()
