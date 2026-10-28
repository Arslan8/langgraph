"""Demo 15: logging failures do not control tool execution."""

from langchain_core.tools import tool
from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.analysis import Analysis, BuiltinEvent
from langgraph.runtime import Runtime


def run_case(available):
    effects = []

    def log_dispatch(call):
        if not available:
            raise RuntimeError("Logging backend is unavailable")
        print(f"Observed dispatch: {call['name']}")

    @tool
    def record(message: str) -> str:
        """Record one message in this process."""
        effects.append(message)
        return message

    with Analysis() as analysis:
        analysis.on(BuiltinEvent.TOOL_DISPATCH, log_dispatch)
        tools = ToolNode([record], analysis=analysis, handle_tool_errors=False)
        result = tools.invoke(
            [
                {
                    "name": "record",
                    "args": {"message": "hello"},
                    "id": "record-1",
                    "type": "tool_call",
                }
            ],
            runtime=Runtime(),
        )
        assert effects == ["hello"]
        assert result["messages"][0].content == "hello"
        label = "available" if available else "unavailable"
        print(f"Logging {label}: {len(effects)} tool effect(s)")


def main():
    run_case(True)
    run_case(False)


if __name__ == "__main__":
    main()
