# Demo 11: a callback on a real tool call

Run an actual LangChain tool through `ToolNode` and log its result in your callback.
No LLM or service is required, and the demo never manually emits an analysis event.

```python
@tool
def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b


def on_result(message):
    print(f"Tool {message.name} returned: {message.content}")


with Analysis() as analysis:
    analysis.on(BuiltinEvent.TOOL_RESULT, on_result)
    tools = ToolNode([add], analysis=analysis)
    tools.invoke(
        [{"name": "add", "args": {"a": 2, "b": 3}, "id": "call-1", "type": "tool_call"}],
        runtime=Runtime(),
    )
```

The complete imports are in [demo.py](demo.py).

- `on` subscribes your callback to tool results.
- `analysis=analysis` connects your callbacks to ToolNode’s lifecycle.
- `invoke` executes the registered `add` tool. Its returned `ToolMessage` goes to your callback automatically.

`Runtime()` supplies the context needed to invoke ToolNode outside a graph. A graph
normally supplies it. The call arguments are explicit here; an LLM can generate
them in an agent, but is not needed to execute the tool.

Run from the repository root:

```bash
libs/prebuilt/.venv/bin/python workspace/11_analysis_plugin/demo.py
```

Expected output:

```text
Tool add returned: 5
```

Change `a` or `b` to see the callback receive the new tool result.
If needed, run `uv sync --directory libs/prebuilt` first.

The callback owns its logging and needs no return value. There are no required
findings, snapshots, identity strings or database. The hook preserves the original
tool result regardless of the callback's return value. For async tools/callbacks,
use `await tools.ainvoke(...)`; the same `analysis` option supports both paths.

Demo 11 listens only for results. [Demo 12](../12_analysis_boundaries/README.md)
extends it with proposal, preparation, dispatch, and error callbacks to show the tool
lifecycle. The integration does not install hooks on unrelated tools. Structured
findings remain optional; see the [API documentation](../../docs/security/analysis/plugin-api.md).

[All demos and setup notes](../README.md)
