# Demo 12: the tool event lifecycle

Extend [demo 11](../11_analysis_plugin/README.md) by subscribing to all five tool
events. Run the same real `add` tool twice: once successfully and once with a
negative input that makes its body raise an error.

```python
analysis.on(BuiltinEvent.TOOL_PROPOSE, on_proposal)
analysis.on(BuiltinEvent.TOOL_PREPARE, on_prepare)
analysis.on(BuiltinEvent.TOOL_DISPATCH, on_dispatch)
analysis.on(BuiltinEvent.TOOL_RESULT, on_result)
analysis.on(BuiltinEvent.TOOL_ERROR, on_error)
tools = ToolNode([add], analysis=analysis, handle_tool_errors=True)
```

ToolNode emits the events at its execution boundaries. The demo contains no manual
`emit` calls and requires no findings, registry, database, or identity strings.
The callback functions own their printing.

Run from the repository root:

```bash
libs/prebuilt/.venv/bin/python workspace/12_analysis_boundaries/demo.py
```

Expected output:

```text
Success
  tool.propose: add
  tool.prepare: add
  tool.dispatch: add
  add executes
  tool.result: 5
Failure
  tool.propose: add
  tool.prepare: add
  tool.dispatch: add
  add executes
  tool.error: Error: ValueError('Use non-negative numbers')
```

| Event | When it occurs |
| --- | --- |
| `TOOL_PROPOSE` | ToolNode receives a call, before any custom execution wrapper |
| `TOOL_PREPARE` | An execution attempt begins checking the tool and preparing authorization/arguments |
| `TOOL_DISPATCH` | ToolNode is about to invoke the tool or host router |
| `TOOL_RESULT` | The call finishes with a successful result |
| `TOOL_ERROR` | The call finishes with an error result or raises an exception |

`add executes` is printed by the tool body, not by an event callback. It makes the
location of actual execution visible. `handle_tool_errors=True` converts the raised
exception to an error ToolMessage for `on_error`; the callback prints its first line.

Success and error are alternative endings, not consecutive stages of one call.
An unknown or unauthorized tool ends with an error before dispatch. Dispatch marks
an invocation attempt; tool argument validation or host checks can still fail before
the body executes. A retry wrapper repeats preparation/dispatch for each attempt.

Change the arguments or tool name to explore these paths. No LLM or service is
needed. If necessary, run `uv sync --directory libs/prebuilt` first. This lesson
covers the tool lifecycle; model, retrieval, state, and other event families require
their corresponding integrations and are not emitted by a tool-only example.

[All demos and setup notes](../README.md)
