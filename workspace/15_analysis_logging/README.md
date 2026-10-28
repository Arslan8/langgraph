# Demo 15: analysis logging does not enforce policy

An analysis callback observes a real tool call. A working logger and a failing
logger must produce the same tool result and effect.

```python
def log_dispatch(call):
    if not available:
        raise RuntimeError("Logging backend is unavailable")
    print(f"Observed dispatch: {call['name']}")

analysis.on(BuiltinEvent.TOOL_DISPATCH, log_dispatch)
tools = ToolNode([record], analysis=analysis, handle_tool_errors=False)
```

The dispatcher logs observer exceptions and continues. A callback return value,
exception, or timeout is not an allow/deny decision. Framework notifications use
detached payloads so edits to a callback's copy cannot rewrite arguments or results.
Existing runtime security mechanisms remain responsible for authorization; analysis
observers do not replace, weaken, or add decisions to them.

Run from the repository root:

```bash
libs/prebuilt/.venv/bin/python workspace/15_analysis_logging/demo.py
```

Expected standard output:

```text
Observed dispatch: record
Logging available: 1 tool effect(s)
Logging unavailable: 1 tool effect(s)
```

The failing case also emits one warning through Python logging:

```text
Analysis observer failed: tool.dispatch (RuntimeError)
```

Both cases invoke the real `record` tool and verify that it appended `hello` exactly
once and returned the original message. `handle_tool_errors=False` makes clear that
observer failure is isolated by the analysis dispatcher, rather than hidden by
ToolNode's tool-error handling.

## Try it

Return `False` from the callback: the tool still executes. Raise from a result
callback: the original result still reaches the caller. Analysis callbacks are for
observation and developer-owned logging/results, not runtime argument-based detection
used to enforce access decisions.

No analyzer IDs, registry, structured findings, identity strings, or analysis store
are needed. If necessary, run `uv sync --directory libs/prebuilt` first. No LLM,
service, Cedar CLI or sandbox is needed.

## Scope

These are trusted application callbacks, not sandboxed code. They can still perform
their own side effects, and synchronous delivery can delay a call. Configure a
callback timeout where appropriate; its expiration is logged, not used to deny the
operation. Caller-requested cancellation and actual tool/runtime errors retain their
normal behavior. A closed observer or an uncopyable notification is logged/skipped
without changing the underlying operation.

[All demos](../README.md) · [Observer API and design policy](../../docs/security/analysis/plugin-api.md)
