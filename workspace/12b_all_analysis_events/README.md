# Demo 12b: all 25 analysis events

Extend demos 11 and 12 into a tour of the whole built-in event catalog. A plain
callback prints event names as real operations execute. A final table reports
which event types were observed and how often.

The callback registration is still just:

```python
for event in BuiltinEvent:
    analysis.on(event, partial(record, event))
```

`record(event, payload)` is developer code. In this demo it counts and prints;
it could instead log to your own system. No standardized findings, analyzer IDs,
versions, provenance registry, or analysis database are required.

## Run

Use the same prebuilt virtual environment as the other demos. No reactivation is
needed if you invoke its Python directly:

```bash
libs/prebuilt/.venv/bin/python workspace/12b_all_analysis_events/demo.py
```

This demo requires a running real LLM. It defaults to llama.cpp at
`http://127.0.0.1:8081/v1`, with model alias `qwen3:8b`. There is no fake model or
canned-response fallback. If needed, install the provider client into this venv:

```bash
uv pip install --python libs/prebuilt/.venv/bin/python langchain-openai
```

Start your local server in another terminal, substituting your GGUF path:

```bash
llama-server --model /path/to/model.gguf --alias qwen3:8b \
  --host 127.0.0.1 --port 8081 --ctx-size 4096 --parallel 1 \
  --jinja --reasoning off
```

On the system used to verify this demo, the executable is
`/usr/local/lib/ollama/llama-server` and the installed Qwen3 8B model is
`$HOME/.ollama/models/blobs/sha256-a3de86cd1c132c822487ededd47a324c50491393e6565cd14bafa40d0b8e686f`.
Port 8081 avoids an existing service on 8080. For a server at another endpoint:

```bash
libs/prebuilt/.venv/bin/python workspace/12b_all_analysis_events/demo.py \
  --base-url http://127.0.0.1:8080/v1 --model qwen3:8b
```

Model requests go to the endpoint you select. The resource-send example separately
uses a temporary loopback HTTP receiver on a free port. Files live in a temporary
directory, and state, document retrieval, store and checkpoints use local memory.
The receiver and temporary resources are cleaned up after the run.

## What actually triggers each event

| Event | Real operation |
| --- | --- |
| `input.admit` | Admit the query into the running workflow |
| `model.request` | Submit the assembled prompt to llama.cpp |
| `model.response` | Receive its generated answer |
| `tool.propose` | Submit an `add` call to ToolNode |
| `tool.prepare` | ToolNode begins preparing that call |
| `tool.dispatch` | ToolNode invokes the registered tool |
| `tool.result` | `add(2, 3)` returns 5 |
| `tool.error` | `add(-1, 3)` raises a real error |
| `retrieval.request` | Search two documents using a SQLite query |
| `retrieval.result` | Return the matching document |
| `output.emit` | Publish the final generated answer to the terminal |
| `context.transform.before` | Begin joining retrieved documents into context |
| `context.transform.after` | Return the assembled context |
| `resource.read` | Read the temporary notes file |
| `resource.write` | Write that file |
| `resource.send` | POST bytes to the loopback receiver |
| `state.read` | Read the workflow's answer from its state dictionary |
| `state.write` | Write that answer into state |
| `state.store.read` | Read a saved item through LangGraph's InMemoryStore |
| `state.store.write` | Write that item through the store |
| `state.checkpoint.save` | Serialize a checkpoint using LangGraph's InMemorySaver |
| `state.checkpoint.restore` | Load the saved checkpoint after changing the original value |
| `dispatch.child.start` | Invoke a compiled child StateGraph |
| `dispatch.child.return` | Receive the child graph's computed output |
| `dispatch.branch.merge` | Reduce the outputs of two child executions |

The child graphs count the characters in the retrieved context and model answer;
the merge sums those counts. They run sequentially to keep the trace easy to read.
Checkpointing is a real call to the public saver API, demonstrated explicitly;
it does not claim to intercept every scheduler checkpoint automatically.

## What to look for

The trace follows execution order, not enum order. Some events repeat: two tool
calls produce one success and one failure, and two child calls produce two starts
and returns. The final table always covers every current `BuiltinEvent` member:

```text
Coverage (actual emitted events):
  SEEN    input.admit                  1
  ... one row for every event ...
25/25 event types observed
All operation effects verified.
```

The script checks the file contents, retrieved document, nonempty model response,
tool results, state/store readbacks, detached checkpoint restoration, child output,
merge result, and bytes received by the HTTP server. It exits unsuccessfully if an
operation fails, an assertion fails, or any catalog event is missing. The table is
also printed on failure; `SEEN` means emitted, not that an operation succeeded.

Try an unavailable model endpoint to see a partial report with missing events;
there is no fallback that pretends the tour completed. Change the tool's negative
input to a positive one and `tool.error` becomes missing, so coverage fails.

## Instrumentation and scope

ToolNode emits its lifecycle events natively through `analysis=analysis`. The other
operations run through the optional `ObservedOperations` adapter. Its methods wrap
the real operation and emit at its boundary; the demo does not manually call
`analysis.emit` or loop through enum members to fabricate events. The registration
loop only installs callbacks.

Most resource/state/checkpoint events occur before an attempted operation. Paired
model/retrieval/transform/child completion events occur only after success; merge
fires after the reducer returns. The callback receives ordinary application data,
and callback results never replace operation results.

This is a showcase of all catalog event types, not proof of every lifecycle path
or application-wide instrumentation. The adapters are explicit and synchronous.
They do not automatically intercept other Python I/O, provide resource grants,
enforce access policies, or track provenance. Those integrations remain separate.
Developers can use their own logging/results or opt into standardized analysis.

[All demos](../README.md) · [Callback API](../../docs/security/analysis/plugin-api.md)
