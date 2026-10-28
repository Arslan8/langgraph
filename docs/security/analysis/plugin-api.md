# Analysis callbacks and optional structured plugins

## Plain callbacks

The engine delivers events and executes callbacks. Developers own payloads,
logging, side effects, result formats and destinations. A callback can return
nothing, return an application-specific object, or produce standardized analysis
results. Standardization enables shared consumers; it is not required to use the
engine. No provenance store, finding schema, identity strings or registration
metadata are required for a plain callback.

```python
from langgraph.prebuilt.analysis import Analysis, BuiltinEvent

def on_input(document):
    print("Input admitted:", document)

with Analysis() as analysis:
    analysis.on(BuiltinEvent.INPUT_ADMIT, on_input)
    analysis.emit(BuiltinEvent.INPUT_ADMIT, "Quarterly report")
```

`on(event, callback)` also accepts a set of events. Events must be `BuiltinEvent`
members or explicit custom `EventSpec` objects; arbitrary strings are rejected.
For plain dispatch, a custom spec identifies a subscription; its schema is not
applied to the developer's payload. Emit the same spec to reach its subscribers.
No producer is installed automatically. Applications explicitly emit events at
boundaries they own; registering a callback does not intercept resource/tool calls.

Each callback receives exactly the payload supplied to `emit`, unchanged and
without copying or serialization. Callbacks execute sequentially in subscription
order. `emit` returns a tuple of their original return values, including `None`,
or an empty tuple when there are no subscribers. The caller can ignore it:

```python
with Analysis() as analysis:
    analysis.on(BuiltinEvent.INPUT_ADMIT, lambda text: {"my_length": len(text)})
    results = analysis.emit(BuiltinEvent.INPUT_ADMIT, "hello")
    assert results == ({"my_length": 5},)
```

A failed callback contributes `None` and a logging warning; it is not a clean
finding or authorization verdict. Nothing is automatically stored or converted to findings. Mutable payloads are
shared between callbacks, and developers own synchronization for concurrent emits.
Subscriptions are captured at emission start; changes apply to subsequent emits.
Repeated subscription of the same callback registers it again.

Use `await analysis.aemit(event, payload)` for async callbacks. It also accepts
synchronous callbacks, running them in worker threads. Synchronous `emit` runs
sync callbacks in worker threads and rejects async callbacks; use `aemit` when any
subscriber is async. Observer exceptions are logged and later callbacks still run.
Callbacks provide observation, not enforcement: returns, exceptions and timeouts
must not be interpreted as runtime authorization decisions.

`on(..., timeout=seconds)` optionally bounds each callback's execution wait.
There is no default deadline. Timeouts are logged as observer failures. Cancellation
requested by the caller propagates; an observer cancelling itself is logged and isolated. Python cannot forcibly stop a synchronous callback already running:
it may finish its side effects after cancellation or timeout. The context manager
closes the executor and cancels queued work; callbacks are trusted application code,
not sandboxed extensions. Direct registration/emission after close is a usage error. Framework notifications
to a closed observer are logged/skipped while the underlying operation continues.

## Events from real tool calls

Pass the dispatcher to ToolNode to receive lifecycle events without manual emits:

```python
from langgraph.prebuilt import ToolNode
from langgraph.runtime import Runtime

with Analysis() as analysis:
    analysis.on(BuiltinEvent.TOOL_RESULT, lambda message: print(message.content))
    tools = ToolNode([add], analysis=analysis)  # add is a registered @tool function.
    tools.invoke(
        [{"name": "add", "args": {"a": 2, "b": 3}, "id": "one", "type": "tool_call"}],
        runtime=Runtime(),
    )
```

A standalone invocation supplies `Runtime()`; graph execution supplies its own
runtime. Async invocations use `await tools.ainvoke(...)` with the same option.
See [demo 11](../../../workspace/11_analysis_plugin/README.md) for a result listener
and [demo 12](../../../workspace/12_analysis_boundaries/README.md) for the full tool
lifecycle with success and error paths. Neither example needs an LLM.

| Event | Boundary | Payload |
| --- | --- | --- |
| `TOOL_PROPOSE` | Incoming call, before custom execution wrappers | Fresh dict with `name` and `id` |
| `TOOL_PREPARE` | Each attempt starts tool lookup and security/argument preparation | Fresh dict with `name` and `id` |
| `TOOL_DISPATCH` | Immediately before invoking the tool or host router | Fresh dict with `name` and `id` |
| `TOOL_RESULT` | Successful outer completion | Detached copy of ToolMessage, Command, or result list |
| `TOOL_ERROR` | Error-status completion or raised exception | Detached copy of error result or exception |

Callbacks own their output formats; their return values do not replace tool results.
Framework integrations give each observer a detached copy. A copy failure skips
that notification and is logged; mutations cannot rewrite live arguments/results.
Phase metadata deliberately excludes mutable authorization objects and arguments.
The security verifier's reviewed source contract includes these metadata-only phase
helpers; authorization checks and grants are unchanged. Callbacks remain trusted
application code, not sandboxed plugins.

Unknown tools and authorization denials end with an error before dispatch. Dispatch
means an invocation attempt, not proof that a tool body executed: tool argument
validation or host checks can still reject it. A custom wrapper may return a cached
result without preparing/dispatching, or repeat preparation and dispatch when it
retries. The outer proposal and completion occur once. Cancellation and graph
interrupts propagate without a fabricated result/error event.

Tool exceptions follow `handle_tool_errors`: handled failures emit an error result;
unhandled tool exceptions emit an error and are re-raised. Observer failures are
logged and cannot block a permitted tool, replace a result, mask a tool exception,
or turn a runtime security denial into permission. Existing runtime enforcement
owns access decisions; plain analysis is not a runtime argument-detection gate.
Synchronous observation can still delay execution, and trusted callbacks can perform
their own side effects. This is not a sandbox for hostile callback code. Concurrent
calls can interleave; call IDs provide correlation, not global ordering.

The older `wrap_tool_call=analysis.wrap_tool_call` and async counterpart remain
available as outer-wrapper hooks only. They expose proposal, result, and error,
not internal preparation/dispatch; their proposal payload is a detached tool-call mapping.
Use `analysis=analysis` for the complete tool lifecycle. Do not install both forms
on the same node, which would duplicate outer notifications. Other event families
require their own instrumentation; this integration observes only its ToolNode.

## Observing other application operations

`ObservedOperations` from `langgraph.prebuilt.analysis.adapters.operations` is an
optional synchronous adapter for plain callbacks. It executes real operations and
preserves their results and exceptions; it requires no structured result contract.

```python
from langgraph.prebuilt.analysis.adapters.operations import ObservedOperations

with Analysis() as analysis:
    analysis.on(BuiltinEvent.RESOURCE_READ, lambda path: print("Reading", path))
    operations = ObservedOperations(analysis)
    text = operations.read_text(path)
```

Its `model` and `retrieve` methods call the supplied object's `invoke`; `transform`
calls your transformation; `child` invokes the supplied graph and `merge` calls your
reducer. `read_text`/`write_text` operate on UTF-8 files, and `send` calls your
transport. `state_read`/`state_write` access a supplied mapping. `store_read` and
`store_write` call a store's `get` and `put`; `checkpoint_save` and
`checkpoint_restore` call a saver's `put` and `get_tuple`. `run` admits input, invokes
your workflow, then reports output before calling your publisher.

Resource, state, store and checkpoint events occur before their operations;
input admission precedes the workflow and output emission precedes publication.
Paired model/retrieval/transform/child after-events fire only on success. Branch
merge fires after the reducer succeeds. Observer failures are logged and do not
prevent or change the operation. The callback receives a detached copy and its
return value is ignored. There is no provenance store or policy installation.

These explicit adapters do not monitor unwrapped operations or authorize access.
In particular, their resource notifications do not replace the grant-bearing
`ResourceAdapter` used by the optional structured security integration. Async
operations need their own awaited integration; these methods are synchronous.

[Demo 12b](../../../workspace/12b_all_analysis_events/README.md) executes a real
local workflow spanning all 25 built-in events and reports per-event coverage.
It verifies effects separately: seeing a before-event alone is not evidence of
successful execution. Its model call requires a live endpoint, with no mock fallback.

## Opting into standardized findings

`StructuredAnalysis` provides the optional local integration for developers who
want tracked values, standardized findings, and in-memory persistence. The older
local `Analysis(*registrations)` API is now named `StructuredAnalysis`; use
`Analysis().on(...)` for plain callbacks. `AnalysisRuntime` remains the structured
integration for authenticated identities, persistent storage and policy adapters.
Both paths use the same callback executor; result validation and persistence belong
to the structured consumer, not to the executor.

```python
from langgraph.prebuilt.analysis import (
    AnalysisResult, AnalyzerRegistration, BuiltinEvent, StructuredAnalysis,
)

class DocumentListener:
    def analyze(self, event, context):
        return AnalysisResult(findings=(context.finding(code="example.seen"),))

    async def aanalyze(self, event, context):
        return self.analyze(event, context)

with StructuredAnalysis(
    AnalyzerRegistration(analyzer=DocumentListener(), events={BuiltinEvent.INPUT_ADMIT})
) as analysis:
    document = analysis.value("Quarterly report")
    snapshot = analysis.emit(BuiltinEvent.INPUT_ADMIT, (document,))
    assert snapshot.findings[0].code == "example.seen"
```

This opt-in session owns its storage and generates isolated local identities;
these do not authenticate a user. `value` tracks content and provenance, `emit`
returns a snapshot, and `aemit` is its async equivalent. The context manager closes
the session and its storage. Explicit IDs and versions remain optional overrides.

Shared policy/query consumers require the standardized contract. A custom dict or
`None` is valid for plain callbacks but cannot serve as standardized evidence:
the structured integration rejects it and marks required analysis unavailable.
Callback completion alone does not authorize an operation. Developers using a
private format supply their own consumers or explicitly adapt it to `AnalysisResult`.



For local consumers, `analysis.client` provides scoped inspection without constructing
an AccessContext or supplying identity strings. `analysis.checkpoint(*refs)` saves
metadata in a trusted local handle; `checkpoint.restore()` opens a fresh session.
`configuration={...}` selects meaningful fixed analysis configuration. These helpers
retain scope, signature and configuration checks internally; they do not authenticate
external callers or add authorization decisions. See the [local inspection and
checkpoint guide](developer-api.md#local-sessions-without-identity-boilerplate).

The remaining sections describe only this optional structured contract.

Import contracts from `langgraph.prebuilt.analysis`. `Analyzer` supplies
`analyze(event, context)` and `aanalyze(event, context)`, returning `AnalysisResult`.
Findings carry stable IDs, analyzer identity/version, namespaced code, subject and
evidence references, explicit status and configuration digest. Optional scores must
be finite in [0, 1]. They are not calibrated confidence.

Register `AnalyzerRegistration` explicitly at the root with a set of `BuiltinEvent`
enum members (or explicitly declared custom `EventSpec` objects),
dependencies, required/advisory mode, timeout and content access. No import-time
registration occurs. Duplicate IDs, unknown schemas/producers, missing dependencies,
advisory dependencies of required plugins, and cycles are rejected. Register custom
`EventSpec` objects with schema, phase, producer and barrier. Registration alone does
not instrument any Python operation.

Registration requires only `analyzer` and `events`, passed by keyword. The runtime
derives `analyzer_id` from the module and class name; `version` defaults to
`unversioned`. Explicit overrides remain available for duplicate instances,
dependency names, or versioned records. Derived identity is not a code fingerprint
and does not establish implementation equivalence across deployments.
Use `context.finding(code="example.document.seen")` to create a finding without
manually supplying its ID, analyzer identity/version or event metadata. Subjects
default to the current event's input/output references; the configuration digest
defaults to the fixed run policy and may be explicitly overridden for a plugin's
own configuration. Scope and identity checks still run before persistence.
Subscriptions have set semantics and are frozen at construction. Use
`events={BuiltinEvent.INPUT_ADMIT, BuiltinEvent.MODEL_REQUEST}` for built-in events.
Raw strings, even valid wire names, are rejected; serialized event records still
use the existing string names. An undeclared custom spec, mismatched spec or
missing producer fails registry construction. Migrate older positional calls to
named arguments and replace event-name strings with enum members or custom specs.

A minimal second plugin is in
`libs/prebuilt/tests/analysis/test_runtime_access.py` (`Marker`). It uses the same
public result schema to mark `example.department.restricted`; its separate policy is
in `test_policy_bridge.py`. To give a plugin a custom event:

```python
from langgraph.prebuilt.analysis import EventSpec, Registry, AnalyzerRegistration

spec = EventSpec("example.document", "before", "document_adapter", True)
# analyzer implements the public Analyzer protocol.
registry = Registry(
    (spec,),
    (AnalyzerRegistration(
        analyzer_id="department",
        version="1",
        analyzer=analyzer,
        events={spec},
    ),),
    producers=frozenset({"document_adapter"}),
)
```

The application must actually emit the event and await the barrier at its document
admission boundary. `context.resolver.resolve(ref)` requires configured content
access and an in-scope reference. `context.provenance.ancestors(ref)` is scoped too.
Dependencies ensure upstream committed findings are available in
`context.prior_findings`. A benign finding cannot remove previous annotations.

Annotation and dependency proposals are additional restrictions. Registered domains
combine proposals with current labels. Plugins cannot remove mandatory edges,
declassify confidentiality, endorse integrity or mint grants. Integrity and
confidentiality retain the existing `SecurityLabels` representation. A future
trusted declassification/endorsement API is deliberately absent from this demo.

Run the contract and second-plugin checks:

```sh
cd libs/prebuilt
uv sync
uv run pytest tests/analysis/test_contracts.py tests/analysis/test_runtime_access.py tests/analysis/test_policy_bridge.py
```

## Optional static IFC

[StaticFlowPolicy](static-flow.md) adds a pre-execution information-flow gate to
manifest admission. It is independent of callback result formats and runtime
provenance. The same module exposes `check_manifest_flow` for plugin writers who
only want a static report. See [demo 14b](../../../workspace/14b_static_information_flow/README.md)
for actual admission rejection and the conservative scope of this check.

## Design policy: observation is not enforcement

Analysis callbacks support logging and developer-owned analysis results. They do
not add runtime argument-based detection gates. Existing runtime enforcement
mechanisms own authorization. Framework observer failures, return values and edits
to notification copies have no allow/deny channel. Demo 15 demonstrates this
separation with a real tool and a failing logger. Explicit structured security
modules are existing runtime-policy integrations, not authority granted to plain
callbacks. Static manifest admission remains a separate pre-execution control.
