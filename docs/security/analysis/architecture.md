# Analysis runtime

slangGraph provides extensible instrumentation, provenance tracking and enforcement integration for externally supplied analyses. The Repeat-After-Me classifier is a replaceable demonstration module. Detection quality belongs to that classifier; the runtime enforces configured restrictions for the instrumented execution paths.

The implementation starts at `Arslan8/slanggraph` `wip`, base
`5bebea0ffbce3a68895deb266838291165719e1f`. Analysis is disabled by default.

## Observation versus enforcement

Plain analysis callbacks observe execution; they do not implement runtime argument-
based detection gates. Existing runtime security mechanisms own access decisions.
Observer failures are logged without changing the operation, and framework event
payloads are detached so callback mutations cannot rewrite arguments or results.
Caller cancellation and actual runtime/tool failures retain their existing behavior.
This is a separation of responsibilities for trusted plugins, not callback sandboxing.
Static manifest admission is a distinct pre-execution control. Existing structured
security-policy integrations remain explicit policies rather than callback authority.

## Optional result contracts

The core `Analysis` event dispatcher accepts ordinary callbacks and developer-owned
payloads. It returns callback outputs unchanged, including `None`. It does not
require tracked values, findings, identities, a database or a result schema.
Logging and private result ecosystems remain the developer's choice.
`ToolNode(..., analysis=analysis)` connects this dispatcher to real proposal,
preparation, dispatch, result and error boundaries. Tool events are not synthesized
by demo code. Other event families need their corresponding instrumentation.

`CallbackExecutor` handles execution for both plain callbacks and the structured
integration. `StructuredAnalysis` is the explicit local opt-in to that integration;
`AnalysisRuntime` supports its authenticated/persistent application use. Structured
validation, provenance and persistence are consumers of callback results, not
requirements imposed by the callback executor. Shared policy and inspection tools
require standardized findings at their integration boundary. Their validation and
fail-closed behavior remain in place; an arbitrary callback result grants no authority.

See [callback examples and migration](plugin-api.md). The rest of this document
describes the optional structured integration and its security guarantees.

## Ownership and dependency direction

`langgraph.prebuilt.analysis` owns versioned records, scheduling, canonical storage,
provenance, scoped access and boundary adapters. `analysis_plugins.repeat_after_me`
owns the classifier protocol, prompt, validation and example finding mapping.
`security.modules` owns restrictive policy interpretation. The example directory is
the composition root. Core `libs/langgraph` does not import this package; a narrow injected input-admission callback and existing security placement/output callbacks form the lower-level boundary. The core knows no analyzer or prebuilt types.

The reference monitor remains `SecurityStack`, with DAC, `SecurityModule` hooks,
HostRouter grants, and `SessionFlowPolicy` reservations. Analysis produces evidence,
not permissions. Its result schema rejects policy/rule/grant fields. The static
escape analysis in `security/taint.py` is unchanged.

## Immutable-policy invariant

The root loads `AnalysisConfig.policy_json` before a run. Its canonical digest is
the policy version in every snapshot and authenticated analysis checkpoint. Policy
modules must implement that preloaded configuration and must not change their rules
in response to findings. Analysis has no policy-installation or update API.
Approval remains one-operation input to the existing permission chain. It does not
change this digest or bypass another module's denial.

Each physical tool attempt constructs a fresh event and snapshot after argument
normalization and policy preparation. The binding includes principal/session,
roles/scopes, tool, normalized and actual arguments, invocation/attempt, and host
execution binding. Arguments are copied into immutable JSON structures in the
analysis-enabled path. Non-JSON injected objects fail closed instead of being
hashed using arbitrary object representations. This is a time-of-check/time-of-use
boundary, not permission to execute a historical snapshot.

## Runtime and trust

Required analyzers execute sequentially in deterministic dependency order before an
adapter proceeds. Sync execution uses bounded workers and deadlines; async execution
awaits plugins with deadlines and preserves cancellation. Plugin exceptions become
unavailable/failed records, never a clean result. A timed-out trusted Python thread
cannot be forcibly killed; its late result has no commit path. Analyzers are trusted
extensions, not sandboxed hostile Python.

Analysis contexts hold detached scoped content/provenance views and prior findings.
They do not expose graph state or the storage coordinator. The root owns identities,
mandatory edges, domain registration, storage credentials and interpreter bindings.

SQLite WAL transactions commit findings, annotations and dependency proposals;
short transactions create request snapshots. No transaction spans a model call.
Notifications reference committed snapshots and cannot authorize execution. The
in-memory backend is an isolated SQLite memory database with the same semantics.
Metadata is bounded by configured per-run record limits; exhaustion fails closed.
Explicit deletion/garbage collection is not exposed, so live checkpoint ancestry is
not silently discarded.

See [coverage](coverage.md), [information flow](information-flow.md),
[plugins](plugin-api.md), [developer access](developer-api.md) and
[extension contracts](extension-contracts.md).

## Optional static information-flow control

[Static IFC](static-flow.md) checks manifest-bounded read/input authority against
write and return clearances during source-bound tool admission. It rejects unknown
or incompatible bounds before execution and leaves the existing runtime grant and
body-identity checks intact. This is a conservative tool-local control for the
supported in-process subset, separate from callback delivery and runtime provenance.
