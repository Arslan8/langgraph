# Instrumentation coverage

An event registry is not proof that a producer executes. `AnalysisConfig.coverage`
is an explicit composition-root report: each boundary is `instrumented`,
`explicitly_adapted` or `unsupported`. Strict configuration rejects required paths
listed as unsupported or absent. Applications must inventory their actual routes;
arbitrary callables and callbacks are not automatically instrumented.

| Boundary | Implemented integration |
| --- | --- |
| input.admit | Injected scheduler admission before graph work, plus prebuilt agent history admission; explicit BoundaryAdapter for standalone use |
| retrieval.request/result | Explicit RetrievalAdapter; each admitted chunk is a distinct value |
| context.transform.before/after | Explicit TransformAdapter; summary inherits all declared inputs |
| model.request/response | Final prebuilt prompt/provider sequence, static/dynamic and structured outputs; ModelAdapter for custom nodes |
| tool.propose/prepare/dispatch | Existing SecurityStack, ToolNode and direct guarded tools; fresh final request snapshot |
| tool.result/error | Tool result adapters and in-process ToolNode/direct guarded results; bounded explicit error adapter |
| resource.read/write/send | Explicit ResourceAdapter requires authoritative object and grant references |
| state/store/checkpoint | Existing object request translation plus explicit StateAdapter and authenticated CheckpointBinding |
| dispatch.child.start/return/branch.merge | Explicit DispatchAdapter with scope-transfer and selection references |
| output.emit | Existing secured graph output mediator and explicit OutputAdapter for external publications |
| interpreter operations | Explicit trusted InterpreterBoundary; no general interpreter |

## Unsupported or incompletely integrated paths

Unmediated Python/native I/O, direct provider callbacks that bypass graph output
mediation, arbitrary reducers/caches without declared input references, host-worker
internal accesses without resource instrumentation, and unadapted custom model
nodes are outside this runtime's tracking coverage. Mark required instances of those
paths unsupported; do not label them covered because an event name exists.

The generic boundary helpers expose sync/async barrier methods. Some convenience
adapters have only sync convenience methods; async integrations should use the
awaited `abefore`/`acall` boundaries directly. Provider-structured tool calls execute
only when complete messages reach the normal ToolNode path. No ordinary JSON parser
has been added. Graph streaming passes through the existing output mediator;
independent provider callbacks are not claimed to be gated by that mediator.

Opaque operations conservatively inherit the run context unless trusted
instrumentation supplies a complete influence scope. This may overrestrict heavily.
Host authority must be conservatively classified; `AnalysisFlowPolicy` denies
unclassified destinations, and `SessionFlowPolicy` remains responsible for atomic
read/send reservations. A returned-value label cannot prevent an internal side effect.

Automated evidence is in `tests/analysis/`. These tests do not establish complete
instrumentation of every route in a user graph, general noninterference, or sound
classification. The extension fixtures demonstrate finite public contracts, not
full reproductions of Progent or CaMeL.
