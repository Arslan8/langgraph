# Runtime operations (pandas)

The runtime exposes a finite list of operations to the pandas application.
Anything not in this list is refused or excluded. The machine-readable catalog
is [`runtime-operations.json`](runtime-operations.json). It is checked against
the current sources by
`langgraph.prebuilt.security.operation_catalog.verify_catalog`. That check is
required as `operation-catalog` by SGV901 on all six supported routes.
It checks catalog consistency; it does not prove arbitrary application effects.

## Decisions

- **D8, finite surface.** The runtime exposes a finite set of well-defined
  operations, bounded by what the evaluation needs. Everything else is refused.
- **D9, LLM calls are a hook.** The hook asks policy before a call made through
  the runtime's model operation. A deny means the LLM is never called. The
  runtime does not guarantee what the model receives or returns.
- **D10, pandas only.** This catalog covers the pandas application only.
- **D11, trusted application.** Application graph code and the framework are
  trusted. Only tool implementations and generated code are contained. See
  [threat-model.md](threat-model.md).

## Operations

Pandas steps refer to the rows of section 1 of
`eval/scope/pandas-route-design.md`.

| Operation | What it does | Trust (D11) | Route | Proof | Pandas steps |
| --- | --- | --- | --- | --- | --- |
| `compute` | Runs generated code in the Linux worker (`LinuxSandboxExecutor`, Lean receipt checker) | contained | `linux-worker-compute` | proved | W3, V4, P5 |
| `output_publish` | `OutputMediator` -> `HostRouter.output_emit` -> `ObjectManagerHost` | proved egress | `output-publication` | proved | P3 |
| `model_invoke` | Policy hook before an LLM call (`HostRouter.model_invoke`, `MODEL_CALL` node) | hooked | `model-invoke-hook` | proved (hook only) | none required; O2, W2, W5, V2, V3, V6 may use it |
| `tool_dispatch` | Exact `ToolNode` through `HostRouter` to a contained tool | contained | `tool-node-dispatch`, `language-sandbox-tool` | proved | none (no third-party tools) |
| `state_read` | `StateRequest` `TOOL_READ`/`MODEL_READ` via `HostRouter.state` | trusted runtime | none | premise | W3, V4 |
| `state_write` | `StateRequest` `WRITE` from mediated nodes | trusted runtime | none | premise | none |
| `checkpoint` | Checkpoint read, write and restore via `MediatedCheckpointer` | trusted runtime | none | premise | none (`checkpointer=None`) |
| `approval_resume` | `HostRouter.resume` after a bound approval | trusted runtime | none | premise | none |
| `dataset_read` | Pinned, authorized, bounded dataset read (`read_dataset` in `security/dataset_operation.py`) | trusted runtime | `dataset-read` | source-derived ordering and byte correspondence, with live controls | D1 |

Under D11 the pandas node functions also call the LLM directly. Those calls are
trusted application behavior and are not policed by the `model_invoke` hook.

Framework operations from `layered_verification.OPERATIONS` that pandas does not
use are listed under `excluded` in the JSON, each with its refusal code or
reason: `Principal.transfer`, `Principal.attenuate`, all `Dispatch.*` forms,
`ToolRegistry.register`, `ToolRegistry.override`, `State.store_read`,
`State.store_write` and `FrameworkOp.guard_operation`.

## What the check verifies

`verify_catalog(repo)` reads only the current sources and manifests. It checks
that:

- cited request classes exist in `security/objects.py`;
- cited router methods exist on `HostRouter`;
- cited functions and classes exist (parsed with `ast`, never imported);
- every refusal code is registered in `security/unsupported.py` (`REGISTRY` or
  `PREFIXES`) or is a string literal raised in the cited file;
- every supported route in `supported-surface.json` maps only to catalogued
  operations, and every proof check id is required by that route;
- every `OPERATIONS` entry is mapped to an operation or excluded.

`complete` is true only when all of these pass and no operation is `missing` or
`in_progress`.

## Adding an operation

Add one operation at a time. There is no generic fallback operation: a request
that matches no catalogued operation is refused.

1. **Contract.** Define a frozen request type with bounded input and output
   shapes. State the policy hook, the effect, the refusal codes and the trust
   class under D11.
2. **Enforcement.** Implement the operation behind `HostRouter` or a dedicated
   mediator. Register every refusal code in `security/unsupported.py`.
3. **Proof.** Add or extend a route in `supported-surface.json` whose
   obligations name the checks that discharge it. Record any premise
   explicitly.
4. **Tests.** Add positive tests and refusal tests for every code.
5. **Gate check.** Add the entry to `runtime-operations.json` with its
   citations, routes, proof status and pandas steps. `verify_catalog` must
   report no issues before the operation counts as `implemented`.
