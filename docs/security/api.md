# Public security API

Everything exported by `langgraph.prebuilt.security` is listed here. Most
applications need only declarations, `Principal`, `SecurityConfig`, a mediation
entry point, and an audit sink. The lower-level records are public so policy,
analysis, and operator tooling can use stable typed values instead of private
framework objects.

## Constants and registries

| Name | Contract |
| --- | --- |
| `PRINCIPAL_CONFIG_KEY` | Reserved `RunnableConfig` key used by `with_principal` and `principal_from`. Application state and model-visible data must not write it. |
| `NORMALIZERS` | Immutable registry of built-in resource normalizers: `realpath`, `domain`, `email_domain`, `sql_statement_kind`, and `shell_argv0`. |

## Tool declarations and author DAC

| Name | Contract |
| --- | --- |
| `Effect` | Enum containing `READ`, `WRITE`, `NETWORK`, `EXEC`, `DELEGATE`, and `SEND`. |
| `ResourceArg` | Declares a resource-bearing argument, its resource kind, optional normalizer, and whether the resource is local or remote. |
| `ToolDescriptor` | Immutable materialized tool name, effects, resources, sensitivity, reversibility, and extra metadata. |
| `ToolDac` | Immutable author DAC: owner, execute grants, required scopes, and value-specific normalized argument grants. |
| `DacOverrides` | Immutable operator replacements. `values` replaces legacy `ToolDac` entries; `profiles` replaces complete `ToolProfile` entries. Unknown tool names fail configuration. |
| `effects` | Decorator that attaches a descriptor to a function or `BaseTool`. At least one effect is required. |
| `dac` | Decorator that attaches author-proposed call authorization to a function or `BaseTool`. |
| `normalize_resource` | Applies the normalizer selected by a `ResourceArg`; it returns the original value when no normalizer is named. Errors fail the call closed. |
| `dac_check` | Pure decision function over a `Principal`, `Tool`, and normalized argument map. It runs before policy modules. |

The common declarations are:

```python
@dac(
    owner="analyst",
    grants={"analyst": "x", "*": "-"},
    required_scopes={"fs:read"},
)
@effects(
    Effect.READ,
    resources=[ResourceArg("path", "path", "realpath")],
)
def read_file(path: str) -> str:
    ...
```

An undeclared tool is inferred as critical, irreversible execution with a
default-deny DAC. A declaration describes intended behavior; it does not
confine the implementation.

## Identity, calls, and private module state

| Name | Contract |
| --- | --- |
| `Principal` | Authenticated user ID, immutable roles and scopes, session ID, optional delegator, and private module blobs. |
| `Tool` | Security representation used by policy: public name, DAC, effects, resources, and private module blobs. |
| `ToolCall` | Immutable physical-call request containing raw arguments, normalized resources, call ID and index, and prior audit history. Raw arguments must not be copied into audit or approval payloads. |
| `Slot` | Thread-safe mutable mapping owned by one module for one principal or tool. `snapshot()` returns an immutable copy. |
| `Blobs` | Thread-safe mapping from module name to independent `Slot` values. |
| `allocate_blobs` | Allocates one empty slot for each unique module name. |
| `copy_blobs` | Copies all or selected slots without sharing their mutable mappings. |
| `with_principal` | Copies a runnable config, prepares module credential slots, and binds the authenticated principal outside graph state. |
| `principal_from` | Reads the bound principal from runnable config or runtime context and returns `None` when absent. Invalid reserved values fail closed. |
| `SecurityBindingError` | Raised when a module fails while preparing a principal binding. |

`Principal`, `Tool`, and `ToolCall` are frozen records. Their nested `Blobs`
remain mutable only through module-owned slots.

## Decisions, modules, and mediation

| Name | Contract |
| --- | --- |
| `Verdict` | Enum containing `ALLOW`, `DENY`, `TRANSFORM`, and `ESCALATE`. |
| `Decision` | Immutable verdict plus a reason. `TRANSFORM` requires `new_args`; `ESCALATE` requires an `EscalationRequest`; allow and deny carry neither. |
| `EscalationRequest` | Redacted request ID, reason, tool and call IDs, and safe metadata. `to_payload()` never includes tool arguments. |
| `Approval` | Human response containing request ID, boolean decision, approver, and optional reason. |
| `SecurityModule` | Base class exposing the seven hooks: allocation, credential preparation and transfer, call preparation, call permission, post-call observation, and resume permission. |
| `CapModule` | Framework-owned first module. It prevents scope growth and rejects negative approval input. Applications do not register it manually. |
| `SecurityStack` | Restrictive composition engine for DAC, capability checks, ordered modules, timeout handling, audit, and observation. Application code normally creates `SecurityConfig` instead. |
| `SecurityConfig` | Frozen configuration for modules, DAC overrides, audit sink, observer, policy timeout, and principal requirement. It configures `ToolNode` directly or through `StateGraph.compile`. |
| `SecurityDeniedError` | `PermissionError` subclass raised when a guarded direct call or delegation is denied. `ToolNode` instead returns an error `ToolMessage`. |
| `guarded_tool` | Wraps a callable or `BaseTool` so direct sync and async invocation crosses the same security stack as `ToolNode`. Other aliases to the original callable remain unguarded. |
| `delegate` | Wraps a child runnable with an explicit scope subset, independent copied blobs, and `delegated_by` provenance. Scope growth is denied. |

Modules are independently restrictive. An allow never overrides another deny.
Malformed return values, exceptions, and timeouts become denials. A transform is
normalized and checked by DAC again before permission hooks run.

## Audit and observability

| Name | Contract |
| --- | --- |
| `AuditRecord` | One hash-chainable stage record: call index, tool, user and session IDs, argument hash, stage, module, verdict, reason, previous hash, and record hash. |
| `AuditSink` | Protocol requiring `write`, `records`, and `verify`. |
| `MemoryAuditSink` | Thread-safe process-local hash-chained sink. Useful for tests and short-lived runs. |
| `SqliteAuditSink` | Thread-safe SQLite WAL sink using full synchronization and a SHA-256 chain. Call `close()` during shutdown. |
| `SecurityEvent` | Redacted policy observation with stage, module, verdict, reason, latency, identity, call index, and argument hash. |
| `SecurityObserver` | Protocol consuming `SecurityEvent` values. |
| `MemorySecurityObserver` | Thread-safe event collector with verdict counters. |
| `LoggingSecurityObserver` | Emits structured, argument-free records through standard logging. |
| `OpenTelemetrySecurityObserver` | Adapter for compatible tracer and counter objects without adding a hard OpenTelemetry dependency. |
| `langsmith_metadata` | Converts a `SecurityEvent` into redacted metadata suitable for a LangSmith run. |

Audit is decision evidence, not kernel evidence. The current records cannot show
that an allowed tool stayed within its declaration; see [implementation status](status.md).

## Inventory and escape analysis

| Name | Contract |
| --- | --- |
| `ToolInventoryEntry` | One statically discoverable tool, descriptor, DAC, graph path, source, and compile-time labels. |
| `ToolInventory` | Tuple of entries plus `complete`, which is false when dynamic sources prevent a complete static inventory. |
| `introspect` | Walks a compiled graph, nested wrappers, and registered guarded tools to produce a `ToolInventory`. |
| `EscapeKind` | Enum classifying unmediated nodes, unknown callbacks and calls, dynamic dispatch, unprotected compilation, retained capabilities, direct invocation, dangerous sinks, and undeclared effects. |
| `EscapeSeverity` | Finding priority enum. |
| `EscapeFinding` | Source path, location, kind, severity, symbol, enclosing function, taint flag, message, and stable fingerprint. |
| `TaintReport` | Immutable findings and parse errors. Its JSON form is used by CI tooling. |
| `analyze_source` | Scans one or more Python paths and optional exclusions for routes around tool mediation. |

The `langgraph-security-taint` command is the CLI over `analyze_source`. It exits
nonzero for findings or parse errors. Today it is an explicit CI command; wiring
it into `compile()` with audited exceptions is planned, not shipped.

## Constructive profile model

The profile objects are immutable. Most users call `parse_profiles` and
`ProfileDocument.evaluate`; policy generators and tests may construct the
lower-level records directly.

| Name | Contract |
| --- | --- |
| `Requirement` | Enum with `NEED` and `WANT`. Removing a need denies the call; removing a want records the loss and continues. |
| `SourceLocation` | Source name, line, and column for diagnostics and provenance. |
| `PathTemplate` | Absolute path template with variable binding and an optional terminal `/**` subtree. |
| `BoundPath` | Canonical absolute path plus subtree flag. `contains()` implements exact/subtree containment without filesystem resolution. |
| `FsRule` | Filesystem operations, path template, optional requirement, and source location. |
| `NetRule` | TCP `connect` or `bind`, a literal or bound port, optional requirement, and source location. |
| `ExecRule` | Executable path template, optional requirement, and source location. |
| `NamedRule` | Service or credential kind with immutable string attributes, optional requirement, and source location. |
| `ShareRule` | Filesystem authority shared with one user or role. |
| `Limits` | Optional positive CPU milliseconds, memory bytes, PID count, open-file count, and wall-clock milliseconds. |
| `ToolProfile` | Parsed tool-owned constructive policy: callers, scopes, run locus, delegability, syscall sets, resources, limits, and output class. |
| `PrincipalProfile` | Principal roles, scopes, resource envelope, credentials, and outbound shares. |
| `BoundFsRule` | Surviving filesystem operations and bound path with source provenance. |
| `BoundNetRule` | Surviving TCP operation and integer port with source provenance. |
| `BoundExecRule` | Surviving executable path with source provenance. |
| `BoundNamedRule` | Surviving service kind and bound attributes with source provenance. |
| `ConstructiveGrant` | Result of DAC intersection before mandatory policy and adapter lowering. It is not the platform-neutral final `Grant` planned by ADR 0007. |
| `RemovedLine` | Resource class, need/want requirement, reason, and source for a candidate removed during intersection. |
| `DacEvaluation` | Constructive grant, removed lines, denial flag, and optional denial reason. |
| `ProfileDocument` | Immutable tool and principal maps. `evaluate()` also gathers applicable inbound shares and supports full operator overrides. |
| `ProfileSyntaxError` | Parse error carrying source, line, column, and message. |
| `parse_profiles` | Parses a complete `.slp` string into a `ProfileDocument`. |
| `evaluate_dac` | Low-level intersection of one `ToolProfile`, one `PrincipalProfile`, normalized arguments, principal bindings, and prefiltered inbound shares. |

Canonical path strings are a parser/evaluator invariant, not a TOCTOU defense.
Each enforcing adapter must resolve resource objects safely for its platform. The
Linux reference adapter will use descriptors as specified by ADR 0007; other
platforms may use different native object identities behind the same contract.

The planned `HostModel` is separate from both the final `Grant` and adapter set.
It will contain an attested, platform-neutral inventory of capabilities available
on the current machine. Execution will fail closed when a grant requires a host
capability that the selected host does not provide, even if an adapter implements
that capability on other hosts.

## Exceptions and fail-closed behavior

The package deliberately uses ordinary Python exception families at its
boundaries:

- declaration and profile construction errors use `TypeError` or `ValueError`;
- profile text errors use `ProfileSyntaxError`;
- principal preparation errors use `SecurityBindingError`;
- guarded runtime denials use `SecurityDeniedError`; and
- `ToolNode` converts runtime denials into error tool messages.

Policy exceptions do not escape as authorization success. The stack attributes
them to the module, audits the failure when configured, and denies the call.
