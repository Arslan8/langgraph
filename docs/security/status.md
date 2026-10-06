# Implementation and freeze status

This page is the authoritative distinction between code that exists on the
branch and architecture accepted for later implementation. ADR 0007 describes
the target design, and [grant lowering](lowering.md) specifies its negotiation
sequence; accepted documentation is not evidence that its adapters exist.

## Shipped decision layer

| Capability | Status | Current guarantee |
| --- | --- | --- |
| Tool effects and author DAC declarations | Implemented and tested | Metadata is preserved through tool conversion; undeclared tools default deny. |
| Authenticated principal binding | Implemented and tested | Identity is stored outside graph state and module blobs are private. |
| Seven-hook restrictive module stack | Implemented and tested | DAC runs first; modules cannot override denial; failure and timeout deny. |
| `ToolNode` mediation | Implemented and tested | Every physical callback execution, retry, and rewritten request is checked immediately before invocation. |
| Direct tool mediation | Implemented and tested | Calls through `guarded_tool` use the same decision stack. Other aliases are outside the boundary. |
| Scope delegation attenuation | Implemented and tested | Child scopes must be a subset and blobs are independently copied. Typed label ordering, exact-grant attenuation, and shared budgets are not implemented. |
| Checkpoint-compatible approval flow | Implemented and tested | Escalation requires a checkpointer; resume rechecks policy; approval payloads omit arguments. Current matching binds request, call, and tool identifiers only. |
| Hash-chained audit | Implemented and tested | In-memory and SQLite sinks detect modification inside the retained chain. They do not detect deletion of a valid suffix without an external head or terminal seal. This is decision evidence only. |
| Redacted observability | Implemented and tested | Memory, logging, OpenTelemetry-compatible, and LangSmith adapters expose no raw tool arguments. |
| Tool inventory | Implemented and tested | Static entries are collected; incomplete dynamic inventory is reported honestly. |
| Escape analysis | Implemented and tested | Source and CLI analysis report known and unresolved bypass paths. It must currently be run explicitly. |
| `.slp` grammar and constructive DAC | Implemented and tested | The parser, binding, need/want semantics, provenance, overrides, and monotonicity properties are shipped. |

## ADR 0007 phase one

| Step | Status | Freeze consequence |
| --- | --- | --- |
| 1. Profile grammar and monotonic DAC evaluator | Complete | The `.slp` grammar is frozen. |
| 2. Attributed platform-neutral `Grant` IR and resource selectors | Not implemented | No `Grant` API is frozen. `ConstructiveGrant` is only the DAC candidate. |
| 3. Cedar integration and reference forbid policies | Not implemented | Cedar request construction and module forbid emission are not frozen. |
| 4. `HostAttestation`, exact obligations, enforcement-adapter interface, activation receipts, transactional audit, and explicit degradation | Not implemented | Host, adapter, activation, and expanded audit contracts are not frozen. |
| 5. Dedicated spawner and Linux reference adapter | Not implemented | There is no host-confinement claim. |

The seven hook names and invocation structure are frozen. The detailed
`tool_call_permission` return contract remains open for the planned forbid-only
constraint emission. The course-facing promise is a verdict with optional typed,
forbid-only constraints once Cedar integration lands.

## Architecture-review disposition

The accepted target is specified in [grant lowering](lowering.md). The following
table prevents target prose from being mistaken for implementation evidence.

| Review area | Current status | Target disposition |
| --- | --- | --- |
| Rule-specific negotiation | Specified, not implemented | Resource classes are hints; exact operation, selector, conditions, dependencies, and complements are negotiated per obligation. |
| Closed-world default deny | Specified, not implemented | Every retained authority is a grant/baseline line and adapters attest denial of each owned domain's complement. |
| `need`/`want` revalidation | Initial DAC behavior implemented and tested; later stages not implemented | A requirement ledger is rechecked after policy filtering, lowering, and activation. |
| Host evidence trust and context binding | Not implemented | Authenticated attestation is trust-anchored and bound to boot, worker, namespaces, credentials, cgroup, adapter, nonce, and freshness. |
| Worker activation receipt and lease invalidation | Not implemented | A startup barrier releases import only after a verified worker-specific receipt and audit precommit; live dependencies are leased. |
| Multi-component enforcement | Specified, not implemented | A semantic rule expands into an obligation DAG; each obligation has one primary enforcer and all required dependencies must activate. |
| Advisory security claim | Evaluation-only projection exists; runtime not implemented | Waivers produce `DEGRADED`, suspend the full subset claim, enumerate missing guarantees, and cannot waive baseline invariants. |
| Module output to Cedar | Current verdict API implemented; typed constraint output not implemented | Modules emit bounded typed labels/forbid constraints, never arbitrary Cedar text, and are pinned TCB components. |
| Broad-resource mandatory filtering | Not implemented | Use sound resource-set difference, complete per-operation brokering, or reject the rule; a representative request is insufficient. |
| Cedar diagnostics and aggregate combinations | Not implemented | Any diagnostic denies; both per-line and aggregate candidate checks run. |
| Pre-confinement execution | Current decorators, tool construction, normalizers, hooks, and imports execute in the trusted process | Strict mode uses declarative manifests and imports tool code only after activation; custom transformations run confined and are reauthorized. |
| Ambient authority and runtime baseline | Baseline is specified; enforcement not implemented | Start from a clean worker, enumerate every retained capability, and include it in grant obligations and activation evidence. |
| Delegated labels and budgets | Scope subset and blob copying implemented and tested; richer semantics not addressed in code | Typed label partial orders and a shared atomic escrow ledger govern children. |
| Approval subject binding | Request/call/tool matching and recheck implemented and tested; full intent binding not implemented | One-time expiring approval binds principal, artifact, normalized intent, authority, policy, ledger, and nonce. |
| Atomic history, retries, audit outcomes, truncation | Atomic call indexes and thread-safe append are implemented and tested; the stronger properties are not addressed | A durable authorization transaction, idempotency contract, `INDETERMINATE` outcome, outbox, terminal seal, and external witness are required. |
| Security disable/downgrade control | Root configuration and static propagation exist; monotonic inheritance is not guaranteed | A secured root issues an immutable context inherited by every descendant/resume/retry; missing or weaker context fails closed. |

## Phase two

The following accepted components are intentionally deferred until phase one
lands and is measured:

- service-adapter credential custody and authenticated spawn records;
- AWS STS session policies and GitHub App installation token issuers;
- MCP per-call proxying;
- the native `slanggraph-exec` launcher;
- a second host adapter such as Windows isolation, WASI, or a microVM;
- AgentDojo, InjecAgent, and ASB evaluation harnesses; and
- the vulnerable-tool comparison used by the paper.

None of these names is a shipped public API.

## Present security claim

The present branch can claim complete mediation only for calls crossing a
configured `ToolNode` or the returned `guarded_tool` wrapper. It cannot claim
process-wide MAC, confinement of an allowed tool, syscall enforcement,
credential isolation, or automatic compile-time rejection of every analyzer
finding.

For untrusted tool code today, use an external OS sandbox and run
`langgraph-security-taint` as an explicit CI gate. Do not treat an allow verdict,
effect declaration, profile grant, audit record, or accepted ADR as evidence of
kernel enforcement.

## Target security claim

After phase-one steps 2 through 5 land and exact obligation negotiation passes,
local untrusted tool code will run only after a verified worker-specific activation
receipt. A waived obligation produces an explicitly `DEGRADED` result for which
the complete grant-subset claim is not made. The final claim still excludes model
final text, kernel or trusted-adapter bugs, and remote APIs that cannot scope
credentials; missing domain-level egress mediation prevents an enforced result.
