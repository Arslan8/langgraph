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
| Classified session scheduling | Implemented and tested when configured | Operator-supplied possible-read labels and outward-effect ceilings are joined and reserved atomically; same-call source/sink conflicts, cross-call races, and mediated session transfers are covered. This is not a hostile-code confidentiality claim until confinement validates the bounds and channels. |
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
| 2. Attributed platform-neutral `Grant` IR and resource selectors | Implemented and tested | `compile_grant` preserves source identity and `need`/`want`, marks runtime baselines, and emits a requirement ledger. |
| 3. Cedar integration and reference forbid policies | Partially implemented and tested | Modules emit attributed bounded `ForbidConstraint` and `ForbidCombination` values. The replaceable reference backend filters exact grants, subtracts filesystem subtrees, rejects unrepresentable broad differences, rechecks requirements, and fails on diagnostics. A Cedar backend is not yet shipped. |
| 4. `HostAttestation`, exact obligations, enforcement-adapter interface, activation receipts, transactional audit, and explicit degradation | Contracts implemented and tested; runtime wiring incomplete | Exact rule assessment, multi-adapter ownership, host trust verification, activation evidence, degradation, dispatch/outcome audit, and external chain seals exist. Tool execution is not yet routed through a native adapter. |
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
| Rule-specific negotiation | Implemented and tested as a platform-neutral contract | Resource classes are hints; exact operation, selector, conditions, dependencies, and complements are negotiated per obligation. No native adapter is wired to tool execution yet. |
| Closed-world default deny | Implemented and tested as a negotiation invariant | Every represented authority domain requires a non-waivable `DENY_COMPLEMENT` obligation. Runtime proof awaits the native adapter. |
| `need`/`want` revalidation | Implemented and tested through policy filtering and lowering | Source lineage survives DAC intersection, rule splitting, policy subtraction, waivers, and adapter selection. Activation-time reductions remain to be wired. |
| Host evidence trust and context binding | Implemented and tested as a contract | An explicit verifier checks nonce, freshness, and trust; activation binds boot, worker, namespaces, credentials, cgroup, broker epoch, plan, and obligations. A host probe/attestor is not yet shipped. |
| Worker activation receipt and lease invalidation | Activation receipt implemented; live invalidation not implemented | A receipt must cover every assigned obligation and exact worker context. The startup barrier and renewable dependency leases remain. |
| Multi-component enforcement | Implemented and tested as an obligation DAG | Each obligation has one explicit primary enforcer, dependencies are complete and acyclic, and activation evidence must cover all assigned obligations. Semantic obligation compilers and native adapters remain. |
| Advisory security claim | Implemented and tested in negotiation | Only explicitly waivable obligations may degrade; closed-world complements and required source lines cannot be waived. A waiver never retains authority while dropping its restriction, and no confinement or confidentiality claim applies to an unknown effective-authority bound. Runtime propagation remains. |
| Module output to Cedar | Typed forbid-only output implemented and tested | The framework owns module attribution and rejects spoofed or malformed outputs. Cedar translation remains replaceable backend work. |
| Broad-resource mandatory filtering | Implemented and tested in the reference backend | Filesystem child subtrees become explicit exclusions; unrepresentable conditional differences remove the broad rule and requirements are rechecked. |
| Cedar diagnostics and aggregate combinations | Backend diagnostics and aggregate combinations implemented; Cedar adapter not implemented | Any backend diagnostic denies; typed combinations can reject cross-domain authority sets. |
| Pre-confinement execution | Current decorators, tool construction, normalizers, hooks, and imports execute in the trusted process | Strict mode uses declarative manifests and imports tool code only after activation; custom transformations run confined and are reauthorized. |
| Ambient authority and runtime baseline | Baseline is specified; enforcement not implemented | Start from a clean worker, enumerate every retained capability, and include it in grant obligations and activation evidence. |
| Delegated labels and budgets | Scope subset and blob copying implemented and tested; richer semantics not addressed in code | Typed label partial orders and a shared atomic escrow ledger govern children. |
| Approval subject binding | Principal, roles, scopes, delegation, tool, call, raw and normalized arguments, expiry, and one-time use are implemented and tested | Artifact, final-grant, policy, ledger, and activation nonce binding require the strict execution path. |
| Atomic history, retries, audit outcomes, truncation | Dispatch/outcome states, pre-dispatch audit failure, post-dispatch `INDETERMINATE`, hash chains, and external seals are implemented and tested | Durable quota reservation, side-effect idempotency, outbox delivery, and automatic external witnessing remain. |
| Security disable/downgrade control | Reconfiguration and delegation downgrade are rejected and tested | A secured `ToolNode` cannot be replaced with another config and delegation must inherit or explicitly receive security. A signed immutable context for arbitrary dynamic descendants remains. |

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

Without `SessionFlowPolicy`, the claim remains per-execution resource access
control. With an operator-complete flow policy and shared durable store,
classified calls crossing `ToolNode` or `guarded_tool` receive atomic
source/sink scheduling; explicitly wrapped model and framework effects can use
`guard_operation()`, and mediated copies can use `transfer_session()`. These
labels prove confidentiality only when actual reads and outward channels are
bounded by trusted code or active confinement. Background descendants,
unmediated consumers, and copies that bypass transfer remain outside the claim.
See [security properties](security-properties.md) for the exact boundary.

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
