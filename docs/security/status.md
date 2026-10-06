# Implementation and freeze status

This page is the authoritative distinction between code that exists on the
branch and architecture accepted for later implementation. ADR 0007 describes
the target design; an accepted ADR is not evidence that its backend exists.

## Shipped decision layer

| Capability | Status | Current guarantee |
| --- | --- | --- |
| Tool effects and author DAC declarations | Implemented and tested | Metadata is preserved through tool conversion; undeclared tools default deny. |
| Authenticated principal binding | Implemented and tested | Identity is stored outside graph state and module blobs are private. |
| Seven-hook restrictive module stack | Implemented and tested | DAC runs first; modules cannot override denial; failure and timeout deny. |
| `ToolNode` mediation | Implemented and tested | Every physical callback execution, retry, and rewritten request is checked immediately before invocation. |
| Direct tool mediation | Implemented and tested | Calls through `guarded_tool` use the same decision stack. Other aliases are outside the boundary. |
| Delegation attenuation | Implemented and tested | Child scopes must be a subset and blobs are independently copied. |
| Durable approval | Implemented and tested | Escalation requires a checkpointer; resume rechecks policy; approval payloads omit arguments. |
| Hash-chained audit | Implemented and tested | In-memory and SQLite sinks detect record-chain tampering. This is decision evidence only. |
| Redacted observability | Implemented and tested | Memory, logging, OpenTelemetry-compatible, and LangSmith adapters expose no raw tool arguments. |
| Tool inventory | Implemented and tested | Static entries are collected; incomplete dynamic inventory is reported honestly. |
| Escape analysis | Implemented and tested | Source and CLI analysis report known and unresolved bypass paths. It must currently be run explicitly. |
| `.slp` grammar and constructive DAC | Implemented and tested | The parser, binding, need/want semantics, provenance, overrides, and monotonicity properties are shipped. |

## ADR 0007 phase one

| Step | Status | Freeze consequence |
| --- | --- | --- |
| 1. Profile grammar and monotonic DAC evaluator | Complete | The `.slp` grammar is frozen. |
| 2. Attributed kernel-facing `Grant` IR and descriptor path compilation | Not implemented | No `Grant` API is frozen. `ConstructiveGrant` is only the DAC candidate. |
| 3. Cedar integration and reference forbid policies | Not implemented | Cedar request construction and module forbid emission are not frozen. |
| 4. Backend interface, capability contract, attestation, audit changes, and `advisory` | Not implemented | Backend and expanded audit contracts are not frozen. |
| 5. Dedicated spawner and Landlock backend | Not implemented | There is no kernel confinement claim. |

The seven hook names and invocation structure are frozen. The detailed
`tool_call_permission` return contract remains open for the planned forbid-only
policy emission. The course-facing promise is a verdict with optional forbid
policies once Cedar integration lands.

## Phase two

The following accepted components are intentionally deferred until phase one
lands and is measured:

- broker credential custody and authenticated spawn records;
- AWS STS session policies and GitHub App installation token issuers;
- MCP per-call proxying;
- the native `slanggraph-exec` launcher;
- a second enforcing backend such as WASI or a microVM;
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

After phase-one steps 2 through 5 land and their capability contract passes,
local untrusted tool code will run only under an attested backend or an explicit
audited advisory exception. The final claim still excludes model final text,
domain-level egress without a broker or proxy, kernel bugs, and remote APIs that
cannot scope credentials.
