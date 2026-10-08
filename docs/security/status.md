# Implementation and freeze status

This page is the authoritative distinction between code that exists and the
target accepted by [ADR 0007](adr/0007-kernel-enforced-confinement.md). A row
marked planned or partial cannot support a complete-mediation or layered
reference-monitor claim.

## Model

The target is a layered reference monitor: LangGraph is a user-space object
manager for ten framework object classes, the host kernel monitors OS objects,
and the two compose into the system reference monitor.

> An operation is in scope if and only if a hook on the single dispatch path can refuse it.

Shipped policy defaults never narrow this scope. `HostRouter` is the target
single dispatch path; `ToolNode` and `guarded_tool` are callers into it, not
independent completeness boundaries.

## Per-operation coverage

`Implemented` means the operation has current code and focused tests. `Partial`
means related enforcement exists but does not yet meet ADR 0007. `Planned`
means the new refusing hook or route is not shipped.

| Class | Operation | Target hook/enforcer | Current coverage | Evidence or gap |
| --- | --- | --- | --- | --- |
| Principal | `bind` | `cred_prepare` | Implemented | Authenticated principal binding and private module blobs are tested. |
| Principal | `transfer`, `attenuate` | session transfer, `cred_transfer`, subset check | Partial | Every explicit router dispatch checks the child subset and runs `cred_transfer`, including identity transfers; automatically discovering every framework dispatch and every minted credential remains open. |
| ToolCall | `prepare`, `invoke`, `post` | three existing tool-call hooks through `HostRouter` | Partial | Host-confined `ToolNode` and `guarded_tool` execution enters the verified router; their trusted in-process compatibility paths still execute outside it. |
| Dispatch | subgraph, `Send`, parallel branch, subagent, nested agent | `cred_transfer` plus child-subset check | Partial | All five sync/async router forms and completeness tests exist. Tool-call parallel branches use the identity-transfer route; general subgraph, `Send`, subagent, and nested-agent placement is not automatic. |
| ToolRegistry | static `register`, `override` | `tool_alloc_security`, inference, audit | Implemented | The object manager routes static registration and audited overrides through allocation and inference. |
| ToolRegistry | dynamic `register` | `tool_alloc_security`, runtime inference | Partial | Runtime allocation and undeclared default-deny exist; arbitrary application mutation of registries is not intercepted. |
| State | `write` | `state_write` | Partial | The refusing router entry and object-manager effect exist; general graph state writes are not yet rewritten through it. |
| State | `restore` | `state_restore`, hash chain, principal binding | Implemented | Object-manager restore verifies the keyed hash chain, predecessor, monotone sequence, and principal binding and rejects replay. Core checkpointer adapters are not yet routed automatically. |
| State | `tool_read`, `model_read` | `state_read` | Partial | Tool reads use profile-declared channel sets and receive a sanitized runtime with only principal ID and declared resources. General model prompt assembly is not yet routed automatically. |
| State | `store_read`, `store_write` | `state_read`, `state_write` on owned/labeled keys | Partial | Store keys have owners and labels and ToolRuntime access uses the mediated wrapper; other direct Store references remain outside placement. |
| Approval | `resume` | `resume_permission`, then full permission chain | Implemented | Sync/async router resume consumes one call-bound approval and reruns the complete authorization chain before dispatch. |
| FrameworkOp | `guard_operation` | existing guarded operation path | Implemented | Explicitly wrapped operations are mediated; placement is not automatic. |
| ModelInvocation | `invoke` | `model_invoke` | Partial | Sync/async deny-or-strip routing exists and strips before host prompt assembly; normal LangGraph model nodes are not yet automatically placed on it. |
| Output | `emit(destination)` | `output_emit` | Partial | Sync/async allow, deny, redact, and escalate routing exists with labels and destination clearance; ToolRuntime stream output uses it, but every framework publication API is not yet placed. |
| HostResource | `file` | grant lowered to kernel | Implemented | The namespace-free Landlock executor builds descriptor-based rules in the parent; granted/second-file, raw `open(2)`, grandchild, and `openat2` magic-link tests pass. |
| HostResource | `socket` | grant lowered to kernel/proxy | Partial | ABI 4+ port rules lower to Landlock, while phase one tightens them with seccomp to no network. Endpoint/name enforcement remains phase two. |
| HostResource | `exec` | Landlock `EXECUTE` plus syscall policy | Partial | Target-specific `EXECUTE` lowering exists; phase one tightens execution to no new exec in the worker. |
| HostResource | `syscalls` | seccomp class filter | Implemented | Socket/connect fail with `EPERM`; ptrace, process-vm read, BPF, and unshare kill the worker. The default filter is installed after fd cleanup and Landlock restriction. |
| HostResource | `limits` | cgroup v2, rlimits, supervisor | Implemented | A fresh cgroup is configured and the worker's membership is verified before `GO` when CPU, memory, and PID controllers are delegated. `cgroup.kill` owns descendant teardown. Rlimits and pidfd are the recorded tighter fallback when delegation is unavailable. |

No completeness claim is made for `ToolNode` or `guarded_tool` separately.
Their target tests establish only that they call `HostRouter`; completeness is
tested once per router entry point.

## Per-authority coverage

| Authority | Intended primary enforcer | Current state | Required before claim |
| --- | --- | --- | --- |
| Framework principals and delegation | coordinator and policy evaluator | Partial | Explicit router dispatches have one subset check; placement for every implicit dispatch and minted credential remains. |
| Tool arguments and invocation | `HostRouter` hook stack | Partial | Host-confined execution routes through it; trusted in-process compatibility remains outside the certificate. |
| State channels | coordinator object manager | Partial | Refusing hooks, routes, profile-declared reads, and ToolRuntime mediation exist; core state channels are not automatically rewritten. |
| Store keys | coordinator object manager | Partial | Owner/labels and same-/cross-principal tests exist; direct references need placement. |
| Checkpoints | coordinator object manager | Partial | Hash-chain verification, replay defense, and principal binding exist in `ObjectManagerHost`; checkpointer integration remains. |
| Model context | coordinator object manager | Partial | Pre-assembly stripping and audit events exist at the router; model-node placement remains. |
| Output destinations | coordinator object manager | Partial | Full verdict and clearance handling exists at the router; publication placement remains. |
| Filesystem reads/writes | Landlock | Implemented | ABI-probed descriptor lowering and the required denial tests pass. |
| Network ports | Landlock where available | Partial | Port semantics only, tightened to no network in phase one; no endpoint claim. |
| Network endpoints/names | trusted proxy or broker | Phase two | Broker custody and destination scoping. |
| Executable targets | Landlock `EXECUTE` | Partial | Target-specific lowering and clean-fd activation exist; current phase-one syscall policy tightens it to no new exec. |
| Syscall classes | seccomp | Implemented | Required errno/kill actions are active; receipts record their relation. |
| CPU, memory, PIDs | cgroup v2 | Implemented | Delegated controllers are attested; each call gets a fresh configured leaf and verified worker assignment before release. The absence of delegation selects the recorded rlimit fallback. |
| File descriptors | `RLIMIT_NOFILE` and clean fd table | Implemented | Worker closes every non-protocol descriptor before `restrict_self`; no `O_PATH` descriptor enters it. |
| Wall clock | supervisor timer plus `cgroup.kill` or pidfd kill | Implemented | The supervisor owns the timer; delegated hosts kill the complete call cgroup, while other hosts use the recorded pidfd fallback. |
| Service credentials | phase-two broker and resource issuer | Phase two | No token in worker environment/fd table; scope equals the service rule. |

## Shipped foundation

The current branch contains the following foundations, each narrower than the
target operation table:

- author DAC declarations, default deny for undeclared tools, principal binding,
  and the seven existing restrictive hooks;
- ToolNode and direct guarded-tool checks, approval/resume, scope attenuation,
  hash-chained audit, and redacted observability;
- session-flow scheduling for configured tool rules and explicit
  `guard_operation`/session-transfer calls;
- static inventory, source escape analysis, API conformance, bounded
  authorization-state analysis, and a 21-entry `HostRouter` certificate now
  used by host-confined `ToolNode` and `guarded_tool` dispatch;
- `.slp` profile parsing, constructive DAC, an attributed grant IR, forbid-only
  constraint values, Cedar forbid-wins evaluation with one ephemeral permit per
  surviving DAC line, obligation negotiation, attestation types, activation
  receipts, and explicit degradation; and
- object-manager entry points for dispatch, registry, state/store, checkpoint,
  model invocation, output, and call-bound approval; and
- a namespace-free Landlock-primary executor with descriptor-based rules,
  seccomp, per-call cgroup v2 assignment where delegated, rlimit fallback,
  supervisor timeout, cgroup/pidfd kill, and per-rule receipts.

These features do not yet establish the ten-class object-manager claim. The
remaining gap is placement: general graph state/checkpoint APIs, model nodes,
publication APIs, and four non-parallel dispatch forms are not automatically
routed. Trusted in-process tool compatibility also remains outside the router.
Zero-or-waived disposition of the escape findings is not shipped. The Cedar
backend is the default and fails closed if its CLI, validation, evaluation, or
output is unavailable or malformed.

## Path-cover status

| Required path | Status |
| --- | --- |
| Model proposes a tool call | Partial: configured host-confined calls use the verified router; trusted in-process compatibility remains outside it. |
| Proposal arrives via subgraph, `Send`, or subagent | Partial: the refusing forms exist, but automatic framework placement is pending. |
| Injected content changes an argument | Implemented for secured Tool APIs: prepare transforms are normalized and the effective request is rebound before dispatch. |
| Injected content is written to state and read later | Partial: labeled object-manager storage is mediated; core state placement is pending. |
| Tool result carries a secret into model context | Partial: `model_invoke` strips labeled values; automatic model-node placement is pending. |
| Another thread's data arrives via store | Implemented through `MediatedStore`; direct Store references remain a placement finding. |
| Tampered or replayed checkpoint | Implemented in object-manager restore; checkpointer integration remains a placement finding. |
| Runtime tool lacks a profile | Implemented on the object-manager registration path: inference runs and undeclared DAC is empty/default-deny. |
| Human approval | Implemented: call-bound resume runs the complete chain again. |
| Tool touches the OS | Implemented for the Landlock filesystem subset; all other unsupported classes deny or require an explicit linter waiver. |
| Output goes to a lower-clearance destination | Implemented at `output_emit`; automatic publication placement is pending. |
| Child output returns to parent | Partial: labels can be attached and emitted, but child-return placement is pending. |

The compile gate is not complete. Findings must reach zero or be individually
waived with reasons before the target coverage claim is enabled.

## Host capability and lowering status

The shipped attestation probes Landlock ABI by calling
`landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`, cgroup v2 delegation and `cgroup.kill`,
unprivileged user namespaces, BPF LSM, Landlock audit, and the mechanism used
per call. Kernel-version inference is not acceptable.

Each grant rule must be reported as `exact`, `tightened`, or `unsupported`.
Looser lowering denies. Unsupported classes deny unless explicitly waived per
class with a reason; all affected call records say `unenforced`. A
module-introduced class is rechecked at grant time and denies if unsupported.
`slanggraph check --backend X profiles/` uses the same probes and returns
nonzero for an unsupported unwaived class. Class waivers require a reason and
are stamped `unenforced`; grant-time rechecking denies module-introduced
unsupported authority. On a delegated host, the execution backend creates and
configures a fresh cgroup, assigns and verifies the worker before release, and
uses `cgroup.kill` for descendants. Without delegation it records the rlimit and
pidfd fallback. Combined cgroup/rlimit rules remain `tightened`, never silently
looser than the grant.

## Freeze schedule

Frozen now:

- the seven existing hook names; and
- their invocation structure.

Not frozen:

- the `tool_call_permission` return contract;
- `Grant` and Cedar request construction;
- the backend contract and audit schema; and
- signatures for `state_write`, `state_restore`, `state_read`, `model_invoke`,
  and `output_emit`.

The `.slp` profile grammar freezes after PR 1. `Grant` and Cedar request
construction freeze after PR 3. Backend and audit contracts freeze after PR 4.
The course contract promises only the hook names and "return a verdict,
optionally emit forbid policies."

## Ordered delivery

The phase-one order is:

1. single-path `HostRouter`, with `ToolNode` and `guarded_tool` as callers;
2. router entry points and hooks for Dispatch, ToolRegistry, State,
   ModelInvocation, and Output;
3. mediated `ToolRuntime` injection without `RunnableConfig`;
4. verified, principal-bound restore and owned/labeled store keys;
5. dynamic registration with allocation and undeclared inference;
6. compile gate, rejection of in-process untrusted code, and disposition of all
   56 findings; and
7. PRs 1–5 for grammar/DAC, Grant, Cedar, backend contract, and the
   Landlock/seccomp/cgroup/spawner implementation.

The estimate is approximately five weeks for phase one. It should be revised at
the next check-in if implementation evidence shows that is no longer credible.

Phase two contains broker credential custody, scoped tokens, MCP stdio proxying,
`slanggraph-exec`, a second `wasi` or `microvm` backend, and the evaluation
harness.

## Claim gate

No guarantee is printed until the ADR 0007 kernel, contract, object-model,
read/output, and Cedar tests pass under both `invoke` and `ainvoke`. In
particular, an accepted ADR, allow verdict, declared effect, profile, grant, or
adapter capability name is not evidence of enforcement. The audit must carry
the verified hook decision, lowering result, attestation, and activation
evidence for the operation.
