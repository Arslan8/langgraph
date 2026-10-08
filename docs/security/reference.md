# Security model and behavior reference

The public API lives in `langgraph.prebuilt.security`. This page describes the
accepted target model. [Implementation status](status.md) identifies which
parts are shipped; accepted design is not implementation evidence.

## Layered reference monitor

slangGraph is LangGraph's user-space object manager for framework-owned
objects. The host kernel mediates OS objects from the compiled grant. The
composite is the system reference monitor.

> An operation is in scope if and only if a hook on the single dispatch path can refuse it.

`HostRouter` is that single dispatch path. `ToolNode` and `guarded_tool` are
callers into it, not peer boundaries. An unplaceable path fails compilation.

## Object classes

| Class | Operations | Hook or enforcement |
| --- | --- | --- |
| Principal | `bind`, `transfer`, `attenuate` | `cred_prepare`, session transfer, `cred_transfer` |
| ToolCall | `prepare`, `invoke`, `post` | `tool_call_prepare`, `tool_call_permission`, `tool_call_post` |
| Dispatch | `subgraph`, `Send`, `parallel_branch`, `subagent`, `nested_agent` | `cred_transfer` and explicit child-subset check |
| ToolRegistry | static/dynamic `register`, `override` | `tool_alloc_security`, inference, audited override |
| State | `write`, `restore`, `tool_read`, `model_read`, `store_read`, `store_write` | `state_write`, `state_restore`, `state_read` |
| Approval | `resume` | `resume_permission`, then the permission chain again |
| FrameworkOp | `guard_operation` | existing guarded operation path |
| ModelInvocation | `invoke` | `model_invoke` before prompt assembly |
| Output | `emit(destination)` | `output_emit` with content, labels, and destination clearance |
| HostResource | `file`, `socket`, `exec`, `syscalls`, `limits` | kernel enforcement from the grant |

The seven existing hook names are frozen. New hook names are additive and
default to `ALLOW`. Modules cannot distinguish trusted-node dispatch from
separate-process untrusted-node dispatch.

## Policy input and decisions

The default profile is one `.slp` file with `tool`, `principal`, and `policy`
blocks. `policy` is forbid-only. Cedar is the default engine and is hidden
behind `Policy`; an existing OPA deployment may implement the same interface.

Constructive DAC proposes authority. The evaluator creates one ephemeral Cedar
`permit` for each surviving DAC line and combines it with operator forbids.
Forbid wins. A diagnostic or evaluation error denies that line and names an
attributable module. Modules may return verdicts, forbid policies, and labels;
they never emit permits or mutate principals, grants, or audit state.

The stable verdict vocabulary is `ALLOW`, `DENY`, `TRANSFORM`, and `ESCALATE`.
Preparation and attenuation are non-expansive. Exceptions, timeouts, malformed
outputs, missing principals, unverifiable checkpoints, unlowerable classes,
and unplaceable paths deny and are named in the audit.

## Calls, approval, and delegation

The ToolCall sequence is prepare, normalize, re-run constructive DAC, evaluate
permission, dispatch only on allow, and run post handling for the attempted
execution. `ESCALATE` requests operator-owned approval for one call. Resume
runs `resume_permission` and the complete permission chain again; approval is
not attached to an individual policy line and cannot bypass changed input.

Every subgraph, `Send`, parallel branch, subagent, and nested-agent dispatch
runs `cred_transfer` and an explicit child-subset check. Every minted credential
gets the same subset check even when the kernel can also attenuate it.

## State and runtime injection

State writes, restores, and reads are explicit router operations. Restore
verifies the hash chain and binds the checkpoint to the principal. Store keys
are resources with owners and confidentiality/integrity labels; cross-principal
access is a policy decision, not ambient store access.

`ToolRuntime` injection is mediated. A profile lists readable state channels and
store keys. A tool receives its principal ID, not `RunnableConfig`; credentials,
policy state, approvals, and audit handles are never injected.

## Model invocation and output

`model_invoke` runs before prompt assembly. Its full verdict may deny or strip
labeled context. `output_emit` sees the content, confidentiality and integrity
labels, and destination clearance; it may allow, deny, redact, or escalate.

Both operations are in scope. Their shipped defaults are label-only, while the
reference non-exfiltration, integrity, and compartmentalization policies are off
by default. Defaults never redefine scope.

## Registry and undeclared tools

Static registration is checked at compilation. Dynamic registration runs
`tool_alloc_security` and inference at runtime. A tool without a profile
receives the undeclared default. Overrides are operator actions and are audited.

## Host contract

Host capability evidence is probed per boot. Landlock ABI is read through
`LANDLOCK_CREATE_RULESET_VERSION`, not inferred from the kernel version.
cgroup v2 delegation, `cgroup.kill`, unprivileged user namespaces, BPF LSM,
Landlock audit, and the per-call confinement mechanism are attested.

Every rule is lowered as `exact`, `tightened`, or `unsupported`. Looser
lowering denies. Unsupported classes deny unless waived per class with a reason;
affected calls are always stamped `unenforced`. A class introduced by a module
is rechecked at grant time and denies the call if unsupported.

Use `slanggraph check --backend X profiles/`; unsupported, unwaived rules produce
a nonzero exit.

## Audit and trust

The hash-chained audit identifies every hook verdict, child-subset decision,
checkpoint verification, registry override, per-rule lowering, waiver, worker
activation, and denial reason without recording raw secrets.

Operator-authored nodes are trusted by default. Imported nodes are untrusted by
default; promotion is an audited operator action. Trusted nodes run in the
coordinator and honor hooks by assumption, checked by placement analysis.
Untrusted nodes run separately and reach framework objects over the mediated
router channel. Placement analysis checks the trust assumption; it is not the
security boundary.

The host TCB is the kernel, adapter, launcher, and broker. The framework TCB is
the coordinator, LangGraph runtime, policy backend, grant compiler, modules,
and trusted node code.

## Out of scope

Out of scope are trusted-node reads, kernel bugs and side channels, remote
services without scoping, name-based network policy without a proxy, the
internal computation of a tool over granted data, the model-provider channel,
and denial of service. The tool's post result and destination remain in scope.
