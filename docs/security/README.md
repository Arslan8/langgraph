# slangGraph security

slangGraph is a layered reference monitor. LangGraph is the user-space object
manager for ten framework object classes; the host kernel is the monitor for OS
objects. The two layers compose into the system reference monitor. This is the
same architectural pattern used by SELinux-aware user-space object managers
such as X, D-Bus, and sepgsql.

The design is specified by [ADR 0007](adr/0007-kernel-enforced-confinement.md).
The [implementation status](status.md) distinguishes that target from shipped
coverage. Start with the [10-line HOWTO](HOWTO.md), then use the
[behavior reference](reference.md), [public API reference](api.md), and
[security-boundary guide](users/security-boundary.md). The
[escape analysis](escape-analysis.md) documents placement checks and trust
assumptions.

## Scope

> An operation is in scope if and only if a hook on the single dispatch path can refuse it.

Shipped defaults do not define scope. In particular, ModelInvocation and Output
remain in scope even when their default policies attach labels without denying.

| Object class | Operations |
| --- | --- |
| Principal | `bind`, `transfer`, `attenuate` |
| ToolCall | `prepare`, `invoke`, `post` |
| Dispatch | `subgraph`, `Send`, `parallel_branch`, `subagent`, `nested_agent` |
| ToolRegistry | `register`, `override` |
| State | `write`, `restore`, `tool_read`, `model_read`, `store_read`, `store_write` |
| Approval | `resume` |
| FrameworkOp | `guard_operation` |
| ModelInvocation | `invoke` |
| Output | `emit(destination)` |
| HostResource | `file`, `socket`, `exec`, `syscalls`, `limits` |

Every framework operation crosses the hook stack through `HostRouter` as the
single dispatch path. `ToolNode` and `guarded_tool` call the router; they are not
independent boundaries. Untrusted nodes and tools run as separate-process units
of work and use the same mediated channel for framework-object access. Trusted
operator nodes may run in the coordinator, with placement analysis checking the
trust assumption.

## Policy and enforcement

The open-class input is one `.slp` manifest with `class` and `tool` blocks.
The manifest enumerates finite candidate authority; Cedar supplies tool-owner
and principal `permit` policies for DAC and operator `forbid` policies for MAC.
See the exhaustive [manifest language reference](manifests.md) for everything
accepted by the parser and [open object classes](object-classes.md) for the
architecture and ToolNode wiring.
Modules remain independently restrictive and use `ESCALATE` for approval.

An allowed operation produces a canonical grant. Host enforcement must
implement each rule exactly or more tightly. A looser lowering denies;
unsupported classes deny unless explicitly waived, and waived calls are stamped
`unenforced`. Runtime baseline authority is visible in every grant.

For a trusted tool declared with `runs inprocess`, effective permission is the
intersection of the surviving slangGraph authorization and the coordinator's
existing host permission:

`effective = slangGraph allow ∩ host allow`

A slangGraph allow cannot override a Unix mode, ACL, credential, database role,
or other host denial. A host allow cannot override a slangGraph denial. The host
normally sees the coordinator's service identity rather than the application
`Principal`; the trusted tool is part of the TCB and must exercise ambient host
authority only through operations allowed by slangGraph. A language sandbox may
enforce that obligation in process. This mode does not claim per-call kernel
confinement.

`model_invoke` and `output_emit` ship label-only. Reference
non-exfiltration, integrity, and compartmentalization policies ship off by
default. Approval is per call and resume reruns the complete permission chain.

## Boundary

Direct reads by trusted node code, kernel bugs and side channels, unscopable
remote services, name-based network policy without a proxy, denial of service,
and the model-provider channel are outside the claim. What a granted tool
computes is outside the claim; where its result goes remains in scope through
`tool_call_post` and `output_emit`.

`security=None` is compatibility mode and does not provide the layered
reference-monitor claim.
