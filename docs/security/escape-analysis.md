# Escape and placement analysis

Escape analysis checks the trust assumptions of the layered reference monitor.
It is not itself a security boundary. The framework boundary is `HostRouter`;
the host boundary is the kernel or selected external enforcer.

> An operation is in scope if and only if a hook on the single dispatch path can refuse it.

The analyzer must reject every untrusted-input-to-effect path that cannot be
placed on an operation in the ten-class model. A reviewed exception has a
narrow fingerprint, owner, and non-empty reason and is included in the graph's
security fingerprint and compile audit.

The scope inventory is:

| Class | Operations |
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

## Sources and effects

Untrusted sources include messages, model proposals and output, graph state,
tool results, store values from other threads, checkpoint content, imported
components, runtime registrations, approval input, and values derived from any
of them.

Security-relevant effects include tool dispatch, state and store access,
checkpoint restore, model prompt assembly, output emission, dynamic registry
changes, child dispatch, filesystem and network access, process execution,
syscalls, and resource consumption.

Declarations and labels are metadata, not sanitizers. An unresolved callback or
dependency is a finding; inability to inspect is never converted into safety.

## Required cover

| Path | Mediated operation |
| --- | --- |
| Model proposes a call | ToolCall `prepare` and `invoke` |
| Proposal arrives via subgraph, `Send`, or subagent | Dispatch and child-subset check |
| Injected content changes an argument | ToolCall after final normalization |
| Injected content lands in state and is read later | State `write` and `state_read` |
| Tool result carries a secret into context | ToolCall `post`, State `write`, ModelInvocation `invoke` |
| Another thread's data arrives via store | State `store_read` on an owned, labeled key |
| Checkpoint is tampered with or replayed | State `restore`, hash-chain and principal verification |
| Runtime tool has no profile | ToolRegistry `register` and undeclared inference |
| Human approves | Approval `resume`, then full permission chain |
| Tool touches OS | HostResource grant enforcement |
| Output goes to lower clearance | Output `emit(destination)` |
| Child output returns to parent | Output `emit` and parent State `write` with labels |

## Trust modes

Operator-authored nodes are trusted by default. Imported nodes are untrusted by
default. Promotion is audited like a DAC override.

Trusted code runs in the coordinator and is assumed to honor hooks. Placement
analysis checks that assumption by finding direct effects, retained aliases,
unresolved calls, dynamic selection, and framework-object access that does not
reach `HostRouter`. Reads directly performed by trusted node code are outside
scope and must be reviewed as TCB behavior.

Untrusted code cannot run in the coordinator. It is dispatched as a separate
process through `HostRouter`; framework-object access returns over the same
mediated channel used by tools. Its isolation, not placement analysis, is the
security boundary.

## Findings and compile behavior

The compile gate reports at least:

- direct invocation of a tool or node alias outside `HostRouter`;
- subgraph, `Send`, branch, subagent, or nested-agent dispatch without transfer
  and subset checks;
- direct state, store, checkpoint, model, output, or registry operations;
- untrusted code selected for in-process execution;
- resource effects absent from the profile or grant;
- background work or descendants that outlive their confinement lease;
- reflection, native code, dynamic imports, or dependencies that cannot be
  resolved; and
- any path whose sink cannot be assigned to a refusing hook.

All 56 existing findings must be removed or individually waived with reasons
before the target complete-mediation claim is enabled.

## CI use

The existing analyzer remains a discovery tool while the compile gate is built:

```bash
langgraph-security-taint src --exclude src/generated
langgraph-security-taint src --json > taint-report.json
```

Do not use a blanket baseline. Compare stable fingerprints and fail on every
new or unresolved path. Target compilation fails on any unplaceable path.

The placement method follows Zhang, Edwards, and Jaeger's static verification
of authorization-hook placement and Jaeger, Edwards, and Zhang's consistency
analysis. It supports the trust argument; it does not replace enforcement.
