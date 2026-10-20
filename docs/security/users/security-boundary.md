# Security boundary

slangGraph uses a layered boundary. LangGraph is the user-space object manager
for framework objects, and the host kernel monitors OS objects. A request is
protected by the full claim only when both layers are active and attested.

> An operation is in scope if and only if a hook on the single dispatch path can refuse it.

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

The complete hook mapping is in
[ADR 0007](../adr/0007-kernel-enforced-confinement.md).

## One dispatch path

Every mediated framework operation goes through `HostRouter`. `ToolNode` and
`guarded_tool` are ordinary router callers and do not create separate security
boundaries. Retries, rewritten arguments, child dispatch, resume, state access,
model invocation, and output each receive their own operation decision.

Approval applies to one call. After resume, `resume_permission` and the complete
permission chain run again.

## Trusted and untrusted nodes

Operator-authored nodes are trusted by default. Imported components are
untrusted by default. Promoting imported code is an audited operator action.

Trusted nodes may run in the coordinator. Their hook use is a trust assumption
checked by placement analysis, not an isolation boundary. Direct reads by such
code are outside scope.

Untrusted nodes and tools run as separate-process units of work. They receive
only mediated framework access over the router channel. A tool receives its
principal ID and profile-declared state channels and store keys, never the full
`RunnableConfig`.

## What is mediated

- principal binding, transfer, and attenuation;
- tool preparation, invocation, and post handling;
- subgraphs, `Send`, parallel branches, subagents, and nested agents;
- static and dynamic tool registration and audited override;
- state writes and restores, tool/model reads, and store reads/writes;
- approval resume and guarded framework operations;
- model prompt assembly and labeled-context stripping;
- output allow, deny, redaction, or escalation by destination; and
- host files, sockets, execution, syscall classes, and limits from the grant.

Model invocation and output are in scope even though their shipped defaults are
label-only. Optional reference policies provide non-exfiltration, integrity,
and compartmentalization checks.

## Host enforcement

The host implements each grant rule exactly or more tightly and records
`exact`, `tightened`, or `unsupported`. A looser result denies. Unsupported
classes deny unless explicitly waived with a reason; every affected audit record
is stamped `unenforced`.

Trusted `inprocess` tools do not receive a per-call kernel sandbox. Their
effective permission is the intersection of the authority surviving slangGraph
policy and the coordinator's existing host authority. slangGraph cannot bypass
a host denial, and host access cannot override a slangGraph denial. The host
usually authorizes the coordinator service identity, not the application
principal. Preserving the slangGraph half of the intersection is therefore a
trusted-tool or language-sandbox obligation.

Capabilities are probed per boot. Landlock support is detected through its ABI
query, not the kernel version. The audit records the actual confinement
mechanism, runtime baseline, attestation, and per-rule lowering.

## Outside the boundary

The claim excludes reads by trusted node code, kernel bugs and side channels,
remote services that cannot scope authority, name-based network policy without
a proxy, what a tool computes over data it was granted, the model-provider
channel, and denial of service. Tool results and their destinations are still
mediated by post and output hooks.

`security=None` is compatibility mode and supplies none of this claim. For
shipped versus planned behavior, see [implementation status](../status.md).
