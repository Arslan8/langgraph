# Grant lowering and host capability negotiation

This document specifies the target lowering process accepted by
[ADR 0007](adr/0007-kernel-enforced-confinement.md). The final `Grant`,
`HostModel`, adapter protocols, and enforcement plans described here are not yet
shipped public APIs; [implementation status](status.md) records what exists on
the branch today.

## Boundary between policy and enforcement

slangGraph keeps authorization portable and lowering platform-specific:

```text
normalized call
      |
      v
constructive DAC candidate
      |
      v
Cedar restrictive filtering
      |
      v
platform-neutral Grant
      |
      +-------- HostModel --------+
      |                           |
      v                           v
selected adapter set ----> capability negotiation
                                  |
                                  v
                         enforcement plan + attestation
                                  |
                                  v
                              dispatch
```

Cedar does not emit Landlock rules, Windows access-control entries, sandbox
bytecode, or broker requests. It decides whether individual candidate lines may
survive. The framework assembles those surviving lines into a canonical
`Grant`; adapters lower that grant without widening it.

## Inputs to lowering

### `Grant`

The final grant is immutable and platform-neutral. It carries:

- the `(principal, tool)` subject and call identity;
- typed filesystem, network, executable, syscall, service, delegation, and
  resource-limit rules;
- whether each rule is required or advisory;
- mandatory-policy and DAC provenance for every surviving rule;
- the selected runtime baseline; and
- a canonical digest used by approvals, adapter plans, credentials, and audit.

Paths and named resources in a grant are semantic selectors, not native object
handles. Linux file descriptors, Windows handles, service tokens, and similar
objects exist only in a compiled enforcement plan.

### `HostModel`

A host model is an immutable, attested inventory produced by trusted probes. It
describes what the current machine can provide independently of which adapters
are selected. Its eventual representation will include:

- platform and architecture;
- normalized semantic capabilities;
- evidence and probe version for each capability;
- observation time and freshness constraints; and
- an attestation digest.

The model, tools, graph state, and policy files cannot assert host capabilities.
A configured host model at compile time is only an expectation. Adapters must
revalidate its evidence before dispatch.

### Adapter set

An adapter declares which semantic capabilities it knows how to lower. Its
availability on one machine is a function of the host model. Conceptually, an
adapter provides operations equivalent to:

```python
declared_capabilities() -> CapabilitySet
available_capabilities(host) -> CapabilitySet
runtime_baseline(host) -> GrantLines
lower(grant, host) -> EnforcementPlan
attest(plan, host) -> Attestation
```

This is explanatory pseudocode, not a frozen Python protocol. Adapter-specific
types remain below this boundary.

## Capability negotiation

Negotiation distinguishes an unsuitable host from a missing adapter:

```text
required        = grant.classes()
host_required   = grant.host_classes()
host_missing    = host_required - host.capabilities
adapter_missing = required - adapters.declared_capabilities
effective       = adapters.available_capabilities(host)
missing         = required - effective
```

The call may proceed only when every required class has an enforcing owner and
`missing` is empty. A failure is attributed precisely:

| Condition | Result |
| --- | --- |
| Host lacks a required primitive | `host_cannot_enforce:<classes>` |
| No selected adapter implements a class | `adapter_not_selected:<classes>` |
| Adapter implements the class elsewhere but not on this host | both host and effective-capability diagnostics |
| Probe or attestation fails | `host_attestation_failed` |
| Lowering cannot preserve a rule | `adapter_lowering_failed:<class>` |
| Multiple adapters claim a rule without an operator-selected owner | `adapter_ownership_conflict:<class>` |

A missing capability never silently chooses advisory mode. An operator may
permit a specific advisory class only through explicit policy. The exception,
complete unenforced set, host digest, and adapter attestations are then included
in every decision and execution record.

## Composing enforcement loci

One call can use multiple adapters:

- A **host adapter** confines local code and processes. The Linux reference
  adapter may use Landlock, seccomp-BPF, cgroup v2, and rlimits. A Windows
  adapter may use Windows-native isolation while consuming the same grant.
- A **service adapter** mediates semantic operations such as SQL statements,
  mail recipients, chat destinations, browser navigation, or MCP requests.
- A **resource adapter** mints resource-side credentials whose permissions and
  lifetime are subsets of the grant.

Every rule has exactly one enforcing owner in the compiled plan. Composition is
an explicit mapping, not first-adapter-wins ordering. Adapters may reinforce one
another, but overlapping claims do not turn into additional authority.

For example, a mail tool can receive local filesystem and syscall confinement
from a host adapter while its recipient rule and credentials remain exclusively
owned by a mail service adapter. The untrusted worker receives the broker
channel, not the mail credential.

## Conservative lowering

For every grant line, an adapter may:

1. enforce the line exactly;
2. enforce a strict subset and record the reduction; or
3. report that it cannot enforce the line.

It may never produce a superset. Property tests compare the authority represented
by each native plan with its input grant. Runtime baseline rules go through the
same Cedar filtering, provenance, hashing, and subset checks as tool-requested
rules; an adapter cannot add hidden authority during compilation.

Resource resolution is also adapter-owned. The Linux reference adapter can use
`openat2` and `O_PATH` descriptors to prevent path substitution. A Windows
adapter can use native handles and reparse-point-safe resolution. Neither native
identity appears in the portable grant.

## Dispatch and revalidation

Lowering is complete only after the following checks succeed:

1. Re-probe or validate the host attestation.
2. Recompute effective capabilities for the selected adapter set.
3. Resolve each rule to exactly one enforcing owner.
4. Compile native enforcement plans and service/resource bindings.
5. Prove or test that every plan is no broader than its grant lines.
6. Bind every plan, credential, and worker to the canonical grant digest.
7. Write the pre-execution audit record.
8. Enter confinement before importing or invoking untrusted tool code.

A changed host, stale probe, capability loss, lowering error, failed attestation,
or audit failure denies dispatch. Approval never bypasses these checks.

## Audit requirements

The completed lowering path records:

- constructive candidates and removed lines;
- Cedar policy identifiers and per-line decisions;
- final grant and provenance digest;
- expected and observed host-model digests;
- required, host-provided, adapter-declared, effective, and missing capabilities;
- adapter identity, version, plan digest, and attestation;
- advisory exceptions and the full unenforced set;
- service requests and effective credential subsets; and
- worker exit, supervisor termination, and enforcement-denial evidence.

This evidence distinguishes “policy allowed the call” from “the selected host and
adapters enforced the resulting grant.”

## Portability example

Suppose a grant requires filesystem read confinement, executable selection, and
a mail-recipient rule.

On Linux, the selected set might be a Linux host adapter plus a mail service
adapter. On Windows, it might be a Windows host adapter plus the same mail
service adapter. Cedar sees the same typed grant in both cases.

If the Windows host model reports filesystem and executable confinement but no
usable process-isolation primitive required by the grant, execution denies with
`host_cannot_enforce` even though the Windows adapter implements that capability
on other Windows configurations. The operator must select a different host,
reduce the requested authority before approval, or explicitly accept an audited
advisory exception. The framework does not substitute Linux semantics or broaden
the grant.

## Required tests

Before the lowering APIs freeze, tests must prove:

- reducing a grant cannot increase native-plan authority;
- reducing host or adapter capabilities cannot turn a denial into an enforced
  allow;
- every required line has exactly one enforcing owner;
- host and adapter mismatches have distinct diagnostics;
- stale or malformed attestations fail closed;
- platform-specific objects never appear in Cedar requests or the `Grant` IR;
- advisory execution is impossible without explicit policy and complete audit;
- delegation produces a child grant, host plan, and credential set no broader
  than the parent; and
- Linux and a second host adapter pass the same backend-neutral contract suite.
