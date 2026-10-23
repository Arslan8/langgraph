# Grant lowering, obligations, and activation evidence

This document specifies the lowering process accepted by
[ADR 0007](adr/0007-kernel-enforced-confinement.md). The platform-neutral grant,
obligation, adapter, attestation, and activation-receipt contracts are shipped.
The Linux reference executor implements the documented filesystem and
resource-limit subset; [implementation status](status.md) records the exact
boundary and remaining adapters.

## Isolated object-resource implementation

`ObjectBrokerDispatcher` now composes the existing `EnforcementCoordinator`
with a Linux host adapter and operator-supplied `ResourceMediatorAdapter`
instances. It compiles the object grant and explicit runtime baseline into
obligations; mediator semantics depend on host bypass prevention, authenticated
broker transport, and parent-owned credential custody. It negotiates the
concrete host, removes unsupported optional authority, rechecks the ledger,
and verifies activation evidence bound to the worker before releasing `GO`.
The worker receives only the retained broker routes.

SLP `lowering` names are contracts for adapters to recognize, not assertions
of host support. The exact-file host adapter currently accepts its default
strategy only; unknown strategies fail closed. Custom semantic adapters must
assess each complete line, including the strategy. See
[isolated tools](object-classes.md#isolated-tools) and the
[pump example](../../workspace/05_custom_class_quickstart.py).

The negotiation API is platform-neutral; the shipped executable object backend
is Linux Landlock ABI 5+ with seccomp. A different OS needs a real confinement
backend and evidence verifier. Local activation evidence is authenticated by
per-invocation supervisor trust anchors, not independent remote attestation.
A mediator's witness identifies an operator-reviewed semantic contract, not a
machine-checked proof of arbitrary Python or physical-device semantics.
This integration does not claim the full target authority record, externally
anchored audit, or all resource/OS adapters described below.

## Security invariant

An execution may be reported as **enforced** only when the framework can produce
one `ExecutionAuthorityRecord` containing:

1. the exact, canonical `Grant` authorized for the principal, tool artifact, and
   normalized intent;
2. every enforcement obligation derived from that grant and the closed-world
   runtime baseline;
3. the component responsible for each obligation and its conservative lowering;
4. authenticated, worker-bound evidence that all required components were active
   before untrusted code was imported; and
5. the authorization transaction, activation receipt, service/resource leases,
   dispatch receipt, outcome, and externally anchored audit head.

Capability-class matching, a successful Cedar decision, a compiled native plan,
or a hash with no verified provenance is not sufficient evidence of enforcement.

## Boundary between policy and enforcement

slangGraph keeps authorization portable and lowering platform-specific:

```text
normalized intent + requirement ledger
                  |
                  v
       constructive DAC candidate
                  |
                  v
  mandatory line and aggregate filtering
                  |
                  v
       platform-neutral exact Grant
                  |
                  v
     enforcement-obligation graph <--- closed-world runtime baseline
                  |
           HostAttestation
                  |
                  v
       rule-specific negotiation
                  |
                  v
      conservative enforcement plan
                  |
                  v
       worker activation receipt
                  |
                  v
       authorization transaction
                  |
                  v
               dispatch
```

Cedar does not emit Landlock rules, Windows access-control entries, sandbox
bytecode, or broker requests. It restricts a typed candidate. The framework
assembles the surviving authority into a canonical `Grant`; selected adapters
lower obligations derived from that grant without widening it.

## Authority and default deny

The final `Grant` is immutable and platform-neutral. It carries:

- the authenticated principal, exact tool artifact, normalized intent, and call
  identity;
- typed filesystem, network, executable, syscall, service, delegation, and
  resource-limit rules;
- stable source-line identifiers and `need` or `want` provenance;
- mandatory-policy and DAC provenance for every surviving rule;
- the selected runtime baseline; and
- a canonical digest used by approvals, plans, credentials, receipts, and audit.

The grant is a closed-world allowlist, not a list of selected restrictions. The
worker starts with an empty authority envelope. Filesystem, network, process,
IPC, service, credential, and runtime access not represented by a grant or
explicit baseline line is denied. An adapter is usable only if it supplies and
attests a `deny_complement` obligation for every authority domain it owns.
Allowing the listed paths while leaving every other path ambient is therefore an
unsupported lowering, not partial success.

Paths and named resources are semantic selectors, not native object handles.
Linux file descriptors, Windows handles, service tokens, and similar objects
exist only in a compiled enforcement plan.

## Requirements and enforcement strength

`need`/`want` and required/advisory answer different questions:

- `need` and `want` are tool-profile construction semantics. If all authorized
  descendants of a `need` line disappear, the call is unusable and denies. If a
  `want` disappears, the permission is removed and the call may continue. A
  missing `want` never means running with broader ambient access.
- required/advisory is an operator-owned enforcement classification. Every
  surviving authority and baseline rule is required by default. Tool authors,
  model input, and policy modules cannot make a rule advisory.

A `RequirementLedger` follows each source line through DAC intersection,
mandatory filtering, set subtraction, conservative lowering, and activation.
Before dispatch, every `need` must have at least one fully enforced descendant.
Every surviving `want` must also be enforced; otherwise it is removed and the
ledger is checked again. A conservative lowering that removes the last descendant
of a `need` denies.

Advisory exceptions are limited to obligations that operator policy explicitly
declares waivable. Identity and artifact binding, closed-world default deny,
principal and grant integrity, requirement-ledger validity, isolation before
import, credential custody, approval binding, and audit precommit are
non-waivable. A run with any waived obligation is `DEGRADED`, not `ENFORCED`, and
the full grant-subset claim is not made for that run. A waiver never means
retaining an authority line while dropping the restriction that bounds it: an
unenforceable optional line is removed. If degradation leaves a broader known
authority upper bound, flow classification uses that upper bound. If the bound
is unknown, the run cannot justify an outward effect through ordinary labels.

## Exact enforcement obligations

Resource classes such as `filesystem` and `network` are discovery and diagnostic
hints only. They cannot authorize execution. Each grant rule expands into typed,
exact obligations. An obligation identifies:

- a stable obligation and source-rule identifier;
- operation and protocol layer, such as `tcp.connect`, `http.request`,
  `mail.send`, or `fs.open`;
- exact selector and resource scope;
- conditions such as destination, port, HTTP host, method, path, recipient,
  statement kind, limit, or expiry;
- lifecycle and revalidation requirements;
- whether it prevents a bypass, protects a credential, enforces an operation, or
  supplies evidence; and
- whether it is required and whether operator policy permits degradation.

For example, TCP destination/port confinement and HTTP host/method/path
confinement are different obligations. An adapter advertising `network` is only
a candidate. It must assess each obligation as `EXACT`, `STRICTER`, or
`UNSUPPORTED`, with a proof or executable conformance witness for the claimed
relation. `STRICTER` records the removed authority and triggers the requirement
ledger. A capability-class match without this rule-specific assessment denies.

## Obligation graph and adapter composition

One semantic grant rule may require several enforcement components. It is
compiled into an obligation DAG whose dependency closure must be satisfied. Each
obligation has one primary enforcer; other components may reinforce it. The old
rule-level “exactly one owner” model does not apply.

For a mail-recipient restriction, the graph normally contains at least:

- a mail service obligation that validates recipients on every send;
- a host obligation that denies alternate network egress and exposes only the
  authenticated broker channel;
- a resource obligation that keeps the mail credential out of the worker; and
- a channel obligation binding broker requests to the principal, artifact,
  grant digest, and worker nonce.

The mail rule is enforceable only if every required dependency is activated.
Evidence is recorded per obligation, then rolled into the plan and activation
digests. An adapter cannot satisfy an obligation by pointing to another adapter
unless that dependency is explicit in the DAG.

Adapters may operate at three loci:

- A **host adapter** creates a closed-world local process authority envelope. A
  Linux implementation may use Landlock, seccomp-BPF, cgroup v2, and rlimits; a
  Windows implementation consumes the same obligations using Windows mechanisms.
- A **service adapter** mediates semantic operations such as SQL statements,
  mail recipients, chat destinations, browser navigation, or MCP requests.
- A **resource adapter** holds or mints resource-side credentials whose
  permissions and lifetime are subsets of the grant.

## Host evidence is not just a digest

A `HostAttestation` is a signed or authenticated evidence statement verified
against a configured trust anchor. Its canonical content includes:

- probe identity, version, binary digest, observations, time, freshness, and
  challenge nonce;
- boot identity, kernel or platform build, relevant feature configuration, and
  adapter/supervisor identity;
- user and group credentials, security token or capability state;
- mount, user, network, PID, and other relevant namespace identities;
- cgroup identity, controller configuration, and delegation state; and
- broker endpoint/key epoch and resource-issuer identity where applicable.

`HostModel.digest` is only the canonical hash of that verified statement. The
hash authenticates nothing by itself. Local evidence must be signed by the
privileged supervisor or rooted in an operator-configured OS, VM, TPM, or
workload trust anchor. Remote evidence must be verified through an authenticated
attestation protocol.

The compile-time host model is an expectation. It is never reusable across a
different boot, namespace set, credentials, cgroup placement, adapter binary,
broker key epoch, or freshness window. Graph state, tool metadata, policy input,
and the model cannot assert host capabilities.

## Negotiation and conservative lowering

Conceptually, an adapter provides operations equivalent to:

```python
discover(host_attestation) -> DiscoveryCapabilities
assess(obligation, host_attestation) -> SupportAssessment
baseline(runtime, artifact, host_attestation) -> GrantLines
lower(obligations, host_attestation) -> EnforcementPlan
activate(plan, worker_context, nonce) -> ActivationEvidence
revalidate(lease, worker_context) -> LeaseStatus
```

This is explanatory pseudocode, not a frozen Python protocol. Adapter-specific
types remain below this boundary.

For every obligation, an adapter may enforce it exactly, enforce a strict subset,
or report it unsupported. It may never produce a superset. A plan is accepted
only if every required obligation and dependency has a primary enforcer, every
enforcer reports `EXACT` or `STRICTER`, the requirement ledger remains valid,
and every authority domain has its `deny_complement` obligation.

Failures distinguish an absent host primitive, no selected implementation, a
rule that cannot be represented exactly, and failed evidence:

| Condition | Result |
| --- | --- |
| Host lacks a required primitive | `host_cannot_enforce:<obligation>` |
| No selected adapter implements the obligation | `adapter_not_selected:<obligation>` |
| Adapter class matches but exact scope or conditions do not | `adapter_rule_unsupported:<obligation>` |
| Mandatory resource difference is not exactly representable | `resource_set_not_representable:<rule>` |
| Probe, trust-chain, freshness, or context binding fails | `host_attestation_failed:<reason>` |
| Lowering widens or cannot preserve a rule | `adapter_lowering_failed:<obligation>` |
| A required dependency is absent | `obligation_dependency_missing:<obligation>` |
| Two primary enforcers claim one obligation | `adapter_ownership_conflict:<obligation>` |

Property and backend-contract tests compare the authority represented by each
native plan with its input obligations. Platform-specific mechanisms are never
used as the portable policy vocabulary.

## Mandatory filtering and resource sets

Mandatory policy receives a closed, typed request IR. Authorization-affecting
modules do not return arbitrary Cedar source. Their future return contract is a
typed `ModuleOutput` containing a verdict, namespaced label assertions, and
forbid-only constraints from a bounded schema. The framework validates module
identity and artifact digest, effect, entity types and references, attribute
ownership, resource scope, rule count, expression depth, and evaluation budget,
then translates that IR to Cedar. A module cannot emit `permit`, arbitrary
entities, platform rules, or unbounded source text.

These modules and the translator affect authorization and are explicitly in the
TCB. Operator policy pins their artifact digests. Exceptions, timeouts, malformed
outputs, validation failures, and Cedar diagnostics deny and name the module.

Cedar evaluates concrete requests; one representative authorization cannot prove
that an entire broad selector is allowed. The framework therefore uses a typed
resource-set algebra:

1. apply mandatory forbids to the exact set denoted by each candidate rule;
2. compute the authorized difference and emit exact, attributable fragments;
3. use a broker to check every concrete operation when the set cannot be safely
   materialized but can be mediated dynamically; or
4. reject the broad rule when neither exact representation nor complete dynamic
   mediation is available.

For example, `read /workspace/**` minus `read /workspace/secrets/**` is never
approved by checking only `/workspace`. It must be represented by a sound set
difference or every open must cross a broker; otherwise the line is rejected.

The policy adapter performs both per-line filtering and an aggregate check over
the complete candidate grant, including operator-approved runtime baseline and
authenticated channels. Aggregate policy can reject combinations such as
sensitive-file authority plus outbound communication even if each line
separately survived. That grant-local aggregate check does not establish
cross-call information flow: history, declared effects, or a flow summary cannot
soundly represent dependencies through model context, graph state, checkpoints,
results, or delegation. The separately configured `SessionFlowPolicy` schedules
operator-classified sources and sinks by tainting the whole authenticated
session. It is not noninterference evidence for hostile implementations until
native or service enforcement constrains actual reads and outward effects. Any Cedar evaluation
diagnostic, skipped-policy error, unknown entity, or aggregate error denies. A
combination deny is never converted into separate allows.

## Trusted preparation and import boundary

Strict mode does not import tool-authored Python in the orchestrator. Discovery
loads a declarative, schema-validated manifest containing the artifact digest,
descriptor, profile, entry point, dependency closure, and normalizer identifiers.
Framework-provided pure normalizers may run before authorization. A custom
tool-authored transformation is untrusted: it runs under a separate minimal
preflight grant with no implicit access to the main grant. Its output is treated
as tainted input and must be proven no broader than the original normalized
request, not merely allowed by the principal envelope, before normalization and
authorization run again.

Operator-installed policy modules, policy translators, trusted probes, selected
adapters, supervisors, audit coordinators, and built-in normalizers are in the
TCB. Tool decorators and descriptor construction execute at Python import time,
so the current decorator-based discovery path is not a strict-mode boundary. The
untrusted tool artifact and native dependencies are imported only after the
activation barrier releases the worker.

## Ambient authority and runtime baseline

Before lowering, the supervisor constructs an `AuthoritySnapshot` covering:

- inherited descriptors and handles, existing sockets, IPC endpoints, and broker
  channels;
- environment variables, secrets, credentials, security tokens, capabilities,
  user/group identity, and working directory;
- root/mount view, executable/interpreter and dependency files, temporary files,
  devices, DNS/proxy configuration, and runtime services;
- namespaces, cgroup placement and controllers, resource limits, and child-process
  inheritance; and
- framework objects that act as capabilities, including stores, stream writers,
  model clients, and callbacks.

A fresh worker begins with a clean descriptor/handle table, minimal environment,
private working directory and temporary storage, no direct credentials, no
preexisting external sockets, and only explicitly granted runtime artifacts and
authenticated channels. Every retained item becomes an operator-approved
baseline grant line and an obligation. Baseline lines pass through mandatory filtering and the same
subset, activation, and audit checks. If the baseline cannot start the runtime,
the call denies; the adapter may report a requirement but cannot grant it to
itself or widen it on retry.

## Worker-specific activation and leases

Compilation does not prove activation. The trusted supervisor holds a worker
behind a startup barrier, applies all host plans and cgroup placement, creates
authenticated service/resource channels, and then issues an `ActivationReceipt`.
The receipt binds:

- grant, obligation-graph, plan, policy, adapter, and host-attestation digests;
- tool artifact and runtime-baseline digests;
- worker PID plus pidfd or equivalent stable process identity;
- boot, namespace, credential/security-token, and cgroup identities;
- broker channel, key epoch, credential-lease identifiers, challenge nonce, and
  activation time; and
- evidence for every obligation and the closed-world complements.

The coordinator verifies the receipt against its nonce and expected worker
context, writes the audit precommit, and only then sends the one-time release
message that permits import. Evidence collected for another worker or execution
context cannot satisfy the check.

Host evidence and live leases are invalidated by a boot, namespace, credentials,
cgroup, adapter/supervisor binary, policy, plan, broker key/health, issuer, or
grant change; by expiry or revocation; or by losing a required service. Brokers
check every request. Long-running workers revalidate leases at declared safe
points, and loss of a required lease terminates or quarantines the worker. An
expired cache never silently becomes advisory.

## Delegation, labels, and budgets

Delegation compares exact grants and typed authority labels, not ordinary set
inclusion of arbitrary blobs. Each delegable label type registers a partial order
and meet operation defining “no more authoritative.” Labels without such a
contract are copied unchanged or are nondelegable; an opaque module slot cannot
be used as proof of attenuation. The child grant, label state, baseline, leases,
and credentials must all be no broader than the parent.

Consumable limits use a shared transactional budget ledger. A parent atomically
escrows a child allocation; siblings cannot each receive the parent's full
budget. Consumption, refund of unused escrow, quota checks, and service-side use
are keyed by grant and idempotency identifiers. Copying a numeric counter into a
child is not attenuation.

## Approval binding

An approval is a one-time, expiring authorization input for one named review
condition. Its signed subject digest binds the authenticated principal and
session, exact tool artifact, call identity, normalized intent, candidate grant
and requirement ledger, policy/version and escalating module, requested
authority, issue and expiry times, nonce, and replay count.

Resume recomputes these values. A change to principal, artifact, normalized
arguments, policy-relevant labels, requested authority, candidate grant, or
degradation set requires a new approval. A host change may trigger re-lowering
and re-attestation without new human approval only if the exact authority and all
approval-bound fields are unchanged and the result is still fully enforced.

Approval can satisfy only its named `review_required` condition. It cannot bypass
DAC failure, a mandatory forbid, a missing `need`, invalid evidence, failed
closed-world confinement, unsupported lowering, audit failure, or an expired
lease. Consumption of the approval is atomic with dispatch reservation.

## Authorization transaction, retries, and outcomes

History-dependent decisions and quotas run in an `AuthorizationTransaction` over
a versioned durable snapshot. The transaction atomically:

1. validates policy/history versions and the requirement ledger;
2. reserves shared budgets and quotas;
3. consumes a one-time approval when present;
4. allocates a stable operation/idempotency key;
5. verifies the activation receipt and current leases; and
6. commits the pre-execution audit record before releasing dispatch.

Service and resource adapters must implement the operation key or declare that
they cannot provide retry safety. A dispatched non-idempotent operation is never
automatically retried merely because its response was lost. Host-side effects
that cannot be made exactly-once have explicit at-most-once/unknown semantics.

Outcomes distinguish `DENIED_BEFORE_DISPATCH`, `SUCCEEDED`, `FAILED`, and
`INDETERMINATE`. If dispatch may have occurred but the result or completion audit
cannot be durably recorded, the result is `INDETERMINATE`, never “denied.” A
durable supervisor outbox and signed completion receipt allow later
reconciliation.

The hash chain is externally anchored. Session-close records seal the terminal
record count and head hash, and periodic signed checkpoints are stored with an
independent witness. Recomputing a locally shortened chain is insufficient:
missing terminal seals, count mismatches, or witness-head mismatches detect
suffix truncation.

## Security enablement is monotonic

`security=None` is a trusted root-application compatibility choice made before
compilation. It is never read from messages, graph state, tool output, or model
input. A secured compile creates an immutable `SecurityContext` and fingerprint.
Every nested graph, delegated execution, resume, retry, dynamically created tool
node, and guarded call must inherit that context or fail closed. Descendants may
tighten it but cannot replace it with `None`, choose weaker adapters, or change
the policy/host fingerprint.

Checkpoint resumes verify the stored security fingerprint and approval/transaction
state. Dynamic construction requires the secured factory bound to the context;
unregistered execution paths fail the compile gate. Delegation without an
inherited security context is an error, not a request to synthesize a default or
run unsecured.

## Audit record

The completed path records:

- constructive candidates, source requirements, removed lines, and ledger state;
- policy/module artifact identifiers, per-line and aggregate decisions, and all
  diagnostics;
- final grant, obligation graph, provenance, and digests;
- verified host evidence, trust anchor, freshness, and execution-context binding;
- each adapter assessment, conservative reduction, dependency, plan, and
  obligation evidence;
- activation receipt, retained ambient authority, baseline, channels, and leases;
- approval subject and consumption, transaction and operation identifiers, quota
  reservations, and dispatch receipt;
- degradation state, every waived guarantee, and the best known authority upper
  bound; and
- completion receipt, outcome, worker exit, enforcement denials, chain head,
  terminal seal, and external witness.

This evidence distinguishes “policy allowed the intent,” “the selected components
were capable of compiling it,” and “those restrictions were active for this
worker.”

## Portability example

Suppose a grant requires filesystem read confinement, executable selection, and
a mail-recipient restriction. The mail rule expands into recipient mediation,
alternate-egress denial, credential custody, and authenticated-channel
obligations.

On Linux, a Linux host adapter and mail service/resource adapters may satisfy the
graph. On Windows, a Windows host adapter may satisfy the same host obligations
while the same service/resource adapters enforce mail semantics. Cedar sees the
same typed authority and obligations; neither policy nor the grant is tied to
Landlock.

If a Windows host can isolate files and executables but cannot prevent alternate
egress, the mail rule is unsupported even though recipient validation exists.
The operator must select another host or remove the operation before approval.
It may not infer that generic `network` support is sufficient.

## Required tests

Before these APIs freeze, tests must prove:

- reducing a grant, obligation, label, lease, or host capability cannot increase
  effective authority;
- every enforced execution has an exact grant and complete obligation/evidence
  mapping;
- TCP, HTTP, mail, SQL, filesystem, and process conditions are negotiated per
  rule rather than by resource class;
- default-deny complements cover unlisted authority and all retained ambient
  capabilities appear in the baseline;
- `need`/`want` is rechecked after policy filtering, lowering, and activation;
- multi-component rules fail if any dependency is absent;
- host evidence cannot be replayed across workers, boots, namespaces,
  credentials, cgroups, policies, or broker epochs;
- untrusted code cannot import before a verified activation receipt releases the
  startup barrier;
- Cedar diagnostics fail closed, broad resource differences are sound, and
  aggregate combination forbids are enforced;
- authorization, quota reservation, approval consumption, and audit precommit
  are atomic under parallel calls;
- retries are idempotent or produce `INDETERMINATE`, and audit suffix truncation
  is detected against an independent witness;
- a secured root cannot be downgraded by nested graphs, delegation, retry, or
  resume; and
- Linux and a second host adapter pass the same platform-neutral contract suite.
