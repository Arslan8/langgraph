# 0007: Enforce tool grants through pluggable adapters

Status: Accepted

The operational lowering sequence and failure diagnostics are specified in
[Grant lowering and host capability negotiation](../lowering.md).

## Context

The existing security layer mediates configured `ToolNode` and `guarded_tool`
calls. It does not confine an ordinary graph node, a tool implementation, a
native extension, or a child process. Once admitted, tool code has the ambient
authority of the framework process and may exceed its declared effects. A
benign path-handling bug is therefore enough to turn attacker-controlled tool
arguments into privilege escalation.

Python cannot repair this boundary from inside the same process. A Python
timeout cannot reliably stop running native or synchronous code, a descriptor
is only a claim about behavior, and wrappers do not mediate direct system calls.
The framework must authorize a concrete least-privilege grant and pass it to
adapters that enforce it at the operating system, sandbox, service, or resource
owner. No platform mechanism is part of the policy or grant abstraction.

This decision refines ADRs 0001, 0003, 0004, and 0006. Their hook framework,
ordering, private blobs, principal binding, approvals, auditing, delegation,
and fail-closed behavior remain. Where an earlier ADR treats the Python hook as
the enforcement boundary, this decision supersedes it.

## Trust model

Trusted components are the framework, operator node code, policy evaluator,
selected enforcement adapters, their underlying isolation mechanisms, resource
owners, and the hook-placement gate. Untrusted components are the model, every
tool implementation, all input and retrieved data, native tool dependencies,
and every subagent.

Operator node code is trusted to implement application computation, but its
security-sensitive operations are still subject to the compile gate. An
exception requires a stable allow-list entry with an operator-written reason;
the exception is an audit record rather than an implicit assumption.

The Python layer authenticates, decides, audits, and dispatches. It is not the
resource enforcer. A denial still prevents dispatch, but an allowed tool's
filesystem, network, process, and resource consequences are bounded outside its
Python interpreter.

## Decision

Use one platform-neutral policy pipeline and independently selected enforcement
adapters at three loci:

1. Local code runs in a fresh worker confined by a host adapter before any
   untrusted tool module is imported.
2. Operations whose semantics or credentials cannot be represented by that host
   adapter go through a trusted service adapter.
3. Remote operations use resource adapters that mint short-lived credentials
   whose remote permissions are no broader than the authorized grant.

The default mandatory-policy adapter uses Cedar. Cedar syntax, platform APIs,
Landlock rule types, Windows handles, and broker protocols do not appear in the
`Grant` IR. Changing the policy engine or enforcement platform does not change
profiles, module hooks, or grant semantics.

The pipeline is:

```text
profile + principal envelope + shares
                  |
                  v
       constructive DAC candidates
                  |
                  v
  mandatory line + aggregate filtering
                  |
                  v
       assemble surviving call grant
                  |
                  v
   requirement-ledger revalidation
                  |
                  v
    canonical, platform-neutral Grant
                  |
                  v
       enforcement-obligation DAG
             /          |          \
            v           v           v
       host adapter  service adapter  resource adapter
             \          |          /
                  v
       worker activation receipt
```

Default deny applies at every stage. Resource classes are discovery hints, not
security guarantees. Adapters negotiate every exact obligation, including its
resource scope and conditions, and the obligation DAG includes closed-world
denial of unlisted authority. An adapter set that cannot enforce a required
obligation reports it instead of silently lowering the rule to something broader.

## Constructive DAC profiles

The `.slp` profile grammar contains `tool` and `principal` blocks. This is the
only new policy syntax. Tool authors describe the resources and limits a call
needs; users describe their resource envelope, credentials, and shares. The
effective DAC candidate is:

```text
profile(tool, normalized arguments) ∩ envelope(principal) ∩ shares
```

Variables bind only to typed, normalized arguments. `need` lines deny the call
when their intersection is empty. Empty `want` lines are removed and audited.
Operator `dac_overrides` replace complete profile lines and are audited.

Undeclared tools have no callers, filesystem, network, executable, service, or
credential grants and receive only the minimal runtime syscall set. They cannot
run until an explicit declaration or operator override supplies authority.

DAC is constructive: it can only propose concrete authority owned by the tool
author or user. Cross-tool rules, information-flow labels, organization-wide
ceilings, escalation, and separation of duty belong to mandatory policy.

The profile grammar freezes after the profile parser and monotonic DAC evaluator
land. Property tests define monotonicity over set inclusion: reducing the tool
profile, principal envelope, or applicable shares cannot enlarge the resulting
candidate.

## Mandatory policy adapter

Cedar is the default mandatory-policy adapter. OPA may be supplied behind the
same `Policy` interface by deployments that already operate it. Policy adapters
return restrictive decisions over typed candidate lines; they do not emit
platform-specific enforcement objects.

Each surviving DAC line is authorized independently. The evaluator creates one
ephemeral Cedar `permit` matching exactly that candidate line, combines it with
the operator-owned `forbid` set, and submits the typed domain, action, resource,
and call context. A line survives only when Cedar returns `Allow` and reports no
diagnostic or evaluation error. Any error denies that line. A removed `need`
line denies the call.

The evaluator also performs an aggregate authorization over the complete
candidate so mandatory policy can reject combinations that would be unsafe even
when each line survives separately. Broad resource sets are subtracted using a
typed, sound resource algebra, checked at each concrete broker operation, or
rejected; authorizing one representative resource never authorizes a set.

`forbid` always wins. Student modules may set typed, namespaced labels and emit a
bounded forbid-only constraint IR. They cannot submit arbitrary Cedar text,
emit `permit`, alter the ephemeral base permit, invent entities, or contribute
escalation policy. The framework validates ownership, types, references, scope,
and complexity before translating the IR to Cedar. Authorization-affecting
modules and the translator are in the TCB and are artifact-pinned. A module
requests human review by returning the existing `ESCALATE` verdict. The
escalation policy set is operator-owned and is consulted only after no mandatory
policy forbids the candidate.

A type or evaluation error in a student policy is attributed to the module and
denies the affected line. A module used by every line can therefore deny the
whole call when it is buggy. This availability cost is the intended fail-closed
behavior.

Cedar's symbolic compiler is used offline to validate properties of operator
policy sets. It is not run as a per-request containment proof for module output.

Reference operator policy covers ceilings, per-tool confinement, typed-domain
compartmentalization, non-exfiltration, integrity, delegation depth, human
oversight, quotas, supply-chain manifests, adapter attestation, separation of
duty, and audit requirements.

## Platform-neutral Grant IR

An allowed call becomes an immutable `Grant`. It identifies the subject domain
as `(principal, tool)` and contains typed resource selectors, filesystem
operations, network operations, executable authority, syscall classes, resource
limits, service rules, and provenance for every surviving line. The IR expresses
security semantics, not a platform lowering: it contains no Landlock access bits,
Linux file descriptors, Windows handles, sandbox bytecode, or broker wire types.

The `Grant` is a closed-world allowlist: operations outside it are denied, rather
than left as ambient worker authority. It also contains an explicit runtime
baseline supplied by the selected adapter set before mandatory policy runs. On
Python this normally includes
read-only access to the interpreter's runtime libraries, standard library,
declared tool artifact and dependencies, `/dev/urandom`, and timezone data;
execute authority is limited to the interpreter. Native extension `.so` files
need read access for `mmap`, not Landlock `EXECUTE`, which governs `execve`-style
execution. A private per-worker temporary directory receives only the minimum
read, write, create, truncate, and delete rights required by the profile.

Baseline lines have adapter provenance, pass through the same operator forbids,
appear in the final `Grant`, and are included in the attestation and audit. An
adapter may not add hidden runtime authority during lowering. If its declared
baseline is insufficient to start the runtime, execution fails rather than
silently expanding the sandbox.

The IR does not treat a `realpath()` string as sufficient proof of filesystem
identity. It carries a canonical semantic selector and the provenance needed for
an adapter to resolve it without widening authority. The Linux reference adapter
uses `openat2` with `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS` and `O_PATH`
descriptors; a Windows adapter can use native handles and reparse-point-safe
resolution; another sandbox may use its own object model. Native resolved objects
belong to the adapter's compiled sandbox, not the portable `Grant`.

The `Grant` type and Cedar request construction freeze together after the Cedar
integration lands.

## Host model

An immutable `HostModel` describes the semantic enforcement capabilities that a
particular machine currently provides. It is produced by trusted runtime probes,
not supplied by graph state, tool metadata, policy data, or the model. Platform,
architecture, capability evidence, probe versions, and a canonical digest are
recorded for audit, while the capability names themselves remain platform-neutral.
The digest authenticates nothing by itself: a `HostAttestation` must be verified
against a configured trust anchor and bound to boot, namespaces, credentials,
cgroup placement, adapter identity, freshness, and a challenge nonce.

The host model is distinct from the adapter contract. A host can provide a
primitive for which no selected adapter exists, and an adapter can support a
capability that is unavailable on the current host. Class-level discovery first
computes:

```text
required       = grant.classes()
host_missing   = grant.host_classes() - host.capabilities()
adapter_missing = required - adapters.declared_capabilities()
effective      = adapters.capabilities(host)
```

This calculation only finds candidate adapters and produces diagnostics. It does
not authorize execution. Every exact operation, selector, condition, dependency,
and closed-world complement is then assessed as an obligation. Any unsupported
host-bound obligation denies execution. Diagnostics attribute whether the host
primitive, selected adapter, or exact rule representation is missing. Service
and resource-side obligations are checked against their adapters rather than the
host set.

The host model used at compile time is an expectation, not a permanent fact. The
selected adapters re-probe or validate attestation before dispatch. A stale model,
changed host feature, failed probe, or unverifiable attestation denies execution;
none silently selects advisory mode.

## Enforcement-adapter obligation contract

An adapter's supported rule classes are only discovery hints. The framework
expands the `Grant` into exact enforcement obligations and asks adapters to assess
each operation, selector, condition, dependency, and closed-world complement as
`EXACT`, `STRICTER`, or `UNSUPPORTED`. Host, service, and resource adapters may be
composed through an obligation DAG; each obligation has one primary enforcer and
one grant rule may depend on several enforcers. A call may run as enforced only
when every required obligation and dependency has worker-bound activation
evidence.

Lowering is conservative. An adapter may implement an obligation exactly,
implement a strict subset, or report it unsupported. It may never implement a
superset. Property tests compare each adapter's effective authority with its
input obligations and recheck `need`/`want` after every reduction.

An operator may explicitly waive only an obligation declared waivable. Such an
execution is `DEGRADED`, never `ENFORCED`, and carries the complete missing
guarantee set and known authority upper bound. Identity/artifact binding,
closed-world default deny, isolation before import, grant integrity, credential
custody, `need` satisfaction, approval binding, and audit precommit are
non-waivable.

The `advisory` adapter enforces nothing and makes that fact conspicuous in trace
output. It exists for development and laptop compatibility, cannot satisfy a
non-waivable obligation, and never produces an enforced result. The adapter and
audit contracts freeze after the obligation, activation-receipt, degradation,
and attestation paths land.

## Linux reference adapter

The first enforcing host adapter targets Landlock, seccomp-BPF, cgroup v2,
rlimits, and a trusted supervisor. These mechanisms are an implementation of the
generic adapter contract, not slangGraph's policy or Grant format:

| Rule | Enforcement |
| --- | --- |
| filesystem read, write, create, delete, execute, truncate | Landlock filesystem rights compiled from `O_PATH` descriptors |
| TCP `connect(port)` and `bind(port)` | Landlock network rights |
| UDP and raw sockets | denied by seccomp regardless of available Landlock ABI |
| syscall allow-set | seccomp-BPF resolved for the worker architecture |
| executable target | Landlock `EXECUTE`; seccomp only admits or rejects `execve` and `execveat` as syscall classes |
| fork, clone, signal, ptrace | seccomp, Landlock scoping where available, and Yama; namespace isolation only when attested |
| CPU, memory, PIDs | cgroup v2 when delegated; otherwise the supported rlimit subset |
| open-file count | `RLIMIT_NOFILE` |
| wall clock | supervisor timer followed by pidfd or cgroup termination |

The Linux adapter queries `LANDLOCK_CREATE_RULESET_VERSION` and derives capabilities
from the returned ABI. It never infers Landlock features from a kernel release
number. TCP port rules require ABI 4 or later. Domain and destination-address
policy is not represented as Landlock network authority; it requires the broker
or an egress proxy.

The framework process never forks. Phase one starts a dedicated single-threaded
trusted spawner before the framework creates event loops, telemetry exporters,
or any other threads. The spawner is the only component that forks workers. It
contains no untrusted tool code and forks a fresh worker for every call.

The Linux adapter's spawner resolves paths, opens the `O_PATH` descriptors, creates the Landlock
ruleset, adds every filesystem and network rule, and then closes the `O_PATH`
descriptors. The worker inherits one ruleset descriptor, the result pipe, and
the broker socket only. Where cgroup delegation is available, the spawner holds
the worker behind a synchronization barrier until the worker PID is placed in
its prepared cgroup. The worker installs `no_new_privs`, calls `restrict_self`,
closes the ruleset descriptor, applies seccomp and rlimits, and only then imports
the untrusted tool. Because files opened before Landlock confinement are not
retroactively restricted, the clean descriptor table is mandatory.

Phase one does not require Linux namespaces. PID isolation is a separately
attested capability because unprivileged PID namespaces generally depend on a
user namespace and host policy may prohibit their creation. Likewise, cgroup v2
limits are capabilities only when the service manager delegated a subtree to
the spawner. The Linux adapter detects delegation and `cgroup.kill` independently. If
cgroup enforcement is unavailable, it reports the missing limit capabilities
and may conservatively lower supported limits to `RLIMIT_CPU`, `RLIMIT_AS`,
`RLIMIT_NPROC`, and `RLIMIT_NOFILE`. The capability contract decides whether the
resulting strict subset may run.

Seccomp denial actions are part of the compiled policy and attestation.
Capability probes and ordinary denied operations, including `socket()` and
`connect()`, return `EPERM` with `SECCOMP_RET_ERRNO` so the tool can terminate
normally and expose the failure to the audit path. Escape and kernel-attack
syscalls including `ptrace`, `process_vm_readv`, `bpf`, and `unshare` use
`SECCOMP_RET_KILL_PROCESS`. The supervisor records signal and exit status even
when no per-syscall kernel audit record exists.

The worker inherits only the result descriptor and its authenticated broker
descriptor. The socketpair is created with `SOCK_CLOEXEC`, or immediately
marked `FD_CLOEXEC`, so an executed child cannot inherit broker authority.
Explicitly delegable broker access requires a profile grant and a trusted
launcher operation that deliberately transfers an authenticated child channel.
After confinement, seccomp denies `socket()` and `connect()` for broker-only
tools. The worker communicates over the inherited socketpair; it does not create
or connect a socket.

Landlock and seccomp restrictions stack and are inherited by permitted child
processes. They can only tighten local kernel authority. This is defense in
depth, not a replacement for evaluator and broker subset checks.

Landlock denial audit records are a conditional capability rather than a
baseline guarantee. Landlock kernel audit support begins with Linux 6.15 and may
also depend on host audit configuration. The attestation states whether it is
active. On older or non-auditing hosts, evidence consists of the worker-visible
`errno`, attempted operation metadata available to the supervisor, and worker
exit status; the audit must not claim a kernel-generated denial event.

## Service and resource adapters

The reference service adapter uses a broker. At fork time, that broker binds its
socketpair endpoint to a spawn record
containing the principal, tool identity, `Grant` hash, and nonce. Worker
requests name only the desired broker operation and arguments. The broker
ignores any worker-supplied identity, grant, or claimed scope and re-evaluates
the operation against the spawn record and bound principal.

Credentials never enter the worker environment, filesystem, or descriptor
table. The broker holds credentials and mints a token no broader than the
service rule. Every mint performs an explicit child-subset check. Initial token
issuers are AWS STS role sessions with session policies and GitHub App
installation tokens restricted by repository and permission. The audit records
issuer, effective scope, expiry, grant hash, and request identity, but never the
credential value.

Named services such as mail recipients, chat channels, SQL statements, HTTP
domains, databases, browsers, and remote MCP servers are broker or proxy
operations. Remote tools that declare local rule classes fail the capability
contract unless operator policy explicitly permits advisory execution.

## Delegation and worker lifecycle

The evaluator and broker perform an explicit subset check for every delegated
grant and minted credential. Typed labels use a registered attenuation partial
order and meet; opaque labels are copied unchanged or are nondelegable. Shared
budgets use an atomic escrow ledger so siblings cannot each consume the parent's
entire limit. A child grant, labels, budget, baseline, leases, and credentials
must all be no more authoritative than the parent. Inherited kernel restrictions
reinforce this property only for local kernel resources.

The dedicated single-threaded spawner is the only worker creation path and
always produces one fresh worker per call. It is part of phase one. If later
benchmarks require multiple preinitialized spawners, each remains free of
untrusted tool code and is keyed by enforcement-envelope hash, subject, tool
artifact hash, and taint class. Every call still receives a fresh child that
tightens to the call grant before importing the tool. Arbitrary tool state never
crosses calls, subjects, or grant keys.

## Verified hook placement

Hook placement is verified rather than assumed. The source analyzer is a
compile gate for graphs built with `security=...`. Compilation fails when
model-controlled data can reach an unmediated sink, an unresolved call, an
unprotected execution path, or tool behavior absent from its declaration.

An operator may allow-list a finding only with a non-empty reason. Each entry is
matched narrowly, included in the graph's security fingerprint, and written as
an audit record at compile time. The framework's own findings must either be
removed or carry a justification suitable for publication.

This follows the authorization-hook-placement tradition established by Zhang,
Edwards, and Jaeger's static verification of complete mediation and Jaeger,
Edwards, and Zhang's consistency analysis of the relationship between hooks and
security-sensitive operations.

## Tool execution routes

The tool manifest selects the locus through its `runs` field:

| Tool form | Route |
| --- | --- |
| Python function or native extension | fresh worker under the selected host adapter |
| CLI or subprocess | confined worker with adapter-provided executable authority |
| local MCP server | server envelope plus MCP proxy; strict mode starts a server per call |
| code execution | WASI or microVM host adapter |
| browser or computer use | confined launcher plus URL proxy |
| database | broker-selected database role and row-level security |
| HTTP API, SaaS, remote MCP | broker-held credential and resource-side token |
| non-Python runtime | language-neutral `slanggraph-exec` launcher |

Local MCP per-call narrowing is service-adapter enforcement inside a host-confined
server envelope. It does not claim that an already-running server's kernel
domain can be widened or reset.

## Audit and failure behavior

The audit chain records candidate lines, removed lines and policy identifiers,
normalization and descriptor-resolution failures, approval state, final grant
and provenance, exact obligations, adapter assessments, verified host evidence,
activation receipt, retained ambient authority, unenforced guarantees,
delegation subset results, broker requests, effective token scope, worker exit,
supervisor termination, and kernel denial evidence when available.

Failure to parse, bind, normalize, resolve, authorize, lower, attest, isolate,
or write the pre-dispatch audit record denies execution. After dispatch, an
uncertain side effect or completion-audit failure is `INDETERMINATE`, not a
denial. The chain is sealed with a terminal count/head and independently
witnessed so valid-prefix truncation is detectable. No enforcement adapter
silently degrades. Policy hook timeouts still deny the decision, but timeout of
untrusted tool execution is enforced by the supervisor rather than a Python
thread timeout.

## Delivery and freeze

Phase one is five weeks and contains:

1. profile grammar and monotonic constructive DAC evaluator;
2. attributed platform-neutral `Grant` IR and resource selectors;
3. Cedar integration and reference mandatory policies;
4. obligation and adapter interfaces, host attestation, activation receipts,
   transactional audit changes, and explicit degradation; and
5. the dedicated spawner and Linux reference adapter.

Service credential custody, MCP proxying, the native launcher, a second host adapter,
and benchmark evaluation are phase two and are scoped after phase one.

The seven existing hook names and their invocation structure remain stable.
The course contract promises that modules return a verdict and may optionally
emit typed forbid constraints and labels. The detailed return type is not frozen
until Cedar integration. The profile grammar freezes after step 1; `Grant` and Cedar request
construction freeze after step 3; adapter and audit contracts freeze after step
4.

## Consequences

Tool startup becomes more expensive and platform-specific. Correctness takes
priority over the provisional 1-to-3 millisecond estimate: the phase-one target
is less than 5 milliseconds of Linux-reference-adapter overhead per call and less than
2 percent of an AgentDojo run, measured before pooling is considered. Advisory
mode retains the previous sub-millisecond decision target but is explicitly
degraded and provides no resource-confinement claim.

Profiles, normalizers, path resolution, adapter feature detection, and service-adapter
authentication become security-critical code. Operators must provision Linux
hosts with the required LSM, cgroup, namespace, and seccomp support. Portable
deployments must either select another enforcing adapter or explicitly accept
advisory classes.

The architecture gains a defensible distinction between authorization and
enforcement: interface mediation decides what should happen, while the selected
host, service, and resource adapters bound what can happen when tool code is
buggy or hostile.

## Non-goals

This decision does not claim confinement of model final text, domain-level
network policy without a service adapter or proxy, protection against kernel or adapter
bugs, or enforcement by a remote service whose API provides no suitable scoping
mechanism.

## References

- Xiaolan Zhang, Antony Edwards, and Trent Jaeger. [Using CQUAL for Static
  Analysis of Authorization Hook Placement](https://www.usenix.org/legacy/event/sec02/full_papers/zhang/zhang_html/).
  11th USENIX Security Symposium, pages 33-48, 2002.
- Trent Jaeger, Antony Edwards, and Xiaolan Zhang. [Consistency Analysis of
  Authorization Hook Placement in the Linux Security Modules
  Framework](https://research.ibm.com/publications/consistency-analysis-of-authorization-hook-placement-in-the-linux-security-modules-framework).
  ACM Transactions on Information and System Security 7(2), pages 175-205,
  2004.
- Linux kernel documentation. [Landlock: unprivileged access
  control](https://docs.kernel.org/userspace-api/landlock.html).
- Linux kernel documentation. [Seccomp BPF](https://docs.kernel.org/userspace-api/seccomp_filter.html).
- Cedar Policy Language Reference Guide. [Authorization](https://docs.cedarpolicy.com/auth/authorization.html).
