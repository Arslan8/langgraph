# 0007: Layered reference monitor and object-manager boundary

Status: Accepted

This ADR is the review gate for the design. Acceptance fixes the architectural
direction; each implementation PR is still reviewed on its own. Current and
target coverage are tracked separately in
[implementation status](../status.md).

## Context

The earlier documentation described the security hooks as "not process-wide
MAC." That statement is true only of the framework layer in isolation and is an
incomplete description of the intended system. It also allowed shipped policy
defaults to narrow the architectural scope, excluded operations that already
had refusal hooks, and made `ToolNode` and `guarded_tool` appear to be competing
mediation boundaries.

The corrected model is layered. LangGraph is a user-space object manager for
the framework objects it owns. The host kernel is the monitor for OS objects.
Together they form the reference monitor for the system. This follows the
SELinux precedent of user-space object managers for objects the kernel does not
own directly, including X, D-Bus, and sepgsql, while the kernel continues to
mediate kernel objects. The placement analysis follows the authorization-hook
lineage of Zhang, Edwards, and Jaeger (USENIX Security 2002) and Jaeger,
Edwards, and Zhang (TISSEC 2004).

The design retains author-owned discretionary grants, restrict-only mandatory
policy, durable approval, hash-chained audit, monotone delegation, and
conservative lowering. It changes the framing and the target dispatch
architecture: `HostRouter` is the single dispatch path for every mediated
framework operation, and `ToolNode` and `guarded_tool` are callers into it.

This ADR supersedes ADR 0003's separate innermost-boundary framing for
`ToolNode` and `guarded_tool`. It refines ADR 0004's default-deny rule, ADR
0005's approval semantics, and ADR 0006's fail-closed behavior for the expanded
object model and host contract. ADR 0001 is untouched: DAC still runs before
restrict-only mandatory policy. ADR 0002's private security blobs remain in
force.

## Decision

slangGraph is a user-space object manager for ten framework object classes.
Each operation on those classes is dispatched through `HostRouter`, where the
hook stack can refuse it. Host-resource authority is compiled into a grant and
enforced by the kernel or another selected enforcer. The composed framework and
host layers are the system reference monitor.

The scope rule is:

> An operation is in scope if and only if a hook on the single dispatch path can refuse it.

Scope is determined only by hook placement and refusal authority. Whether a
shipped policy currently permits an operation, records labels only, or enables
a reference policy by default does not change scope.

## Object classes and operations

The seven existing hook names are frozen:

- `tool_alloc_security`
- `cred_prepare`
- `cred_transfer`
- `tool_call_prepare`
- `tool_call_permission`
- `tool_call_post`
- `resume_permission`

New hooks are additive and default to `ALLOW`, so existing modules remain
source-compatible. All hooks return a verdict and may emit forbid policies and
labels within the module contract.

That compatibility default applies only to the module layer. Constructive DAC
for an undeclared tool grants `tool_read` no state channels and no store keys,
matching the undeclared default of no authority in every other class.

| Object class | Operations | Refusing hook or enforcement point |
| --- | --- | --- |
| Principal | `bind`, `transfer`, `attenuate` | `cred_prepare`; session transfer plus `cred_transfer`; `cred_transfer` |
| ToolCall | `prepare`, `invoke`, `post` | `tool_call_prepare`; `tool_call_permission`; `tool_call_post` |
| Dispatch | `subgraph`, `Send`, `parallel_branch`, `subagent`, `nested_agent` | `cred_transfer` plus an explicit child-subset check for every dispatch |
| ToolRegistry | `register` (static at compile time and dynamic at runtime), `override` | `tool_alloc_security`; inference supplies the undeclared default and every override is audited |
| State | `write`, `restore`, `tool_read`, `model_read`, `store_read`, `store_write` | new `state_write`, `state_restore`, and `state_read` hooks; restore also verifies the hash chain and principal binding; store keys are resources with owners and labels |
| Approval | `resume` | `resume_permission`, followed by the complete permission chain again; approval is per call, not per policy line |
| FrameworkOp | `guard_operation` | existing `guard_operation` dispatch |
| ModelInvocation | `invoke` | new `model_invoke`; the full verdict denies or strips labeled context before prompt assembly |
| Output | `emit(destination)` | new `output_emit`; the full verdict is allow, deny, redact, or escalate, with content, confidentiality and integrity labels, and destination clearance visible to the hook |
| HostResource | `file`, `socket`, `exec`, `syscalls`, `limits` | kernel enforcement of the compiled grant |

`state_read` covers tool, model, and store reads. `state_write` covers graph state
and store writes. Hook request types distinguish the operation and resource;
they are not separate public hook names.

Same-principal dispatch, including a parallel branch of one agent, still runs
`cred_transfer` and emits an identity-transfer record. The record makes the
dispatch visible in audit even when no authority is attenuated.

## Default policy

The syntax, engine, broker phase, module contract, and naming choices below are
decided by default; the instructor may reverse any of them before PR 1 without
a new ADR.

This section describes shipped defaults, not scope. `model_invoke` and
`output_emit` ship label-only. Reference non-exfiltration, integrity, and
compartmentalization policies over those operations ship off by default.

The default user syntax is one `.slp` file containing `tool`, `principal`, and
`policy` blocks. The `policy` block is forbid-only and compiles internally to
the mandatory-policy engine. Users do not see Cedar. Cedar is the default
engine because it is analyzable and forbid-wins. A deployment that already
operates OPA may provide it behind the same `Policy` interface.

Modules return verdicts, forbid policies, and labels only. They request human
review through the hook's `ESCALATE` verdict. Broker and resource-side
credential enforcement are phase two.

The naming default is `slanggraph` for the package and CLI, slangGraph in prose,
and `.slp` for grammar files; the bare name "slang" is not used.

## Complete path cover

Placement analysis must map every path from untrusted input to a
security-relevant effect to a refusing operation. A path that cannot be placed
fails compilation.

| Untrusted-input-to-effect path | Required mediated landing |
| --- | --- |
| The model proposes a call | ToolCall `prepare` and `invoke` |
| A proposal arrives through a subgraph, `Send`, or subagent | Dispatch plus `cred_transfer` and child-subset check |
| Injected content changes an argument | ToolCall `prepare` and `invoke` after final normalization |
| Injected content is written to state and read later | State `write`, then the applicable `tool_read` or `model_read` |
| A tool result carries a secret into context | ToolCall `post`, State `write`, and ModelInvocation `invoke` |
| Another thread's data arrives through the store | State `store_read` on a key resource with owner and labels |
| A checkpoint is tampered with or replayed | State `restore`, hash-chain verification, and principal binding |
| A tool is added at runtime without a profile | ToolRegistry `register`, `tool_alloc_security`, and undeclared-default inference |
| A human approves a call | Approval `resume`, then the complete permission chain again |
| A tool touches the operating system | HostResource enforcement from the grant |
| Output targets a destination with lower clearance | Output `emit(destination)` |
| A child's output returns to its parent | Output `emit`, label propagation, and the parent State `write` |

## Trust per node

Operator-authored nodes are trusted by default. Imported components are
untrusted by default. Promotion is an audited operator action, analogous to a
DAC override.

Trusted node code runs in the coordinator. Hooks are honored by assumption;
placement analysis checks that assumption. Placement analysis is a check on
the trust assumption, not a security boundary.

Untrusted node code is dispatched through `HostRouter` as a unit of work in a
separate process. Its framework-object access crosses the same channel used by
tools, so hooks mediate it by construction. Trusted and untrusted modes expose
the same hook surface, and a module cannot distinguish them.

No untrusted code runs in the coordinator process. The framework runtime,
policy backend, grant compiler, modules, and operator-promoted trusted nodes are
inside the framework TCB; untrusted nodes and tools are not.

## Invariants

- Complete mediation: every operation on the ten classes crosses the hook stack through HostRouter as the single dispatch path; `ToolNode` and `guarded_tool` are callers into it, not peers.
- Tamperproofing: no untrusted code in the coordinator process; modules cannot widen authority (verdicts, forbid policies, labels only; never permits; never mutation of principals, grants, or audit).
- Policy flow: host enforcement implements the grant exactly or tighter, recorded per rule as `exact | tightened | unsupported`; looser is a denial; unsupported is a denial unless the class is explicitly waived.
- Fail closed: exception, timeout, malformed output, missing principal, unverifiable checkpoint, unlowerable class, unplaceable path all deny, named in the audit.
- Monotonicity: `prepare`, `attenuate`, and every dispatch yield a subset of the parent's authority, checked by the evaluator and, where the backend supports it, by the kernel. Delegation and every minted credential get an explicit child-subset check regardless of kernel attenuation.
- Verifiability: TCB enumerated per layer (host: kernel, adapter, launcher, broker; framework: coordinator, LangGraph runtime, policy backend, grant compiler, modules, trusted node code); coverage tracked per operation in `status.md`.

## Out of scope

The following are outside the claim because no hook can be placed or no
enforcement exists:

- reads performed directly by trusted node code;
- kernel bugs and side channels;
- remote services that provide no usable scoping mechanism;
- name-based network policy without a proxy;
- what a tool computes over data it was granted, although where the result goes
  is in scope through `post` and `output_emit`;
- the model-provider channel, discharged for evaluation by using local Ollama;
  and
- denial of service.

Model invocation and output are not on this list: both have refusing hooks and
are therefore in scope.

## Host capability contract

Host capabilities are probed and attested per boot. The Landlock ABI is obtained
from the return value of
`landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`, never by
comparing a kernel version. Attestation also records cgroup v2 delegation and
`cgroup.kill`, unprivileged user-namespace availability, BPF LSM, Landlock
audit support, and the mechanism that confined each call.

Compilation fails on an unsupported rule class unless the operator supplies a
per-class waiver with a reason. Every audit record for affected calls is stamped
`unenforced`. Module-introduced classes are rechecked at grant time; an
unsupported class denies that call. Each lowered rule records `exact`,
`tightened`, or `unsupported`.

`slanggraph check --backend X profiles/` is the profile/backend linter and exits
nonzero when an unwaived class is unsupported.

## Mandatory-policy redlines

- The evaluator creates one ephemeral `permit` for each surviving DAC line and
  combines it with operator forbids.
- Any diagnostic or evaluation error denies the affected line. A type error in
  a module forbid denies the line and names the module; that availability cost
  is intentional.
- Modules are forbid-only. They never submit a `permit` or mutate the ephemeral
  permit, entities, principals, grants, or audit.
- The escalation policy set is operator-owned.
- Cedar symbolic analysis is an explicit offline verification step, not free
  validation on the request path.

## Kernel and worker redlines

- Landlock network objects are ports, not endpoints. Endpoint or name policy
  requires a proxy or broker.
- `exec(target)` is lowered with Landlock `EXECUTE`.
- Seccomp admits or rejects syscall classes only. It returns
  `SECCOMP_RET_ERRNO` with `EPERM` for `socket` and `connect`, so libraries fail
  gracefully, and uses `SECCOMP_RET_KILL_PROCESS` for `ptrace`,
  `process_vm_readv`, `bpf`, and `unshare`.
- CPU, memory, and PID limits use cgroup v2; file-descriptor limits use
  `RLIMIT_NOFILE`; wall time is enforced by the supervisor using a timer and
  pidfd kill. Without cgroup delegation, `RLIMIT_CPU` and `RLIMIT_AS` are the
  fallback and `limits` is reported as a strict subset.
- Filesystem paths are resolved with
  `openat2(RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS)` into `O_PATH` descriptors
  passed as `parent_fd`. Create permission applies to the resolved parent. The
  IR contains no `realpath` strings.
- The trusted parent constructs the complete Landlock ruleset and passes the
  worker a single ruleset fd. The worker only calls `restrict_self` and holds no
  `O_PATH` descriptors. A clean fd table before `restrict_self` is mandatory.
- The spawner is single-threaded and starts before any threads exist. A template
  process contains no untrusted code; each call forks a fresh worker, tightens
  it, and only then imports the target. Workers are not pooled by domain alone.
- Every grant includes an explicit, attested, visible, read-only runtime
  baseline for the interpreter, standard library, tool packages,
  `/dev/urandom`, and temporary storage.
- Phase one requires no namespaces. Bubblewrap depends on unprivileged user
  namespaces, which Ubuntu 24.04 restricts by default; Landlock and seccomp do
  not. Landlock is primary, `pid_isolation` is attested, and each audit records
  the confinement mechanism.
- Landlock audit is separately attested because it is available only from Linux
  6.15. On older kernels, the worker's `errno` is denial evidence.

## Phase-two broker redlines

The trusted parent creates a `socketpair()` before confinement. After
confinement, the worker cannot call `socket()` or `connect()`. Descriptors are
`CLOEXEC` by default. Each broker channel is bound to a spawn record containing
the principal, tool, grant hash, and nonce; worker-supplied identity is never
trusted. Initial credential issuers are GitHub App installation tokens and AWS
STS session policies.

## Approval and pipeline order

Approval is for one call, not one policy line. An `ESCALATE` interrupts the
call; resume begins a new evaluation of the complete permission chain and may
not bypass a changed principal, policy, arguments, grant, or host capability.

```text
profile + principal + shares
            |
            v
constructive DAC candidates
            |
            v
prepare / normalize / re-run DAC
            |
            v
one ephemeral permit per surviving line + operator forbids
            |
            v
                         call verdict
                        /      |      \
                       v       v       v
                    deny     allow   ESCALATE
                      |        |        |
                      v        |        v
                     stop      |  approval for this call
                               |        |
                               |        v
                               |  complete permission chain again
                               |        |
                               +---+----+
                                   |
                                   v
                        canonical Grant and lowering
                                   |
                                   v
                          HostRouter dispatch
```

## Documentation changes

`README.md`, `reference.md`, `escape-analysis.md`, and
`users/security-boundary.md` are rewritten around the object-manager framing,
scope rule, and ten-class scope list. `status.md` gains per-operation and
per-authority coverage tables. `host-routing-completeness.md` is extended from
seven entry points to the full router set, and `ToolNode` and `guarded_tool` are
removed from its exclusions as they become router callers.

## Delivery order and freeze points

Phase one is planned as approximately five weeks. The order is mandatory:

1. Make `HostRouter` the single dispatch path. Route `ToolNode` and
   `guarded_tool` through it and retire their separate completeness arguments.
2. Add router entry points for Dispatch, ToolRegistry, State, ModelInvocation,
   and Output with the hooks defined above.
3. Mediate `ToolRuntime` injection. Profiles declare readable channels and
   store keys; tools never receive `config` and receive only their principal ID.
4. Verify checkpoint restore against the hash chain and bound principal; model
   store keys as owned and labeled resources.
5. Run `tool_alloc_security` and inference for dynamic registration, applying
   the undeclared default at runtime.
6. Enforce the compile gate: unmediated paths fail compilation, in-process
   execution of untrusted code is rejected, and all 56 current findings are
   removed or waived with reasons.
7. Deliver PR 1 for profile grammar and the monotone constructive DAC evaluator;
   PR 2 for attributed, canonical `Grant` construction; PR 3 for Cedar; PR 4
   for backend contract, attestation, `advisory`, capability gate, and the
   `check` linter; and PR 5 for Landlock, seccomp, cgroup v2 with rlimit
   fallback, and the spawner.

Frozen now are the seven existing hook names and invocation structure. The
`tool_call_permission` return contract, `Grant`, Cedar request construction,
backend contract, audit schema, and new hook signatures remain open. The
profile grammar freezes after PR 1; `Grant` and Cedar request construction
freeze after PR 3; backend and audit contracts freeze after PR 4. The course
contract promises only hook names and "return a verdict, optionally emit forbid
policies."

Phase two adds broker credential custody and scoped tokens, an MCP stdio proxy,
the `slanggraph-exec` launcher, a second `wasi` or `microvm` backend, and the
evaluation harness.

## Claim gates

No guarantee is printed until its corresponding tests pass under both `invoke`
and `ainvoke`.

Kernel gates cover a granted file while a second file and `ctypes` `open(2)`
receive `EACCES`, grandchild non-expansion, and a per-backend conservative
lowering property. Contract gates cover unsupported compilation, waived
`unenforced` audit stamps, the same profile reported as `exact` on Landlock ABI
4, and denial of module-introduced unsupported classes.

Object-model gates cover subgraph and `Send` dispatch under `DenyAll`, one
`cred_transfer` record per dispatch, undeclared dynamic registration, principal
isolation for store reads, checkpoint tamper refusal, low-integrity inputs to
irreversible calls, and a completeness test for every router entry point.
`ToolNode` and `guarded_tool` have no separate completeness tests.

Read/output gates cover undeclared channels, context stripping before a
lower-clearance model invocation, blocking secrets from lower-clearance output,
and low-integrity labels on child output returned to a parent. Cedar rejects a
module that emits `permit`. Phase two proves broker custody and exact token
scope.

## Consequences

The claim becomes precise: slangGraph is a reference monitor for the ten
framework object classes, composed with the host kernel as the monitor for OS
objects. Interface mediation can authorize a call but cannot bound a vulnerable
tool; kernel confinement can. Placement analysis supports the trusted-node
assumption and proves coverage only for the paths and operations in its model.

The architecture has a larger TCB and a stricter deployment contract. It also
has one vocabulary for trusted and untrusted execution, one auditable dispatch
path, explicit degradation, and no silent widening during policy evaluation or
grant lowering.

Use `slanggraph` for the package and CLI, slangGraph in prose, and `.slp` for
grammar files. Do not use the bare name "slang."

## References

- SELinux Project, [Implementing SELinux-aware applications and object
  managers](https://github.com/SELinuxProject/selinux-notebook/blob/main/src/implementing_seaware_apps.md).
  This documents X, D-Bus, and SE-PostgreSQL as user-space object managers.
- PostgreSQL, [sepgsql](https://www.postgresql.org/docs/current/sepgsql.html).
  PostgreSQL describes sepgsql as making PostgreSQL a user-space object manager.
- Xiaolan Zhang, Antony Edwards, and Trent Jaeger, [Using CQUAL for Static
  Analysis of Authorization Hook Placement](https://www.usenix.org/legacy/event/sec02/full_papers/zhang/zhang_html/),
  11th USENIX Security Symposium, pages 33–48, 2002.
- Trent Jaeger, Antony Edwards, and Xiaolan Zhang, [Consistency Analysis of
  Authorization Hook Placement in the Linux Security Modules
  Framework](https://research.ibm.com/publications/consistency-analysis-of-authorization-hook-placement-in-the-linux-security-modules-framework),
  ACM Transactions on Information and System Security 7(2), pages 175–205,
  2004.
- Linux kernel documentation, [Landlock: unprivileged access
  control](https://docs.kernel.org/userspace-api/landlock.html).
- Linux kernel documentation, [Seccomp BPF](https://docs.kernel.org/userspace-api/seccomp_filter.html).
- Cedar Policy Language Reference Guide,
  [Authorization](https://docs.cedarpolicy.com/auth/authorization.html).
