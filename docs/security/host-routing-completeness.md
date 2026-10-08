# HostRouter completeness

`HostRouter` is the target single dispatch path for every operation in ADR
0007's ten-class model. The current machine-generated certificate covers all 21
sync/async router entry points: seven ToolCall aliases and fourteen framework
object routes. Host-confined `ToolNode` and `guarded_tool` calls enter that core
through an exact-decision bridge; they are callers, not excluded peer
boundaries. Framework placement and trusted in-process compatibility are
tracked below and do not yet carry a system-wide complete-mediation claim.

The latest source review is recorded in [the October 8 recheck](#october-8-recheck-of-4ad6c95c).
The earlier validation results below are historical and do not supersede it.
The subsequent [verifier hardening](#verifier-hardening-after-the-recheck) changes
the default acceptance contract and adds source-bound publication obligations.

Generate the result from `libs/prebuilt`:

```sh
uv run python -m langgraph.prebuilt.security.boundary_verification \
  --output host-router-certificate.json
```

The [recorded certificate](host-router-certificate.json) contains the complete
inventory, path obligations, source and checker digests, and loaded-code binding.
The constructor reruns verification; it does not trust a supplied JSON report.

## Full router surface

| Object class | Operations | Router status |
| --- | --- | --- |
| Principal | `bind`, `transfer`, `attenuate` | Credential hooks are existing callers; every router dispatch checks child subset and transfer |
| ToolCall | `prepare`, `invoke`, `post` | Host-confined `ToolNode` and `guarded_tool` invoke through the verified core; preparation and post remain trusted callers |
| Dispatch | `subgraph`, `Send`, `parallel_branch`, `subagent`, `nested_agent` | Verified sync/async dispatch entries; only ToolNode parallel placement is automatic |
| ToolRegistry | `register`, `override` | Verified sync/async entries with allocation, inference, and override audit |
| State | `write`, `restore`, `tool_read`, `model_read`, `store_read`, `store_write` | Verified sync/async entry; ToolRuntime reads/store are placed, general state/checkpointer paths are not |
| Approval | `resume` | Verified sync/async call-bound entry reruns the full chain |
| FrameworkOp | `guard_operation` | Existing wrapper; unified entry pending |
| ModelInvocation | `invoke` | Verified sync/async deny-or-strip entry; model-node placement pending |
| Output | `emit(destination)` | Verified sync/async full-verdict entry; publication placement pending |
| HostResource | `file`, `socket`, `exec`, `syscalls`, `limits` | Host execution core admitted; backend coverage remains per authority |

Same-principal dispatch still runs `cred_transfer` and emits an identity-transfer
security record. Placement analysis must still show that every in-scope
framework operation reaches one of these entries.

## Exact claim

Given the trusted contracts below, every execution reachable through an admitted
router entry point passes through a fresh destination authorization for the same
principal, tool request, and policy constraints, followed by the host's atomic
activate-and-execute interface. Each cross-tool execution additionally requires
fresh decisions for the same origin, parent, child and destination request:

- host-authenticated caller provenance;
- permitted delegation;
- permitted caller-tool to destination-tool transition.

Constraints returned by destination, delegation and transition policies are all
passed to the host. None may be dropped or replaced. Non-ALLOW decisions and
exceptions stop the route. There is no catch-and-execute-locally fallback.
Retries call the router again and receive new decisions.

| Entry | Required decisions | Only allowed execution target |
| --- | --- | --- |
| `invoke`, `run`, `__call__` | Destination | Host `invoke` |
| `ainvoke`, `arun` | Destination | Host `ainvoke` |
| `invoke_from` | Origin, delegation, transition, destination | Host `invoke_from` |
| `ainvoke_from` | Origin, delegation, transition, destination | Host `ainvoke_from` |
| `route`, `aroute` | Object-specific hook stack | Host object dispatch |
| `resume`, `aresume` | Resume plus the complete original chain | Host object dispatch |
| `dispatch`, `adispatch` | Child-subset plus `cred_transfer` | Host dispatch effect |
| `register`, `aregister` | Allocation/inference and registry policy | Host registry effect |
| `state`, `astate` | State/store/checkpoint policy | Host state effect |
| `model_invoke`, `amodel_invoke` | Model context policy | Host prompt assembly |
| `output_emit`, `aoutput_emit` | Output/destination policy | Host emission effect |

The source analyzer discovers methods independently of this admission table.
Adding a method, an unclassified attribute, a subclass, a raw callable return,
or an unresolved call cannot silently extend the certificate. Cross-tool routes
cannot use the root host interface even if their destination authorization passes.
The constructor compares loaded method bytecode with the checked source and
rejects mismatched globals, defaults, closures, inheritance and runtime methods.
The trusted controller must keep these bindings unchanged after construction.

Certificate schema 2 also records every analyzed authorizer call and its input
identities. Each entry has an explicit required protocol. In particular, resume
must use `object_resume_permission` with the original principal, request, and
approval. Ordinary object authorization cannot satisfy that entry's protocol.
Source-only negative variants check missing guards, substituted effective
requests, repeated dispatch, changed principals, and substituted resume inputs.

## Host trust is explicit

This design does not analyze the tool body or attempt to prove the kernel's MAC
implementation. The host must fulfill the `BoundaryHost` contract:

1. Install the policy bound to the exact principal/request/tool/constraints before
   any tool import, initialization or execution. Never fall back to control-plane
   execution. Unsupported host enforcement must deny.
2. Enforce resource access through trusted MAC/LSM or equivalent confinement.
3. Authenticate a cross-call against a live worker channel, not caller-supplied
   tool names or principal fields. Bind/revalidate that origin at nested dispatch.
4. Keep root admission, policy objects, the router object and other tools'
   execution authority inaccessible to workers. Registered-tool authority may
   only be entered through the mediated channel.
5. Preserve every supplied policy restriction and correctly terminate or confine
   workers when requests fail or are cancelled.

**Trusting LSM correctness alone does not prove these adapter properties.** The
routing certificate assumes the host adapter fulfills them. The current Linux
executor's activation machinery has separate source-bound review evidence and
integration tests; this certificate does not upgrade that evidence to a proof
of every host implementation. Root execution through the new router has been
exercised against the real `LinuxSandboxExecutor`, with activation receipts.

Cross-tool identity refers to entry into another registered tool's execution
authority. It is not a claim to recognize arbitrary internal Python helper calls
or prevent a tool from reimplementing an algorithm under its own confined authority.

## Using the router

```python
from langgraph.prebuilt.security.host_boundary import (
    HostExecutorBoundary,
    StackBoundaryPolicy,
    make_host_router,
)

router = make_host_router(
    StackBoundaryPolicy(security_stack),
    HostExecutorBoundary(linux_executor),
)
result = router.invoke(authenticated_principal, prepared_tool_call)
```

The controller prepares requests from a trusted registry of tool metadata and
binds authenticated principals outside model-controlled state. Request contents
and security identities must remain immutable throughout the call. Policy code
and Python control-plane construction are trusted; tool code runs only in the host.

`StackBoundaryPolicy` uses existing DAC/MAC preparation and permission hooks.
Preparation transforms deny with `router:transforms_require_new_request` rather
than changing an already bound request. Escalations must be handled outside this
router by creating a newly authorized request. The adapter checks principal,
session, roles, scopes and delegation identity before credential-transfer hooks.
Its tool-transition allowlist defaults to deny. Richer policies can implement
`BoundaryPolicy` directly; their semantics are an explicit trust assumption,
while the router's enforcement of their decisions is checked.

For a host implementing authenticated cross-tool RPC:

```python
policy = StackBoundaryPolicy(
    security_stack,
    transitions=frozenset({("search", "fetch")}),
)
router = make_host_router(policy, authenticated_rpc_host)
result = router.invoke_from(origin, parent_principal, child_principal, call)
```

The host transport owns `origin.channel`. Constructing `ToolOrigin` with plausible
strings does not authenticate anything. Only the authenticated worker endpoint
may submit nested calls; workers must not choose the root route.

`HostExecutorBoundary` deliberately **denies cross-tool calls**, because the
existing Linux executor has no authenticated nested-tool RPC transport. It never
invents an origin or treats a nested request as a root call. This provides a safe
root-only integration today. Supporting nested execution requires a host that
implements the full `BoundaryHost` protocol.

## What remains outside this certificate

The exact-decision bridge admits the host-confined execution branches of
`ToolNode` and `guarded_tool`; their preparation, flow reservation, post
handling, and trusted in-process compatibility branches have not moved into the
router certificate. Approval now has its own verified router route. General
subgraph/`Send`/agent, state/checkpointer, model-node, and publication paths
remain outside the system claim until placement analysis assigns their
operations to a router entry point. The broader installed-framework report
therefore remains incomplete.

The result establishes routing/decision completeness within the stated boundary,
not policy correctness, absence of tool bugs, availability of every API, full
publication confidentiality, or arbitrary Python confinement.

The analyzer and its Python execution model are also trusted. Its implementation
has regression and negative-mutation tests, but no independently machine-checked
soundness proof. A passing certificate is a conditional result from this checker,
not a proof that the checker itself has no defects.

The generated certificate currently reports 21 discovered, 21 obligated, and
21 verified entries. The mandatory Tool APIs pass 15,744 API-conformance cases.
The [layered report](layered-verification-report.json) is the current assurance
inventory. The [older installed-source summary](source-verification-summary.json)
is historical evidence; it is not refreshed by this router certificate.

## Implementation review after the object-manager update

The updated implementation includes `MediatedNode`, `MediatedBranch`,
`OutputMediator`, `MediatedCheckpointer`, graph compilation integration, and
sync/async stream filters. Earlier status descriptions saying these adapters
were entirely absent are stale. Their existence and passing examples do not
establish complete path coverage.

The following source-review obligations remain. These are findings from reading
the implementation, not executed bypass demonstrations or an exhaustive audit:

1. **Bind actual adapter effects to effective authorization.**
   `MediatedStore.batch`/`abatch` authorizes through an object manager but then
   sends the original operations to a different backing store. The returned
   authorized value is discarded. `MediatedCheckpointer._metadata` similarly
   discards the state-write result before `put` writes the original checkpoint;
   restore discards the routed result before returning the original tuple.
   Authorize the authoritative backing object and apply the effective result,
   or reject transformations that the adapter cannot enforce. Cover owner and
   label lookup against the actual store, not only its separate shadow state.
2. **Re-run object DAC on resume.** `ObjectManagerPolicy` checks `_dac` on ordinary
   object permission but inherits resume from `StackBoundaryPolicy`, which
   calls the stack directly. Resume must re-enter constructive object DAC and
   the mandatory chain with current policy. The router certificate treats that
   policy primitive as trusted and cannot prove its implementation semantics.
3. **Cover all framework-supported value shapes.** `MediatedNode._state_writes`
   handles mappings and an individual `Command`; graph state extraction also
   supports root values, object schemas, and lists of commands. `_model_input`
   passes non-mappings through without `model_invoke`. Normalize all supported
   forms before mediation, or reject unsupported forms at the secured boundary.
4. **Partition authoritative state and preserve labels.** `ObjectManagerHost`
   keeps state under the channel name alone, shared by invocations of a compiled
   graph. Establish principal/session/graph identity for state storage and reads.
   `labels_for_output` infers labels from matching values and field names; this
   is not a complete provenance argument for derived or renamed values.
5. **Account for every publication and checkpoint API.** The final stream
   filters cover ordinary stream yields, while Pregel still sends `loop.output`
   to completion callbacks separately. Checkpointer history and administrative
   methods delegate directly to the underlying saver. Give each channel an
   enforced decision or an explicit, justified TCB-only admission boundary;
   testing ordinary `invoke`/`ainvoke` is insufficient.
6. **Establish the worker boundary.** `UntrustedNodeHost` is a protocol supplied
   by the operator. Interface conformance does not establish process isolation
   or authenticated object RPC. `HostExecutorBoundary` still denies nested tool
   calls. Keep these adapter obligations distinct from the assumed correctness
   of host MAC.

The layered inventory holds the protected operation set independently of
existing hooks. A missing hook is a coverage failure, not a reason to remove an
operation from scope. Reviewed waivers remain explicit assumptions and never
become path-cover proofs.

Developers can now run `make security-verify` in `libs/prebuilt` to obtain
source-located regression findings for these review patterns, router failures,
and waiver problems. The [developer workflow](source-verification.md#developer-acceptance-workflow)
documents rule IDs, report comparison, extension tests, and the separate strict
system gate. The acceptance run before the October 8 checker extension had no
implementation-owned findings. The verifier's three unfinished proof areas remain explicitly assigned
to the verifier in the output, so the acceptance pass is not a system proof.

Validation of this verification update:

- Router source/runtime certificate: 21/21 entries and 21 dispatch obligations
  pass, including the stronger per-entry authorization protocol checks.
- Focused effective-value, object-manager, placement, callback, and checkpoint
  regression tests: 54 pass. The secured React-agent regression verifies that
  hooks, nodes, and conditional edges are wrapped before execution.
- Tool API conformance: 15,744/15,744 cases across 72 surfaces pass, with no
  background errors. This uses synthetic host oracles, not a fresh kernel proof.
- `make format` and `make lint` pass in both modified libraries.
- `make test` passes with 1,827 tests in `libs/prebuilt` and 1,737 tests in
  `libs/langgraph`; the latter also reports 295 environment-dependent skips.
- Escape discovery reports 55 exact reviewed findings, 55 matched waivers, no
  unwaived finding, and no stale or malformed entry. Nineteen line-shifted
  React-agent findings were re-reviewed against the secured-placement regression
  before their exact fingerprints were updated. These waivers remain explicit
  assumptions and are not promoted to path-cover evidence.

The layered `--require-complete` gate fails intentionally while the placement,
adapter-composition, and host-isolation proofs are absent. Its inventory hashes
149 Python files and lists 70 route candidates. Candidate counts are not a
coverage percentage or an exhaustive count of protected effects.

## October 8 recheck of `4ad6c95c`

The original developer acceptance checks pass on `4ad6c95c`, including the
21-entry router certificate. Source review still finds two incomplete read
adapters. The checker now reports both as `SGV107` and `SGV108`, with separate
sync/async diagnostics. The [fresh developer report](developer-verification-report.json)
has four implementation findings and three verifier-owned proof gaps. Both
`make security-verify` and `make security-verify-complete` fail on this snapshot.

1. **Backing-store read results bypass effective-value mediation.**
   `MediatedStore.batch` and `abatch` return backing results directly
   (`object_manager.py:453,461`). `_authorize` supplies `None` for `GetOp`, while
   `_effective_store_operation` only applies routed values to `PutOp`.
   `ObjectManagerHost` consults its separate store metadata and returns `None`
   when the resource is absent there; that does not authenticate ownership or
   labels of an existing backing-store item. The write transformation fix is
   present, but read transformations cannot affect the returned backing value.
   Bind authorization to authoritative backing ownership/labels and return the
   effective read value; reject unknown ownership when it cannot be established.
2. **Checkpoint history does not verify returned tuples.**
   `MediatedCheckpointer.list` and `alist` authorize query options, then yield
   backing tuples directly (`checkpoint_security.py:78,112`). Unlike the
   `get_tuple` path, these paths do not authenticate the checkpoint envelope,
   principal/session binding, or pending writes. Authenticate each history tuple
   before publishing it and apply effective read results. This requires a
   non-consuming verification operation: calling the existing restore verifier
   directly would also consume replay state.

These are source-review findings, not executed bypass demonstrations. Added
regression fixtures are parsed as source and never executed. The new rules are
narrow review patterns; clearing them is not a composition proof. Host MAC
correctness remains an assumption and does not establish these application-level
ownership, integrity, and value-propagation properties.

Recheck validation:

- Router: 21/21 entries verified.
- Tool API conformance: 15,744/15,744 cases across 72 surfaces pass, with no
  background errors. This is the declared conformance matrix, not all possible
  application executions or a system completeness result.
- Focused verifier regressions, including the new source fixtures: 83 pass.
- Full `libs/prebuilt` suite: 1,827 tests pass. That run collected before the
  five new parsed-source cases were added; those cases passed in the focused run.
- `make format` and `make lint` pass in `libs/prebuilt`.
- Strict mypy over the security package reports 29 errors in seven implementation
  files; strict mypy on the changed adapter checker passes. The normal lint
  target uses `ty`, which passes.

The strict gate continues to report `SGV901` (placement proof), `SGV902`
(adapter-composition proof), and `SGV903` (host adapter/isolation composition
evidence). These are verifier-owned obligations, not requests to re-prove the
assumed security of Linux MAC.

## Verifier hardening after the recheck

The default developer command now fails unless system verification is complete;
`security-verify-complete` is an equivalent compatibility target. Schema 2
reports known regression status separately. A clean pattern scan, a missing
model, an unsupported source operation, or an exhausted analysis budget can no
longer produce an acceptance pass.

The shared transfer engine now checks exact return-value grants, principal and
resource bindings, helper/alias propagation, conditional exits, inherited APIs,
and exception publication within its supported language and explicit primitive
contracts. Source-only tests include valid contracts as well as rejected and
unresolved candidates. Ordinary helpers are analyzed rather than trusted by name.

The repository report includes 2,190 source-bound declaration obligations across
the entire supplied source snapshot, including newly added files. This is a
conservative declaration inventory that includes helpers and verifier code, not
a public-API count or completeness percentage. Publication transfer analysis
covers 49 discovered adapter methods: 10 have locally verified results and 39
are unresolved. Its source model is not closed, so the 10 local results do not
constitute an adapter proof. The four implementation diagnostics from the recheck
remain separate from this verifier-owned work.

Router calls are deliberately not modeled as primitives that always authorize
their returned values: they may return escalation objects. Modeling that result
protocol and receiver binding remains necessary, alongside authoritative
ownership/integrity, placement, and host-adapter composition. The new engine can
prove supported publication contracts, but this repository's system proof is
still incomplete. The verifier changes do not repair production adapters.

Validation: `make format` and `make lint` pass; strict mypy passes for all four
changed verifier modules. The full prebuilt run passes 1,866 tests. The final
focused verification run passes 926 tests, including two added after the full
run collected tests. The router certificate still verifies 21/21 entries.
Both default and compatibility completeness commands return failure as required
for the current incomplete evidence. The fresh schema 2
[report](developer-verification-report.json) contains the per-entry details.
