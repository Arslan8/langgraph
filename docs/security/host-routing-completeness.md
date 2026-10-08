# HostRouter completeness

`HostRouter` is the target single dispatch path for every operation in ADR
0007's ten-class model. The current machine-generated certificate covers all 21
sync/async router entry points: seven ToolCall aliases and fourteen framework
object routes. Host-confined `ToolNode` and `guarded_tool` calls enter that core
through an exact-decision bridge; they are callers, not excluded peer
boundaries. Framework placement and trusted in-process compatibility are
tracked below and do not yet carry a system-wide complete-mediation claim.

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
The broader installed source proof remains unresolved; consult the
[current summary](source-verification-summary.json).
Those unresolved obligations are not converted into passing results by this
reference certificate.
