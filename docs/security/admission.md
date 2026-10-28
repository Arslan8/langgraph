# Closed node and branch admission (opt-in)

`langgraph.prebuilt.security.admission` is the compile-time gate that decides
whether a secured graph body is an admitted execution descriptor. It is enabled
only by `SecurityConfig(closed_admission=True)`; the default configuration is
unchanged. This document describes what the gate checks, which refusal codes it
raises, and what it does not prove. It is a description of implemented
behavior, not an acceptance claim: the gate does not close SGV901 by itself
(see [What the gate does not prove](#what-the-gate-does-not-prove)).

Source: `libs/prebuilt/langgraph/prebuilt/security/admission.py`, with the
hooks in `config.py` (`SecurityConfig.closed_admission`,
`_closed_admission_inventory`, `_verify_admitted_graph`) and `mac.py`
(`register_mac_boundary`, `RuntimeMAC.check`). Tests:
`libs/prebuilt/tests/security/test_admission.py`. The retained design and
findings are in
`eval/campaigns/remediation-v2/raw/checks/receipt-next-placement-v1/report.json`.

## Purpose

Before this gate, `configure_graph` classified node bodies through
`resolve_placement`, which treats a function as operator code (`TRUSTED`) when
its mutable `__module__` lacks a `langchain_core.`/`langgraph.` prefix;
promotes any runnable in which the recursive `_find_tool_nodes` search finds a
`ToolNode`; accepts `security_trust`/`security_promotion_reason` metadata as
authority; and decides model placement by a class-name heuristic (`_is_model`).
`MediatedNode.invoke`/`ainvoke` then call `self.runnable.invoke`/`ainvoke`
with coordinator configuration. The retained witness
`eval/campaigns/remediation-v2/raw/checks/composition-placement-gap-v1/`
shows an ordinary Python node executing in the coordinator through that path.

Closed admission replaces classification with a closed inventory: every node
and branch of the builder must be admitted by exact type identity and captured
native storage, or the compile refuses before any candidate protocol
(`get_name`, `isinstance`, `getattr` with defaults, `inspect.signature`,
schema construction) runs on the candidate inside `config.py`.

## The predicate

Every secured graph entry must reference an admitted execution descriptor:

1. an exact validated language IR program with closed terminal IDs
   (`_language_sandbox.LanguageProgram` behind `inprocess.ManifestAdmission`);
2. an exact framework dispatch primitive with no arbitrary callback payload (an
   exact `ToolNode` whose dispatch path is checked and that has no pre/post
   wrappers); or
3. a validated native node/graph deployment handled by a concrete confined
   host (`container.DockerObjectDispatcher` or a direct
   `linux.LinuxSandboxExecutor` deployment).

Ordinary callables, arbitrary `Runnable` subclasses, implicit module-name trust
(`__module__` prefixes), metadata promotion (`trusted`/`reason` overrides) and
wrappers that merely contain a `ToolNode` do not satisfy the predicate. The
gate reads candidate objects only after `type(x) is` checks on framework
classes whose storage is native; it never calls `isinstance` or `getattr` with
a default on a candidate before that check.

Binding is by captured implementation, not by name: each descriptor holds the
exact captured object graph (`implementation`, excluded from equality), an
`identity` digest (SHA-256 over canonical JSON of the captured program,
deployment or loaded-code projection) and a `source_sha256` digest over the
underlying source/artifact digests. A source hash or class name alone is not
treated as runtime binding. Admission never redispatches through
candidate-controlled instance methods or mutable `func`/`afunc`/`bound`/`steps`
references, and `recheck` re-reads the live links on every check.

## Admitted kinds

`AdmittedKind` is a closed enumeration. `admit_node` yields the first three
kinds; `admit_branch` yields the fourth.

### `language_program`

- Node: exact `ToolNode`; `func`/`afunc` are the exact bound
  `ToolNode._func`/`ToolNode._afunc`; `_wrap_tool_call` and `_awrap_tool_call`
  are `None`; `_tools_by_name` is an exact `dict` of exact `StructuredTool`;
  no injected state/store/runtime arguments; `_security_host_executor` is
  `None` or the configured `host_executor`.
- Dispatch path: `config.host_executor` is an exact
  `ObjectPolicyHostExecutor` whose dispatcher is an exact
  `_LanguageSandboxDispatcher` and whose `admission` is an exact
  `ManifestAdmission`. On every state computation the authorizer must be an
  exact `CedarObjectAuthorizer` with an empty `enforcement_waivers` mapping.
- Program: `ManifestAdmission.validate()` must pass; the dispatcher's tool must
  be the node's single registered tool; every program must be an exact
  `LanguageProgram` whose `_snapshot()` yields a body, signature, terminal IDs
  and contracts with `set(terminals) == set(contracts)`, each with a recorded
  SHA-256 source digest.
- Identity: digest over tool name, program bodies, signatures (parameter name,
  kind, default), sorted terminal IDs, terminal contracts and source digests.
  `source_sha256` is the digest of the sorted program source digests.

### `tool_node`

- Node: the same exact `ToolNode` requirements as above.
- Dispatch path: exact `ObjectPolicyHostExecutor` with exact
  `CedarObjectAuthorizer` (no waivers) and an exact `ObjectBrokerDispatcher`.
- Deployment: every registered tool must have an exact `LinuxToolSpec` in the
  dispatcher's `MappingProxyType` registry with a `str` entrypoint and a
  SHA-256 artifact digest; `runtime_roots` must be an exact `tuple`.
- Identity: digest over tool names, host `broker`, runtime roots and the
  projected specs (tool, entrypoint, artifact path, artifact digest, whether a
  deployment is attached). `source_sha256` is the digest of the sorted artifact
  digests.

### `native_deployment`

Two dispatch paths yield this kind:

- Docker: exact `ObjectPolicyHostExecutor` with exact `CedarObjectAuthorizer`
  (no waivers) and an exact `DockerObjectDispatcher`; identity covers the
  image name, the worker digest (`_worker_digest`, SHA-256) and the projected
  `LinuxToolSpec` records.
- Direct Linux: `config.host_executor` is an exact `LinuxSandboxExecutor`
  (no dispatcher); identity covers host `linux`, runtime roots and the
  projected `LinuxToolSpec` records.

`source_sha256` is the digest of the sorted artifact digests in both cases.
Under an installed `RuntimeMAC` the direct Linux path remains refused with
`mac:tool_requires_object_authorization`, because `_check_tool_node` still
requires an `ObjectPolicyHostExecutor` with a Cedar authorizer and a
Docker/broker/language-sandbox dispatcher; its policy backend does not consume
`runtime_mac_forbids`.

### `framework_branch`

- Branch: exact `BranchSpec` whose `path` is an exact `RunnableCallable`.
- Function: `path.func` must be the pinned framework function. The registry
  currently contains exactly one entry, `langgraph.prebuilt.tool_node:tools_condition`,
  pinned by object identity and by loaded-code identity
  (`inprocess._code_identity(function.__code__)`) at first use.
- Async: `path.afunc` must be the framework shim
  `partial(run_in_executor, None, function)` with empty keywords;
  `path.kwargs` must be an empty `dict` and `explode_args` must be `False`.
- Ends: `branch.ends` is `None` or an exact `dict[str, str]`.
- Identity: digest over the registry id, the loaded-code digest and the sorted
  ends. `source_sha256` is the loaded-code digest.

## Refusal codes

Every refusal is a plain `PermissionError(code)` carrying one of the literals
below. The code registry owner registers them; this module only raises them.

| Code | Raised when |
|---|---|
| `admission:unsupported_node_body` | A node body is not an exact `ToolNode`; the node has pre/post tool-call wrappers, injected arguments, a non-`dict` tool registry, a tool that is not an exact `StructuredTool`, or a host executor/config other than the configured one; `config` is not an exact `SecurityConfig` or has no `host_executor`; the executor is neither an exact `ObjectPolicyHostExecutor` nor an exact `LinuxSandboxExecutor`; the dispatcher is not one of the three admitted dispatchers; the language dispatcher's admission is not an exact `ManifestAdmission`; the authorizer carries waivers; a registered tool has no exact `LinuxToolSpec`; or, under closed admission, the builder, its node map or a node spec/metadata is not the exact framework container. Plain functions, async functions, metadata-promoted nodes, wrappers holding a `ToolNode` and arbitrary `Runnable` subclasses all refuse with this code (tested in `test_unsupported_node_bodies_refuse_before_any_candidate_protocol`). |
| `admission:unsupported_branch` | A branch is not an exact `BranchSpec`, its `path` is not an exact `RunnableCallable`, its function is not the pinned framework function, `path.kwargs` is non-empty, `explode_args` is not `False`, `ends` is not `None`/`dict[str, str]`, loaded-code identity cannot be computed, or the branch name/config is malformed; or, under closed admission, the branch map or a branch spec is not the exact framework container. |
| `admission:unsupported_async` | A `ToolNode` whose `afunc` is not the exact bound `ToolNode._afunc` (a replaced async body), or a branch whose `path.func` is `None` (async-only body) or whose `afunc` is not the framework executor shim for the pinned function. Async is permitted only where the framework adapter supplies its own lifecycle; everything else refuses before starting. |
| `admission:descriptor_changed` | `recheck`/`describe` receive a non-descriptor, or a live link differs from the captured one: node `_security_host_executor` is not the captured executor, executor authorizer/dispatcher replaced, tool registry size or tool objects changed, `ManifestAdmission.validate()` fails, programs or source digests changed, worker/artifact digests malformed, `branch.path` replaced, pinned function or its `__code__` changed, or the recomputed kind/identity/source digest differs. `configure_graph` also raises it when a node or branch exists that was not in the admitted inventory, or when a mediated wrapper does not wrap exactly its captured implementation; `register_mac_boundary` raises it for a closed graph whose inventory and wrappers disagree. |
| `admission:closed_admission_required` | Registered but no longer raised. A secured graph compiled without `closed_admission=True` keeps the legacy runtime MAC behavior: the exact `MediatedNode`-wrapping-`ToolNode` shape with no branches is admitted post hoc, and every other body is refused as `mac:unconfined_graph_body`. |
| `admission:unsupported_callback` | Closed compilation, before any node: a channel reducer other than `operator.add`/`add_messages`, a non-default cache key or retry predicate, or a trace policy. |

The first unsupported body refuses the whole compile; no later node or branch
is read.

## Opt-in and unchanged default

`SecurityConfig.closed_admission` is a `bool` (a non-`bool` value raises
`TypeError`) and defaults to `False`. When `True`, `configure_graph`:

1. requires an exact `StateGraph` with `dict` nodes, `dict`/`defaultdict`
   branches, exact `StateNodeSpec`/`BranchSpec` entries and `None`/`dict`
   metadata, then calls `admit_node`/`admit_branch` for every entry before
   `_find_tool_nodes`, `resolve_placement` or any promotion runs;
2. wraps each admitted node as `MediatedNode` with
   `PlacementSpec(name, TRUSTED, STANDARD)` and each admitted branch as
   `MediatedBranch` with `trust=TRUSTED`, taken from the descriptor and never
   from module names or metadata;
3. after wrapping, verifies (`_verify_admitted_graph`) that every
   `MediatedNode.runnable`/`MediatedBranch.runnable` is the captured node/path
   and rechecks every descriptor;
4. attaches the inventory as `graph._security_admission:
   tuple[AdmittedDescriptor, ...]` on the builder, next to
   `_security_config`, `_security_placement_stack` and
   `_security_output_mediator`.

When `False`, the module is not consulted by `configure_graph` and the
previous classification path runs byte-for-byte as before. The default is
unchanged because closed admission refuses every graph that contains an
ordinary Python node, including the current useful outer evaluation workflows
(for example the Pandas outer graph, which the evaluation adapter compiles
without any `SecurityConfig`). Enabling it by default would relabel those
workflows as refused without providing the mediated model, input and
publication operations they need; that is recorded as future work in the
placement report, not as a safe one-line change.

`mac.register_mac_boundary` records a `_MacBoundary` per secured graph. For a
closed graph it binds the pre-protocol inventory to the mediated wrappers; for
the legacy shape it admits post hoc through `admit_node` and binds the result
to source/deployment identity, which cannot show that no compile-time protocol
ran earlier. `RuntimeMAC.check` rechecks each descriptor, requires
`mediated.runnable is` the captured implementation, and still applies
`_check_tool_node`. The strict form (closed admission required for every
secured graph under MAC) is not applied; see `eval/status.md`.

## What the gate does not prove

The gate closes the identified arbitrary node/branch body path within its
admitted surface and nothing else. It does not by itself prove:

- imports or module initialization of candidate code;
- builder initialization: `StateGraph.add_node` naming (`action.get_name`),
  `inspect.signature`/`get_type_hints` and schema construction run before
  `compile(security=...)` and are outside this module's control;
- reducer, cache (`cache_policy.key_func`) and retry (`retry_on`) callbacks;
- checkpointers and store access;
- stream callbacks and `RunnableCallable` recursive invocation of returned
  `Runnable` values inside admitted primitives;
- module mutation after capture beyond the links that `recheck` re-reads;
- output publication (`OutputMediator`, raw debug/state/event APIs);
- compiler, decoder or OS enforcement, including the Linux/Docker worker
  confinement that the admitted deployment relies on.

It also does not establish that a `MODEL` placement binds the actual model
call, that `MediatedNode`/`MediatedBranch` dispatch only captured descriptors
(the `self.runnable.invoke`/`ainvoke` path in `placement.py` is unchanged by
this module), or that `security=None`, precompiled graphs and raw Pregel entry
points are covered without an installed process-wide `RuntimeMAC`.

**This gate does not close SGV901 by itself.** SGV901 (placement proof),
SGV902 (adapter composition) and SGV903 (host adapter enforcement) remain open
in `eval/campaigns/remediation-v2/acceptance.json`. The
[supported-surface inventory](supported-surface.md) records the gate's codes
as route-independent entries; the security verifier does not consume that
inventory's route check IDs, and no check is waived by this document.
