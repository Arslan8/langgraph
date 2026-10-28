# Useful Pandas route under the closed admission gate: implementation design

> Fact-checked 2026-10-27 (read-only review): six overstatements corrected in place and marked "corrected after fact-check"; vendor `pandas_data_analyst.py` line cites are unverifiable in this repo (upstream pin only).

Status: **design only, unimplemented**. Nothing in this document was executed.
It is the "useful Pandas route" half of
`eval/campaigns/remediation-v2/raw/checks/receipt-next-placement-v1/report.json`
(`useful_pandas_route`, lines 398-448; acceptance checks, lines 472-478). The
other half (the closed admission gate in `admission.py`/`config.py`/
`placement.py`/`mac.py`) is being built concurrently and is only referenced
here by the descriptor it is expected to accept. `implemented_guarantee`,
`system_complete` and `sgv901_closed`..`sgv903_closed` stay `false`
(report.json:479-483); this design does not change that.

Problem statement. Under `SecurityConfig(closed_admission=True)` every secured
graph entry must reference an admitted execution descriptor
(report.json:367-368). The useful Pandas workflow is ordinary Python at every
level: the outer `prepare_messages` / `routing_preprocessor` / branch /
`data_wrangling_agent` / `data_visualization_agent` / `finalize_output` nodes
(`pandas_data_analyst.py:338-493`), the two nested agent graphs, and the
evaluation adapter's `RequestPreservingStage` wrappers
(`eval/apps/pandas/workflow_contract.py:65-122`,
`eval/apps/backend.py:100-111`). Today only the innermost generated-code step
crosses a secured boundary (`eval/apps/pandas/integration.py:164-167,
219-235`); the model client and all vendor closures run in the parent
(report.json:358-364). The gate will refuse all of that, so the useful route
needs a different placement: the **whole vendor graph runs unchanged inside
one confined graph-unit worker**, and everything that has an effect on the
host (model, compute, dataset, state/publication) becomes an explicit,
authenticated host operation requested over a broker channel.

## 1. Effect inventory of the actual outer and nested workflow

Legend for "host op": `model_invoke` / `compute` / `dataset_input` /
`state_and_publication` / `none` (worker-local, inert). "Today (C)" is what the
present C configuration already mediates (`integration.py:121-134,145-162`:
one `compute` ToolNode backed by `LinuxSandboxExecutor` with the v2 receipt
lifecycle). "Absent" is what no secured host operation covers today.

| # | Node / helper (file:line) | Host op | Data crossing the boundary | Today (C) | Absent |
|---|---|---|---|---|---|
| O1 | `prepare_messages` (`pandas_data_analyst.py:338-372`) | none | nothing; message normalization in worker | runs in parent, unsecured | nothing to mediate; the node body itself needs admission (gate half) |
| O2 | `preprocess_routing` -> `routing_preprocessor = prompt \| llm \| JsonOutputParser()` (`:321`, `:373-397`) | model_invoke | request: 1 rendered prompt string; response: 1 assistant text; parse in worker. Fallback on exception at `:379-384` must be preserved | parent `ChatOpenAI` with callbacks (`backend.py:68-78`) | **model terminal** (no host op performs the provider call; `ObjectManagerHost.dispatch` returns `request.context`, `object_manager.py:236`) |
| O3 | `router_chart_or_table` (`:398-404`) | none | nothing | parent | branch body admission (gate half) |
| O4 | `invoke_data_wrangling_agent` (`:406-422`) | none (nested graph, see W*) | state dicts stay in worker | parent | nested-graph admission (gate half) |
| O5 | `invoke_data_visualization_agent` (`:423-447`) | none (nested graph, see V*) | state dicts stay in worker | parent | same |
| O6 | `finalize_output` (`:448-473`) | none | `pd.DataFrame(data_wrangled)` shape summary, in worker | parent | none |
| O7 | `RequestPreservingStage.prepare/invoke` (`workflow_contract.py:78-122`) | none | rewrites `user_instructions`/`recommended_steps` in worker | parent | none; must ship in the worker image unchanged |
| D1 | `pd.read_csv(fixture / "sales.csv")` (`backend.py:120`) | dataset_input | response: bounded CSV text; DataFrame constructed in worker | parent reads the fixture directly, unmediated | **dataset acquisition** (no pin/authorize/bounded-bytes op) |
| W1 | `_summarize_data_raw` / `get_dataframe_summary` (`data_wrangling_agent.py:620-634`) | none | nothing | parent | none |
| W2 | `create_data_wrangler_code` -> `prompt \| llm \| PythonOutputParser()` (`:735-815`) | model_invoke | 1 prompt (steps, instructions, summary, function name) -> 1 text | parent | model terminal |
| W3 | `execute_data_wrangler_code` -> `run_code_sandboxed_subprocess(..., timeout=15, memory_limit_mb=512, data_format="dataframe_list")` (`:883-893`) | compute | request: `{code, function_name, data (JSON of DataFrame.to_dict), memory_limit_mb, data_format, sandbox_serialization, computation_api}` exactly as `integration.py:182-192`; response: `{result, error}` JSON | **covered**: bridge -> ToolNode -> bwrap worker running `eval/apps/pandas/worker.py:9-30` with `recursive-json-v2` and `period-aggregation-v1` (`sandbox_codec.py:94-136`), receipts written at `integration.py:237-243` | the request must now originate from inside a confined worker over the broker instead of from the parent bridge |
| W4 | result processing: list/dict -> `pd.concat` / `pd.DataFrame`, dtype, `df_out.to_dict()` (`:895-965`) | none | nothing | parent | none |
| W5 | `fix_data_wrangler_code` via `node_func_fix_agent_code` (`:965-993`), bounded by `max_retries` (`manifest-v19.json:39`, `graph_retries: 3`) | model_invoke | broken code + error -> fixed code text | parent | model terminal |
| V1 | `_profile_dataframe` / `_build_prompt_context` (`data_visualization_agent.py:997`, `:1156-1157`) | none | nothing | parent | none |
| V2 | `chart_instructor` (`:932-1013`, llm at `:997-1005`) | model_invoke | 1 prompt -> 1 text | parent | model terminal |
| V3 | `chart_generator` (`:1013-1095`, llm at `:1089-1095`) | model_invoke | 1 prompt -> 1 text | parent | model terminal |
| V4 | `execute_data_visualization_code` -> `run_code_sandboxed_subprocess(..., data_format="dataframe")` (`:1150-1165`) | compute | same shape as W3 | covered as W3 | same as W3 |
| V5 | `plotly_from_dict`, chart-type validation, `_build_fallback_chart` (`:1202-1206`, `:1280-1286`, `:817`) | none | Plotly figure reconstructed in worker; result stays a JSON-able dict | parent | none; needs `plotly` in the worker image |
| V6 | `fix_data_visualization_code` (`:1319`) | model_invoke | as W5 | parent | model terminal |
| P1 | `Observer` callbacks writing `events.jsonl` `model_start`/`model_end`/`model_error` (`backend.py:39-61`) | state_and_publication (audit) | today: raw prompts and `response.model_dump()` | parent file append, unmediated | **publication**; in the design the host model mediator records these itself, so the worker needs no file access |
| P2 | `bridge` writing `kind: computation` events (`integration.py:193-205`) | state_and_publication (audit) | payload JSON | parent file append | moves into the host compute mediator |
| P3 | final `output.json`: `{table, plot, plot_native, routing, state}` with `portable_plot` (`backend.py:122-135, 165`; `workflow_contract.py:125-176`) | state_and_publication (final delivery) | one JSON document (observed sizes 5-75 KB in `campaigns/remediation-v2/raw/pandas-v18/*/output.json`) | parent writes the file | **publication** with label/clearance check (`object_manager.py:237-241` exists for in-process `OutputRequest`, nothing for a confined worker) |
| P4 | checkpointer | none | `checkpointer=None` by default (`pandas_data_analyst.py:62, 276`); eval never sets one | n/a | explicitly unsupported in v1 of this route (refuse if configured) |
| P5 | `fault_variant` controlled effects (`integration.py:28-57`) | compute (code rewrite before compute) | AST-injected effect in the code artifact | parent-side rewrite | moves to the host compute mediator so the recorded code artifact is still the one executed |

Summary: of the 22 rows, the only effect the C route mediates today is
`compute` (W3, V4). Six model calls per worst-case run (O2, W2, W5 x3, V2, V3,
V6 x3 -> at most 1 + 4 + 5 = 10 calls with `graph_retries=3`), one dataset
read, two audit streams and one final delivery are absent.

## 2. Proposed architecture

### 2.1 Host choice: `DockerObjectDispatcher` runs the graph unit

The graph unit is one confined worker that imports the vendor packages and
runs `PandasDataAnalyst.invoke_agent` unchanged
(`pandas_data_analyst.py:113-122`). Candidate hosts:

| Host | Has today | Missing for a graph unit |
|---|---|---|
| `DockerObjectDispatcher` (`container.py:71-598`) | exact `sha256:` image identity (`:94`, `:160-166`), pinned worker shim and tool bytes (`:133-146`), `--network=none --read-only --cap-drop=ALL --pids-limit=32 --memory=1g` (`:224-232`), `ContainerIdentity` digesting principal/policy/grant/runtime/plan (`:337-365`, `_container_lifecycle.py:25-50`), guardian cleanup, activation receipt per call (`:425-480`) | **no broker channel at all** (`docker exec -i` stdin/stdout only, `:390-401`); only `fs read` KERNEL lines (`:305-313`); 30 s default wall (`:91`), `cpu_ms 30000`, `address_space 512 MiB` (`:382-387`); no Lean lifecycle checker; `supports()` only fs read (`:203-215`) |
| `LinuxSandboxExecutor` (bwrap, `linux.py:199`) | the exact C compute route, `namespace:no-network` (`:1531-1540`, `:1676`), Lean v2 lifecycle checker (`:227`), optional OSTree `RuntimeDeployment` binding of runtime roots (`:224-226`, `deployment.py:257-275`) | **no `credential_broker`** in its constructor (`:210-228`); SERVICE grants rejected by design (`:202-206`); `pids` must be 1 (`:303-310`, `:1920-1921`); file is under concurrent edit by Codex |
| `ObjectBrokerDispatcher` + `LandlockSandboxExecutor` (`object_broker.py:387-543`, `landlock.py`) | socketpair broker opened before confinement (`landlock.py:352-362`), `SLANGGRAPH_BROKER_FD` plumbing (`:384-385`, `:403-404`), SERVICE lowering with bypass/channel/custody obligations (`object_broker.py:269-321`), typed `ResourceContract` mediators (`mediators/contracts.py:207`) | no network namespace (network denial is only the seccomp allowlist lacking `socket`/`connect`, `_linux_worker.py:24-110`); no Lean checker; no image identity; `pids == 1` |

Decision: **`DockerObjectDispatcher` hosts the graph unit**, because (a) the
gate's native-deployment descriptor wants an image/tool-bytes/manifest identity
and the Docker route already digests exactly that (`container.py:337-365`)
whereas today's bwrap route passes unpinned `runtime_roots`
(`integration.py:131`); (b) the vendor tree (`ai_data_science_team`, `pandas`,
`plotly`, `langgraph`, `langchain_core`) becomes image content, so its bytes are
bound by the image ID rather than by host directories other users could alias;
(c) its 1 GiB / 32-pid envelope is the only existing one in which a whole graph
plus Plotly fits without changing the `pids == 1` compute profile; (d)
`container.py` is not under concurrent edit. **`compute` is not re-hosted**: the
host-side compute mediator invokes the *existing* C `LinuxSandboxExecutor`
route with its v2 receipt lifecycle, so generated code keeps today's network
namespace, Lean `GO`/success gates and `worker-route-grant-v3` selector
(`integration.py:11-25`, `docs/security/lean-receipt-composition-plan.md:8-16`).

Fallback if the Docker broker transport (2.2) proves too invasive: port
`credential_broker` into `LinuxSandboxExecutor` after Codex's edits land
(mechanically `landlock.py:352-404` plus `_baseline_rules`/support at
`landlock.py:751`, `:819-822`), accept `pids == 1`, and bind runtime roots with
`RuntimeDeployment`. Everything in 2.3-2.5 is host-independent.

### 2.2 Authenticated broker channel: reuse `broker.py` / `object_broker.py`; what is missing

Reused unchanged:

- Frame protocol and limits: newline-delimited JSON, 1 MiB frames
  (`broker.py:18`, `:199-236`), identity fields rejected from the worker
  (`:21-22`, `:248-249`), `{"service","operation","payload"}` only
  (`object_broker.py:101-123`).
- `_ObjectBroker._handle_frame`: resolves one active SERVICE rule plus one
  object grant line per (service, operation), invokes the bound mediator, and
  records a token-free `BrokerAuditRecord` (`object_broker.py:124-157`).
- `SpawnRecord` binding of principal/tool/grant digest/nonce (`broker.py:24-35`,
  `open_session` checks at `:172-179`).
- Worker side: `broker_request` / `object_request` /
  `ResourceContract.client(export=...)` (`broker.py:329-384`,
  `object_broker.py:73-80`, `mediators/contracts.py:457`). They only `dup`,
  `write`, `read`, `close` the inherited fd, all in the allowlist
  (`_linux_worker.py:24-110`).
- Mediator typing and lowering: `ResourceContract` with an `ABC` interface,
  `MethodContract` argument/result checks, SLP class declaration and
  `permission()` selectors (`mediators/contracts.py:127-160`, `:439-455`);
  the `sqlite_record_mediator` is the reference for a bounded parent-side
  handler (`mediators/sqlite.py:37-70`).

Missing (new code, all in new files unless noted):

1. **Transport into the container.** `CredentialBroker.open_session` creates an
   `AF_UNIX` socketpair in the parent (`broker.py:180-182`); a `docker exec`
   worker cannot inherit it. Design: the dispatcher binds a listening `AF_UNIX`
   socket at a fresh private path under the dispatcher's temp directory
   (`container.py:131`), bind-mounts that single socket file read-only into
   the container alongside `tool.py`/`worker.py` (`:325-333`), and the pinned
   shim connects to it **before** `_apply_seccomp` (`_linux_worker.py:132`)
   and before the `ready` frame, then treats the connected fd exactly as
   `broker_fd` (`:119-129`); the shim learns the descriptor from the
   `SLANGGRAPH_BROKER_FD` environment variable (`landlock.py:403-404`,
   `broker.py:336`), which the Docker transport must also set. The parent
   `accept()`s exactly one connection per
   call, requires the first frame to echo the call's `startup_challenge`
   (`container.py:378`, `_linux_worker.py:138`), and only then starts
   `_serve` with the call's `SpawnRecord`. This is the only shim change; it is
   additive and gated on a `broker_socket` request field. Alternative without
   a shim change: none (stdio is the protocol pipe).
2. **SERVICE lines in the Docker grant check.** `container.py:305-313` refuses
   any line that is not `fs read` KERNEL. The graph-unit dispatcher must accept
   `EnforcementKind.BROKER` lines for the four classes below and lower them via
   `negotiate_object_grant` with the bypass/channel/custody obligations exactly
   as `_ObjectWorker._prepare_grant` does (`object_broker.py:232-339`), so the
   receipt lists them as `RuleEnforcement(..., "docker-broker-socket")`.
   Implement as a new `GraphUnitDispatcher` in a new module rather than
   widening `DockerObjectDispatcher.enforcer_id = "docker-readonly-v1"`
   (`container.py:85`); the read-only dispatcher's contract stays as documented
   (`docs/security/docker-dispatcher.md:45-47`).
3. **Per-call limits for the graph unit.** `container.py:382-387` hard-codes
   `cpu_ms 30000` / `address_space 512 MiB`; the new dispatcher takes explicit
   `limits` and `wall_timeout_s` (section 4) and binds them into `_plan`
   (`:330-346`; line numbers drift about 8 after 320) so they are part of `native_plan_digest`.
4. **Pinned vendor runtime.** The image must carry the frozen upstream checkout
   (`eval/apps/pandas/README.md`, SHA `4ffeb7f3...`) plus `workflow_contract.py`
   and `sandbox_codec.py` at digests recorded in the manifest
   (`manifest-v19.json:27-34` already records these digests). The image ID is
   the single runtime identity; the manifest records it.
5. **stdout capture.** The shim uses `sys.stdout` as the protocol pipe
   (`_linux_worker.py:114`) and already redirects tool stdout/stderr into
   discarded `StringIO` buffers during `_invoke` (`_linux_worker.py:310-311`),
   so vendor `print(...)` (`pandas_data_analyst.py:339-341`, `:374`, `:398`,
   `:448`) cannot corrupt the protocol pipe today. That capture is unbounded
   and dropped; the graph-unit artifact needs a *bounded* capture only if it
   is to return the text as inert data (corrected after fact-check).

### 2.3 The four host operations

All are `ResourceContract`s (`mediators/contracts.py:207`), one class each,
registered on the graph-unit dispatcher via `resources=`. Payloads are JSON
objects of strings/numbers/lists only; the mediator re-validates types and
sizes before touching any host object. No DataFrame, Period, NumPy scalar,
pickle, provider object, callback, config or `Runtime` ever crosses. Each
response carries `op_id` (parent-chosen, unique per call) so audit rows and
timing scopes bind to one request.

**`model_invoke`** (class `pandas_model`, operations `invoke`)

- Request: `{"messages": [{"role": "system"|"user"|"assistant", "content": str}, ...], "invocation_id": str}`.
  Total serialized size <= 256 KiB; <= 32 messages; roles closed set. No
  model name, URL, key, temperature, seed, tools, headers, callbacks,
  `response_format` or SDK options are accepted from the worker; any extra key
  refuses (`object_broker.py:110-113` pattern).
- Policy: the mediator builds a `ModelInvocationRequest(model=<manifest
  name>, context=(LabeledValue per message), invocation_id)`
  (`objects.py:112-124`) and routes it through `HostRouter.model_invoke`
  (`host_router.py:158-163`, `route` at `:130-135`) so the existing
  `object_permission` policy/approval path decides; `ESCALATE` becomes a
  `broker:approval_required` denial to the worker. Only after `ALLOW` does the
  mediator call the **one** preconfigured `ChatOpenAI` built from the manifest
  (`backend.py:68-78`, `manifest-v19.json:4-13`) with exactly the authorized
  narrowed context. This is the terminal that report.json:332-340 says is
  absent: the provider call happens in the mediator, after and only with the
  authorized context.
- Response: `{"content": str, "finish": str|null, "usage": {"prompt_tokens": int, "completion_tokens": int}|null}`,
  <= 256 KiB. The worker's `JsonOutputParser`/`PythonOutputParser` run on
  `content` locally.
- Side effects owned by the mediator: `model_start`/`model_end`/`model_error`
  rows in `events.jsonl` with the same shape as `backend.py:39-61`, plus
  `monotonic` stamps for the model timing scope.
- Per-call cap: `max_model_calls` (default 10, see section 1) per graph-unit
  invocation; the 11th refuses. Provider timeout = manifest
  `timeout_seconds`; `max_retries` = manifest (0 in v19).
- Worker side: a `BrokeredChatModel(BaseChatModel)` whose `_generate` calls
  `client.invoke(...)`. It is constructed by the graph-unit artifact, not by
  upstream (upstream receives `model=`, `pandas_data_analyst.py:272-276`), so
  the upstream algorithm is unchanged. Its `_agenerate` raises: async is not
  admitted (section 4).

**`compute`** (class `pandas_compute`, operation `run`)

- Request: exactly today's bridge payload after `json.loads(json.dumps(...))`
  normalization (`integration.py:182-192`): `{"code", "function_name",
  "data", "memory_limit_mb", "data_format", "sandbox_serialization",
  "computation_api"}`; `timeout` is not a field (fixed 15 s at the mediator,
  `integration.py:215-216` check retained). <= 1 MiB frame.
- Policy and execution: the mediator applies `fault_variant` for controlled
  cases (`integration.py:28-57`, `:181`), writes the `computation` audit row
  (`:193-205`), then invokes the **existing** compute ToolNode graph with the
  principal config (`:164-170`, `:219-235`) backed by the existing
  `LinuxSandboxExecutor` (`:121-134`) and selected Lean checker (`:11-25`).
  Code artifact bytes, codec version and limits are bound into that call's
  grant/receipt as today; the mediator additionally records
  `{op_id, sha256(code), sandbox_serialization, computation_api, receipt
  grant_digest}` so the graph-unit receipt and the compute receipt are linked.
- Response: `{"result": <JSON>, "error": str|null}` exactly as
  `integration.py:244-247` returns to the bridge today.
- Per-call cap: `max_compute_calls` (default 8). Re-entrancy: the compute
  mediator runs on the broker service thread (`broker.py:185-191`) while the
  outer dispatcher holds `_lock` (`container.py:294`); the compute
  `LinuxSandboxExecutor` is a separate object with its own lock, so no
  deadlock, but this must be a test (section 5, step 6).

**`dataset_input`** (class `pandas_dataset`, operation `read_csv`)

- Request: `{"dataset": "sales"}` (closed enumeration from the manifest, never
  a path).
- Policy: the mediator maps the name to the pinned fixture path recorded in the
  request (`backend.py:79`, `application_campaign.py:365`), checks the file is
  a single-link regular file under an operator-owned private root (same rule
  as `container.py:108-124`, `docs/security/docker-dispatcher.md:12-14`),
  and records `{op_id, sha256(bytes), size}`.
- Response: `{"csv": str}` (UTF-8 text) <= 512 KiB. The worker does
  `pd.read_csv(io.StringIO(csv))`, so the DataFrame is constructed inside the
  worker (report.json:410-412).

**`state_and_publication`** (class `pandas_publish`, operations `audit`, `deliver`)

- `audit`: `{"kind": str (closed set: "stage", "warning", "stdout"), "text": str <= 16 KiB}`;
  appended to `events.jsonl` with `op_id`. Used for captured vendor stdout
  (2.2 item 5) and stage markers; nothing else.
- `deliver`: `{"output": {"table": [...]|null, "plot": <json>|null, "plot_native": <json>|null, "plot_normalization_error": str|null, "routing": str|null, "state": <json>}}`
  produced in the worker exactly as `backend.py:122-135` (including
  `portable_plot`, `workflow_contract.py:125-176`, applied in the worker since
  it is pure) and serialized with `default=str` as `backend.py:165`. Size
  <= 1 MiB (observed 5-75 KB). The mediator wraps it in
  `OutputRequest(destination="pandas:output.json", content, labels, clearance,
  output_id=op_id)` (`objects.py:127-140`), routes it via
  `HostRouter.output_emit` (`host_router.py:170-175`) so the existing
  `validate_output_request` and clearance check run
  (`object_manager.py:237-241`), and only on `ALLOW` writes
  `request["output"]`. Exactly one `deliver` per invocation; a second refuses.
  The graph-unit tool's own return value is only `{"delivered": bool,
  "stdout_bytes": int}`; the oracle reads `output.json` as today
  (`application_campaign.py:407-413`).
- Checkpoint/persistent state: not offered in v1. The upstream default is
  `checkpointer=None`; if a run requests one, the graph-unit artifact refuses
  before building the graph.

### 2.4 Where policy is applied

| Decision | Where | Evidence |
|---|---|---|
| May this principal run the graph unit at all, with these four classes? | `ObjectPolicyHostExecutor` authorization before dispatch, as for any dispatcher (`docs/security/docker-dispatcher.md:4-6`); SLP manifest `tool pandas_graph { ... }` declaring the four classes with `permission()` selectors (`mediators/contracts.py:439-455`) | lowering record + activation receipt |
| Each broker op is granted | `_ObjectBroker._handle_frame` requires one active SERVICE rule and one grant line (`object_broker.py:131-147`) | `BrokerAuditRecord` |
| Model context / approval | `HostRouter.model_invoke` -> `policy.object_permission` (`host_router.py:130-135`) inside the model mediator | audit sink row; ESCALATE -> denial |
| Output labels / clearance | `HostRouter.output_emit` -> `validate_output_request` + clearance (`object_manager.py:237-241`) inside the publish mediator | audit sink row |
| Dataset pin | mediator path check against operator root | audit row with digest |
| Compute | unchanged existing path (`integration.py:139-170`), DAC `@dac(owner="analyst", ...)` and `@effects(EXEC, READ)` (`:145-149`) | existing activation receipts + Lean v2 gates |

### 2.5 What the outer coordinator keeps

The coordinator graph that the gate admits becomes trivially shaped: `START ->
pandas_graph (ToolNode over the GraphUnitDispatcher) -> END`, compiled with
`SecurityConfig(closed_admission=True, host_executor=<graph-unit dispatcher>,
audit_sink=...)`. It keeps: principal construction (`integration.py:168-170`),
the request record (`application_campaign.py:361-374`), the audit sink, the
manifest selection, timing scopes (policy / model / compute / publication
recorded by the mediators, not by the worker), receipt export
(`integration.py:237-243` extended to both dispatchers), and the unchanged
oracle call (`application_campaign.py:412-413`). It no longer holds a model
client, a DataFrame, or any vendor closure.

## 3. Admission

The single coordinator node is a `ToolNode` whose tool is the graph-unit
descriptor; nothing else is in the graph, so the gate's "exact framework
dispatch primitive with no arbitrary callback payload" clause applies to the
node and the "validated native node/graph deployment handled by a concrete
confined host" clause applies to the tool (report.json:367). The descriptor the
gate should capture at compile time and recheck at invocation
(report.json:368):

```
GraphUnitDescriptor(
  dispatcher_type = GraphUnitDispatcher (exact type, not isinstance),
  image           = "sha256:<64 hex>"                     # container.py:94, :160-166
  tool_artifact   = sha256(eval/apps/pandas/graph_worker.py)  # LinuxToolSpec.artifact_digest, linux.py:113-127
  worker_shim     = sha256(_linux_worker.py)              # container.py:133-136
  guardian        = DockerGuardian.code_digest             # container.py:356
  manifest        = sha256(manifest-v20.json)  (records image, integration_sources, limits, model settings)
  classes         = {pandas_model, pandas_compute, pandas_dataset, pandas_publish} with their lowering ids
  limits          = {wall_s, cpu_ms, address_space_bytes, max_model_calls, max_compute_calls}
)
```

`native_plan_digest` already covers image, mounts, worker, guardian, artifact,
seccomp, pids and memory (`container.py:330-346`); the descriptor adds the
manifest digest, class set and the explicit caps, and the dispatcher refuses a
call whose captured descriptor does not equal its live plan
(`container.py:222-223` pattern). The coordinator tool callback is a schema
only; its body never runs (`docs/security/docker-dispatcher.md:5-6`).

Explicitly **not admitted** (confined, not trusted): everything inside the
image: `ai_data_science_team`, `langgraph`/`langchain_core` as imported inside
the worker, `pandas`, `plotly`, `graph_worker.py`, the `BrokeredChatModel`,
`RequestPreservingStage`, and all generated code. They receive bounded data
and a broker fd; they never receive `bound_config`, `Runtime`, the router,
callbacks, provider objects or credentials (report.json:376). A worker that
misbehaves can only (a) send malformed or over-cap broker frames, which refuse,
(b) burn its own CPU/memory/wall budget, which terminates the container, or
(c) emit a wrong `deliver`, which the oracle scores as a failed observation.
None of that is an admission claim about the vendor code, and the inner
LangGraph instance's own reducers, retry callbacks and `RunnableCallable`
injection (report.json:450-471) run entirely inside the confinement.

## 4. Limits and premises, stated honestly

- **Process/thread model.** The worker shim's seccomp allowlist has no
  `clone`, `clone3`, `fork`, `execve`, `socket` or `connect`
  (`_linux_worker.py:24-110`), so threads and subprocesses are impossible in
  the graph unit regardless of `--pids-limit=32`. The vendor graphs are linear
  (one task per super-step), and `PregelRunner.tick` runs a single task
  inline only when `len(tasks) == 1 and timeout is None and get_waiter is None`
  (`langgraph/pregel/_runner.py:201-203`); `stream_eager`, subgraph streaming,
  the `messages`/`custom` stream modes (`main.py:3071-3077`), `step_timeout`,
  two tasks in a step, `Send` or functional `Call` all go through
  `self.submit()` and the thread pool. `BackgroundExecutor` creates the
  executor object eagerly (`_executor.py:48-50`); only the OS thread spawn is
  lazy. **Premise, to be tested per workflow, not assumed:** no thread is ever
  started. If one is, seccomp returns `EPERM` (default action
  `SCMP_ACT_ERRNO(EPERM)`, `_linux_worker.py:253-256`; only bpf/
  process_vm_readv/ptrace/unshare are `SCMP_ACT_KILL`, `:111-116`), Python
  raises `RuntimeError: can't start new thread`, and the run is a recorded
  failure, never a widened profile (corrected after fact-check). The `langchain_core` `prompt | llm |
  parser` chains are synchronous.
- **Budgets.** Today's compute profile is `cpu 15s pids 1 wall 15s` and 512 MiB
  (`compute-v3.slp.template:6`, `integration.py:132`, `:215-216`) and stays
  exactly that for the compute mediator. The graph unit gets its own explicit
  profile in manifest-v20: `wall 1800 s` (upper bound derived from <= 10 model
  calls at observed qwen3:8b latency, not from the 600 s provider timeout
  whose worst case, 10 x 600 s, is intentionally not funded), `cpu 120 s`
  (the worker mostly blocks on broker reads), `address_space 1 GiB` (matches
  `--memory=1g`, `container.py:230`), `nofile 64`, `max_model_calls 10`,
  `max_compute_calls 8`, frames 1 MiB. A wall or cap expiry is a failed
  observation in the frozen denominator. These numbers are proposals until
  the probe in step 2 measures them.
- **Broker availability.** The broker service thread lives in the parent
  (`broker.py:185-191`); if it dies, worker requests get read-EOF and raise
  `PermissionError("broker:invalid_response")` (`broker.py:368-373`;
  `broker:channel_closed` fires only on a zero-length write, which in practice
  surfaces as `BrokenPipeError`), the vendor
  code sees an exception, and upstream's own fallbacks run
  (`pandas_data_analyst.py:379-384`). That fallback path is preserved
  behavior, not a security event, and the mediator's audit row records the
  closed channel.
- **No-network with the model call proxied.** Enforcement is layered:
  `--network=none` (`container.py:225`) plus no `socket`/`connect` after the
  shim's pre-seccomp connect. The pre-seccomp connect is a new trusted
  window inside the pinned shim and must be reviewed as such; the
  acceptance test in step 7 asserts a worker `socket()` after `ready` fails
  with `EPERM` (the worker survives; see the seccomp default above). "Merely proxying a model method while leaving alternate socket
  paths" (report.json:445) does not arise because there is no socket
  syscall, but a review of `libseccomp` argument filtering for the connect
  window is required.
- **Lean lifecycle.** The v2 checker only gates the compute worker's
  activation/success (`lean-receipt-composition-plan.md:8-16`, `:56-61`). The
  graph unit has no Lean coverage in this design; its receipt is the Docker
  HMAC evidence (`container.py:447-455`). Nothing here advances SGV901-903
  (`docker-dispatcher.md:55-56`, `lean-receipt-composition-plan.md:129-136`).
- **Image trust.** The Docker daemon, image and private roots are trusted
  (`container.py:1-8`). Vendor package bytes are bound by image ID, not
  reviewed; "image must not contain secrets" applies.
- **Async.** Not admitted: `BrokeredChatModel._agenerate` raises, and the
  dispatcher refuses `asynchronous=True` until it has its own lifecycle
  (report.json:394). The SQL app's `ainvoke_agent` is out of scope.
- **Not covered by this design:** imports and builder-time effects inside the
  worker, stream callbacks, module mutation inside the worker, the decoder and
  OS correspondence (report.json:396) are inside the confinement and are not
  proved; the coordinator's own admission is the other half of the work.

## 5. Work plan

Ownership: `S` = security library (new files only; nothing in `admission.py`,
`config.py`, `placement.py`, `mac.py`, `linux.py`, `enforcement.py`, proofs),
`E` = `eval/`, `I` = image build. Acceptance checks `AC1`..`AC5` are
report.json:473-477 in order.

| Step | Files | Acceptance test | Est. |
|---|---|---|---|
| 1. Image recipe: frozen upstream checkout + `workflow_contract.py` + `sandbox_codec.py` + `graph_worker.py` + pandas/plotly/langgraph at the recorded overlay; record image ID and all digests in `eval/apps/pandas/policy/manifest-v20.json` | I, E (`eval/apps/pandas/Dockerfile`, `manifest-v20.json`) | `docker image inspect` ID equals manifest; digests of `integration_sources` match (`manifest-v19.json:27-34` pattern) | 3 h |
| 2. Single-thread/stdout probe: run `PandasDataAnalyst` in a plain `docker exec` with the shim's seccomp and a fake brokered model; assert no `clone3`, measure RSS/wall | E (`eval/apps/pandas/probe_graph_unit.py`) | worker exits 0; `events` show 0 thread starts; measured numbers become manifest limits | 3 h |
| 3. `GraphUnitDispatcher`: copy of the Docker lifecycle path with explicit limits, SERVICE-line lowering via `negotiate_object_grant`, socket bind-mount, accept+challenge, `_ObjectBroker` session per call, receipt with broker `RuleEnforcement` | S (`security/graph_unit.py`, additive `broker_socket` branch in `_linux_worker.py`) | unit tests: refuse unknown line classes; refuse second connection; refuse frame before challenge; receipt lists four broker lines; cleanup on wall expiry (AC5: unsupported paths refused) | 10 h |
| 4. Four mediators as `ResourceContract`s with bounded schemas, caps, audit rows, timing scopes | S (`security/mediators/pandas_graph.py`) | unit tests per op: extra keys refuse; size caps refuse; `max_model_calls+1` refuses; model `ESCALATE` -> denial and zero provider calls (AC3 first half); `deliver` twice refuses; clearance mismatch refuses | 8 h |
| 5. Worker artifact `graph_worker.py`: stdout swap, `BrokeredChatModel`, dataset client, builds agents exactly as `backend.py:87-121` with `RequestPreservingStage`, calls `deliver` | E (`eval/apps/pandas/graph_worker.py`) | run one task end-to-end against the local model; `output.json` equals the A-route shape; oracle passes for `monthly_total` (AC2 pilot) | 5 h |
| 6. Compute mediator wiring into the existing C route; re-entrancy test; receipts for both dispatchers exported | E (`integration.py` new configuration `D`), S (mediator from step 4) | compute receipts still Lean-gated (`lifecycle-selection.json` written, `integration.py:135-138`); broker thread invoking `node_graph.invoke` under the outer lock does not deadlock; fault variants still produce `attempt.csv`/`denial.csv` (`integration.py:40-46`) | 4 h |
| 7. Native refusal tests: worker attempts `socket()`, `open("/etc/hostname","w")`, `os.fork()`, read of a non-granted private file after `ready`; model denied -> assert zero `model_start` rows and no connection on the provider port | S/E tests | AC3 both halves | 4 h |
| 8. Post-admission mutation tests: replace tool callable after compile, foreign input containers in `deliver`, candidate-supplied `principal`/`service` keys in frames (`broker.py:248-249`), rebinding `BrokeredChatModel._generate` inside the worker (must have no host effect) | S/E tests | AC4; AC1 is owned by the gate half and must remain green with the new dispatcher registered | 4 h |
| 9. Coordinator graph under `closed_admission=True`: `START -> pandas_graph -> END`; sync only; nested/async/branch/retry/cache/reducer paths explicitly refused at the coordinator and listed in coverage | E (`integration.py`), S (descriptor registration hook agreed with the gate owners, in their files, not mine) | AC5 separately per path | 3 h |
| 10. Full cohort: ten frozen tasks x 5 repetitions for configuration D with new adapter/cohort identity; A/B/C rows untouched; failed observations kept | E (`eval/remaining/application_campaign.py` manifest selection; `--configurations D`) | AC2: 50/50 denominator present, oracle call unchanged (`application_campaign.py:156`, `:412-413`); timing scopes separate per report.json:446 | 4 h + wall time |
| 11. Docs: `docs/security/graph-unit.md`, status/coverage updates, keep SGV flags false | docs | `eval/tests/test_completeness.py`-style consistency checks pass | 2 h |

Total: about **50 agent-hours** of implementation and test writing, plus model
wall time for the cohort. Steps 1-2 are the gating unknowns; if step 2 shows
thread creation that cannot be avoided, the design falls back to the bwrap
port with the same mediators (section 2.1 fallback) and step 3 changes
substantially.

## 6. Risks

Hardest compatibility constraints (report.json:440-447):

- **Period/NumPy/date serialization.** The inner compute result still passes
  through `recursive-json-v2` (`sandbox_codec.py:10-49`) unchanged, and the
  compute payload is normalized with `json.loads(json.dumps(...))` as today
  (`integration.py:192`), so W3/V4 are unchanged. The new boundary is the
  worker-to-parent `deliver`: `pd.DataFrame(table).to_dict(orient="records")`
  and `json.dumps(..., default=str)` (`backend.py:125`, `:165`) now run inside
  the worker, and `state` may contain `Period`, `Timestamp`, `np.int64`,
  `NaN` values and integer index keys. Using `default=str` in the worker
  reproduces today's bytes only if the worker's pandas/NumPy versions equal
  the parent's recorded overlay; pin them in the image and diff `output.json`
  between A and D on the same model transcript in step 5.
- **`plot_native` and portable Plotly.** `portable_plot` decodes native-endian
  `bdata` typed arrays with the comment "serializes and decodes on the same
  host" (`workflow_contract.py:128-131`); moving the decode into the worker
  keeps serializer and decoder in the same process, which is the safer side
  of that assumption, but `plot_native` is then produced by the image's Plotly,
  whose typed-array tags must be the eight supported ones (`:134-143`) or the
  run records `plot_normalization_error` (`backend.py:134-135`), never a
  dropped failure.
- **Retries and fallback.** The upstream fix loops (W5, V6) and
  `preprocess_routing`'s bare `except` (`pandas_data_analyst.py:379-384`)
  turn broker denials into silent fallbacks (table route, fallback chart,
  `_build_fallback_chart` at `data_visualization_agent.py:1280-1286`). That is
  faithful upstream behavior, but it means a mis-configured policy can look
  like a legitimate "table" answer. Mitigation: the model mediator's audit
  rows are the source of truth; the campaign must count denials separately
  from oracle misses.
- **Frame size.** 1 MiB frames (`broker.py:18`) bound `data` in the compute
  payload (the whole DataFrame as JSON), the model prompt (the summary text
  is capped by `MAX_SUMMARY_CHARS` upstream) and `deliver`. Fine for the
  frozen fixture; any larger dataset needs a versioned manifest, not a bigger
  constant.
- **Pre-seccomp connect window.** The only shim change is a trusted-code
  change; it must be reviewed and covered by the refusal tests, and the
  guardian/controller-death cleanup semantics (`docker-dispatcher.md:36-43`)
  must be re-run with the socket mounted.

What would silently widen the compute profile (and must be refused):

- Letting the graph unit call the compute `LinuxSandboxExecutor` with
  worker-supplied `timeout`/`memory_limit_mb`: the mediator fixes 15 s/512 MiB
  and keeps the `ValueError` at `integration.py:215-216`.
- Running generated code inside the graph unit (it has pandas and 1 GiB) when
  the broker is unavailable: `graph_worker.py` must install the brokered
  `run_code_sandboxed_subprocess` alias (`integration.py:249-251`) with no
  fallback, mirroring `integration.py:152-153`.
- Reusing the same container across principals or policies: `ContainerIdentity`
  already destroys on change (`container.py:337-365`); the descriptor's
  `manifest` digest must be part of `_plan` so a manifest change also
  destroys it.
- Raising `--pids-limit`/seccomp to allow `clone3` "just for the thread pool":
  that changes the native plan for every worker in the image; if threads are
  unavoidable, the answer is the bwrap fallback with `pids == 1` enforced and
  a single-threaded Pregel executor, not a wider allowlist.
- Granting `fs read` on the fixture directory to the graph unit instead of
  the `dataset_input` op: it would reintroduce unmediated parent-path reads
  and make `extra-read` fault cases (`integration.py:34-38`) indistinguishable
  from legitimate reads.
