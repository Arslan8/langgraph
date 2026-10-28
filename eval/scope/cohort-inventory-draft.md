# Cohort inventory: Steps 1–3 (DRAFT)

**Draft for advisor and student review, generated from repository records on
2026-10-27.** It is not an authoritative record. Every classification below is
*proposed*. Where a record is silent, this draft says "not recorded". No
application, test, container, model or network call was run to produce it. The
only file written was this one.

## Conventions

Path prefixes used throughout:

- `RV2/` = `eval/campaigns/remediation-v2/`
- `RV1/` = `eval/campaigns/remediation-v1/`
- `RM1/` = `eval/campaigns/remaining-v1/`
- `APPS/` = `eval/apps/`
- `SEC/` = `libs/prebuilt/langgraph/prebuilt/security/`

**Upstream references.** References such as `data_wrangling_agent.py:883` are
line numbers recorded in that app's `APPS/<app>/intake.json` under
`source_evidence[].matches`, at the pinned SHA. The upstream checkouts under
`/data/slanggraph-eval-upstreams` are outside this repository and were not
re-read. Every intake labels its inventory "source inspection; not a runtime
trace" (`effect_inventory_kind`).

**Working tree.** The slangGraph checkout is branch `wip` at HEAD
`40e24e978f9ec2e8f061abb21077e2251583f5e5` with extensive uncommitted changes
(`eval/status.md:24-28`). Some cited docs, for example
`docs/security/status.md`, are modified in that tree. Pilot results record
`slanggraph_sha` 40e24e97 with `slanggraph_dirty: true` (for example
`eval/results/notebook-A-smoke-r1-9c2d3add86b94f3cb17a94e7e1af1531/result.json`).
Later cohorts executed their own source snapshots: RM1 used base 40e24e97 plus
overlays (`RM1/README.md:41`), and RV2 v19 recorded `framework_sources_sha256`
`425672232af6c83b8082b122a0d94310c0f591355b2710b414b0ed6d0df7a845`
(`RV2/raw/pandas-v19-full/trials.jsonl`).

**Execution route vocabulary** (the advisor's terms):

- *language sandbox*: admitted, restricted tool logic that executes in-process. "In-process" describes location only.
- *isolated worker*: a Landlock/Linux worker or a container.
- *mediated broker/adapter*.
- *trusted runtime*.
- *none yet*: no protected route exists in code and no protected execution is recorded.

**Configuration labels.** A = unprotected upstream baseline. B and C = protected
configurations; their meaning is recorded per app in its manifest.

---

## Step 1: Freeze the cohort

### 1a. Classification table

| App | repo@SHA | Attempted tasks/cohorts (paths, pass counts) | Evidence type | Proposed class | Reason | Blocking items |
|---|---|---|---|---|---|---|
| pandas | `business-science/ai-data-science-team@4ffeb7f38178aa250917f29b01355f8b89ba809e` (`apps/pandas-data-analyst-app`) | Ledger P1–P10 (1b). Latest: v19-full A/B/C 50/50 each (`RV2/raw/pandas-v19-full/verification.json`). Earlier denominators kept: RM1 A 29/50, B 27/50, C 29/50; RV1 v10 A 6/10, B 3/10, C 5/10; RV2 v11–v18; v7 pilot clean utility 1/3 per configuration; 95 early pilot attempts, including 30 infrastructure failures, 4 provider failures and 1 timeout (`eval/intake/pilot-summary.json`) | A is the baseline. B (added node dispatch) and C (Linux worker) are protected. Real local model (qwen3:8b), real upstream graphs and a synthetic CSV fixture. Fault variants are synthetic inserted effects. The CSV injection used the real model but had 0 eligible attempts. No service doubles | **supported (proposed)**, limited to the backend generated-computation route in C | A production enforcement path exists (`SEC/linux.py:188` `LinuxSandboxExecutor`, `@minimal`, profile `APPS/pandas/policy/compute-v3.slp.template`) and is wired at `APPS/pandas/integration.py:104-142`. Useful protected runs are recorded (C 50/50 in v19, 29/50 in RM1). C stopped 3/3 supported forbidden probes that A and B completed (`eval/reports/paper-macrobenchmarks.md:141-168`) | (1) Model calls, input loading and outer-graph publication run ungated in the trusted runtime (`APPS/pandas/policy/narrow-v3.json` `boundary`). (2) Private `/tmp` writes succeed: output-only guest writes are unsupported and not gated (`APPS/pandas/policy/mapping.csv` row 6). (3) Network and spawn are untested in the app (mapping.csv rows 7–8). (4) v19 utility depends on the v11–v19 adaptations (`APPS/pandas/policy/manifest-v19.json` `amendment`). (5) SGV901–903 remain open (`RV2/acceptance.json` item 2). (6) The Streamlit UI is excluded |
| sql | same repo@SHA (`apps/sql-database-agent-app`) | Ledger S1–S5. Pilot A 6/8 (v1 0/2, v2 3/3, v4 3/3). RM1 sql-full A/B/C 50/50 each; canary in model input A 26/50, B 27/50, C 0/50 (`RM1/raw/sql-full/trials.jsonl`). 200 deterministic C probes (`RM1/raw/sql-adversarial-v2/trials.jsonl`). Failed pilots kept | A is the baseline. B is call authorization only, with upstream effects unchanged. C is a bounded mediator behind the production broker. Real local model, real upstream graph and a synthetic SQLite fixture. C *replaces* generated-Python execution (`RM1/RESULTS.md:38`) | **requiring an adapter (proposed)** | The app's own effects (SQLAlchemy connection, metadata sampling, generated-Python `exec`) have no production enforcement path. The only C route uses evaluation-harness code, `eval/remaining/bounded_sql.py`, which covers one fixed `sales` table and a single-table SELECT grammar. The production `sqlite_record_mediator` handles a fixed `records(key,value)` table only (`SEC/mediators/sqlite.py:27-28`) | (1) Accept the bounded evaluation mediator, or promote a SQL mediator with conformance tests into `SEC/mediators/`. (2) Reconcile the records: `APPS/sql/README.md:39-44` still says B/C are unsupported, and `eval/APPLICATIONS.md:148-150` says only that `sqlite_record_mediator` "supports only a fixed `records(key,value)` schema" and that "a general SQL mediator would be new system work", without mentioning the RM1 sql-full cohort. (3) The SQLite trusted private-namespace assumption remains (`RV2/acceptance.json` item 9). (4) Outer-graph publication is ungated |
| email | `langchain-ai/executive-ai-assistant@758db7174223da7864feea7c9f8d1aba12923037` (`.`) | None. Install failed on yanked `langgraph-api` versions (`eval/intake/email-install.txt:10-22`). The smoke case is `not_frozen` (`APPS/email/cases.jsonl`). No result directories | None | **requiring an adapter (proposed)** | Effects are Gmail/Calendar SDK calls with OAuth credentials, a human approval node and hosted persistence (`APPS/email/intake.json` `effects`). Production has a generic credential-custody broker (`SEC/broker.py:154-155`) but no Gmail/Calendar handler. Service credentials are "Phase two" (`docs/security/status.md:90`) | A dependency patch. A dedicated Gmail OAuth test account and controlled recipients. The hosted-model reflection graph is excluded (`APPS/email/README.md`). Archived upstream (`intake.json` `archive.archived`). No baseline |
| research | `langchain-ai/open_deep_research@1b7d2e80db9faa586165c60e09096dbbfd483a64` (`.`) | None. Dependencies installed (`eval/intake/research-install.txt`). The smoke case is `not_frozen` | None | **requiring an adapter (proposed)** | Effects are search-provider and remote MCP calls, model calls and report synthesis (`APPS/research/intake.json` `effects`). Network endpoint scoping is "Phase two" (`docs/security/status.md:84`). The Linux worker isolates the network (`SEC/linux.py:1628`). MCP support is a stdio-only broker proxy (`SEC/mcp_proxy.py:1`) | A search service or a labeled contract-preserving corpus double. A local structured-output model. The benchmark needs LangSmith (`intake.json` `next_action`). Archived upstream |
| notebook | `lfnovo/open-notebook@a0f6f3081ae06328f0a451b3a3ef2959ca25721d` (`.`) | N1: A smoke 1/1 (`eval/results/notebook-A-smoke-r1-9c2d3add86b94f3cb17a94e7e1af1531/result.json`). N2: C 50/50 refused at preflight (`RM1/raw/notebook-disposition/trials.jsonl`) | Baseline only, against real services: a dedicated SurrealDB container, the original API and worker, and local llama3 at temperature 1.0 with no seed. The C rows are refusals, not executions | **requiring an adapter (proposed)** | Five paths lack production integration: source lookup, backing-store read, checkpoint restore/history, model input and publication (`RM1/raw/notebook-disposition/plan.json` `coverage`). `SEC/mediators/` has no SurrealDB mediator. `RV2/acceptance.json` item 5 keeps C unsupported | The server boundary: API and worker processes are outside the client trace (`APPS/notebook/policy/manifest-v3.json` `scope`). Reset/oracle calibration (`APPS/notebook/README.md:77-81`). A single unseeded run |
| coding | `langchain-ai/open-swe@ff4e713c094c0abb8c76b3193de464d9b4f1e570` (`.`) | None. Dependencies installed, but the MDA project is a separate environment (`APPS/coding/README.md`). The smoke case is `not_frozen` | None | **requiring a worker profile (proposed)** | Effects are workspace file and shell operations, PostgreSQL access and GitHub publication (`APPS/coding/intake.json` `effects`). Production `@minimal` forbids process creation (`SEC/landlock.py:527-530`, `SEC/linux.py:1716-1717,1723`). The exec-enabled profile is evaluation-only (`eval/src/slanggraph_eval/isolation/binary_worker.py:1,74-83`). The Docker dispatcher supports exact read-only file grants only (`docs/security/docker-dispatcher.md:12,45-46`) | A subprocess worker profile with process ceilings. GitHub and PostgreSQL adapters. A dedicated GitHub App/repository, PostgreSQL and MDA credentials. The remote MDA sandbox is outside local enforcement ("Local executor cannot confine a remote sandbox by itself", `APPS/coding/README.md`) |
| newspaper | `rotemweiss57/gpt-newspaper@1c447b5672dd5ca8cd91a18bfa6daefe257c4fbe` (`.`) | None. Dependencies installed. No edition attempted (`APPS/newspaper/README.md`) | None | **requiring an adapter (proposed)** | Effects are Tavily search, model calls, Send fan-out, publisher file writes and an optional illustration provider (`APPS/newspaper/intake.json` `effects`). Network endpoint scoping is "Phase two" (`docs/security/status.md:84`). No search broker exists in `SEC/` | Dedicated Tavily access or a labeled contract-preserving search double |
| finance | `virattt/ai-hedge-fund@6c41ae8cf5fb4e30eb8cdb6a816eb56ff234989d` (`.`, historical) | None. Historical dependencies installed (`eval/intake/finance-install.txt`). The smoke case is `not_frozen` | None | **requiring an adapter (proposed)** | Effects are HTTP GET/POST to a financial-data provider with an API key, a local cache, model calls and an optional PNG (`APPS/finance/intake.json` `effects`). No HTTP/service broker handler exists. Network scoping is "Phase two" | Frozen provider responses. Local model settings. The historical pin is unverified (`intake.json` `selection_reason`: "candidate historical pin, not a claim of last reproducible release") |

### 1b. Cohort ledger (all recorded attempts; failures kept)

**pandas**

| ID | Cohort and configuration | Path | Denominator and result | Evidence type |
|---|---|---|---|---|
| P1 | Early pilot, manifests v1–v6 (hashes matched against `APPS/pandas/policy/manifest-v*.json`) | `eval/results/pandas-*`, `eval/intake/pilot-summary.json` `groups` | v1 A: 1 timeout. v2 A: 4 (3 provider failures; 1 completed, which is the `apps.csv` `baseline_run`). v3 A: 1 provider failure. v4 A: 3 completed, 1/3 clean success. v5 C: 1 application error. v6 C: 1 application error | Baseline and protected; real model. Adapter-debug runs with incomplete source snapshots (`eval/APPLICATIONS.md:133-137`) |
| P2 | Frozen v7 plan (21 runs) plus v8 dataset-write diagnostic (3 runs) | `APPS/pandas/pilot-plan-v7.json`, `-v8.json`; `eval/reports/application-pilot.md:20-59` | Clean utility 1/3 per configuration (February 120 correct; region totals wrong; chart raises an upstream `re.PatternError`). Supported forbidden probes reached A 3/3, B 3/3, C 0/3 (ENOENT, ENOENT, EROFS). Broad read permitted in all three. The outside-fixture write was reclassified as unsupported (`eval/results/pandas-C-internal-write-r1-ad7fa09c5c3f46c4a8e2d43b03c76c77/oracle-correction.json`) | Baseline and protected; real model. Fault variants are synthetic, "not upstream vulnerability findings" (`application-pilot.md:70-71`) |
| P3 | v9 CSV-cell injection with paired clean task, A/B/C | `eval/results/pandas-{A,B,C}-csv-injection-*` and `-february-*`; `paper-macrobenchmarks.md:179-194` | Per configuration: 20 attempts, of which 10 are infrastructure failures kept (Ollama unavailable). Of the retries: forbidden effect 0/5, target-open attempts 0/5 (0 eligible), legitimate task 5/5 | Real model. The payload reached model input in 15/15 runs (`paper-macrobenchmarks.md:188`). No injection-resistance evidence |
| P4 | Deterministic dispatch checks | `eval/results/pandas-dispatch-20261026-v1/summary.json` | B 4/4, C 4/4; A not applicable (`paper-macrobenchmarks.md:170-177`) | Protected; no model |
| P5 | Runtime/audit timing and end-to-end repetitions | `eval/results/pandas-runtime-20261026-v1/`, `-runtime-audit-profile-20261026-v1/`, `-e2e-repetitions-20261026-{v1,attempt2}/` | Timing only; not a utility denominator | — |
| P6 | Computation replay (no model, graph or Cedar) | `eval/reports/alternatives-v2/report.md:146-152` | `pandas_february` plain/landlock/container replay | Mechanism replay, "not a model-driven full workflow" |
| P7 | RM1 pandas-full: 10 tasks × 5 reps × A/B/C, retries 0 | `RM1/raw/pandas-full/trials.jsonl` (`legitimate_result`) | A 29/50, B 27/50, C 29/50 (`RM1/FAILURES.md:8`). `raw/pandas-pilot` 3/3. Profiler attempts in `raw/workflow-profiles{,-v2,-v3}` failed (20 rows; `RM1/FAILURES.md:9`) | Baseline and protected; real model; clean tasks only |
| P8 | RV1 v10 utility | `RV1/utility-summary.json` | A 6/10, B 3/10, C 5/10. Also `raw/profile-pinned-v3` (1 C workflow) and `raw/serialization-final` (6 deterministic cases) | As P7 |
| P9 | RV2 development cohorts | `RV2/raw/pandas-v11` … `pandas-v18`; `RV2/v1{1,2,4,5}-summary.json` | v11 24/30 (8/8/8); `RV2/README.md:19` says 26/30, see Q8. v12 26/30 (9/9/8). v13-pilot 3/3. v14 20/30 (7/6/7). v15 21/30 (7/7/7). v16 has a manifest but no cohort directory. v17 25/30 (9/8/8). v18 30/30. `pandas-profiles-v18` C 10/10. `period-serialization` 6/6 | As P7. v11 has a source-capture limitation (`RV2/v11-source-capture-limitation.json`) |
| P10 | RV2 v19-full: 10 frozen tasks × 5 reps × A/B/C, 3 graph retries, `preserve-request-v5`, `recursive-json-v2`, `period-aggregation-v1` | `RV2/raw/pandas-v19-full/{trials.jsonl,verification.json}` | A 50/50, B 50/50, C 50/50. Verification `passed: true`. Every C trial has `activation-receipts.json` and `security.sqlite` | Protected utility; real model. Scope: "no security or performance completeness claim" (`verification.json`) |

**sql**

| ID | Cohort and configuration | Path | Denominator and result | Evidence type |
|---|---|---|---|---|
| S1 | Runner pilot, A only (manifests v1, v2, v4) | `eval/results/sql-A-*`; `eval/intake/pilot-summary.json` | v1 0/2 (application errors). v2 3/3 (includes the `apps.csv` `baseline_run`). v4 3/3. No B/C directories, because manifest v4 declares B/C unsupported (`APPS/sql/policy/manifest-v4.json` `configurations`) | Baseline; real model |
| S2 | Schema-sampling observation | `eval/intake/sql-observations.json` | 5/5 A runs placed the payroll canary in the model prompt during metadata sampling | Baseline observation, "not an attack or enforcement result" |
| S3 | RM1 sql-full: 10 tasks × 5 reps × A/B/C, retries 0 | `RM1/raw/sql-full/trials.jsonl`; `RM1/RESULTS.md:33-38` | Legitimate results: A 50/50, B 50/50, C 50/50. Canary in model input: A 26/50, B 27/50, C 0/50. Database changed in 0/150 | Baseline; B is call authorization only; C is a bounded broker mediator. Real model; synthetic fixture with a `bob` canary row (`eval/remaining/sql_campaign.py:105-113`) |
| S4 | Deterministic bounded-SQL probes, C only | `RM1/raw/sql-adversarial-v2/trials.jsonl` | 10 cases × 20. Allowed 20/20. Owner substitution narrowed to 0 rows (20/20). Join, subquery, UNION, ATTACH, PRAGMA, DDL, write and extension forms: 160/160 refused with an empty effect trace | Protected; no model |
| S5 | Failed pilots kept | `RM1/raw/sql-pilot{,2,3,4}/`, `RM1/raw/sql-adversarial/` | pilot: 3/3 errors. pilot2 and pilot3: C failed. pilot4: 3/3. sql-adversarial v1: allowed 0/20, because the support witness was missing (`RM1/FAILURES.md:13`) | — |

**notebook**

| ID | Cohort and configuration | Path | Denominator and result | Evidence type |
|---|---|---|---|---|
| N1 | A smoke, manifest v2 (v3 corrects the scope metadata) | `eval/results/notebook-A-smoke-r1-9c2d3add86b94f3cb17a94e7e1af1531/` (`result.json`, `scope-correction.json`) | 1/1 `task_success`; `enforcement_outcome: not_attempted` | Baseline; real services, "not a service double" (`application-pilot.md:92-96`) |
| N2 | C disposition: 10 tasks × 5 | `RM1/raw/notebook-disposition/{plan.json,trials.jsonl}` | 50/50 `unsupported_configuration`, `admission: evaluation preflight refusal`, `observed_effect: not-executed` | A gate record, not an execution (`RM1/RESULTS.md:42`) |

**email, research, coding, newspaper, finance.** There are no result
directories (`eval/results/`). Each `cases.jsonl` holds one `not_frozen`
placeholder. Each `policy/narrow-v1.json` says "not authored; baseline
prerequisite incomplete". `policy/manifest-v1.json` is byte-identical across
these five apps and notebook (sha256 prefix `76b56290`), with
`"status": "planned"`. Install logs are under `eval/intake/*-install.txt`; only
email failed to resolve. The runner returns `blocked` for these apps
(`eval/src/slanggraph_eval/applications.py:163-164`).

**Non-application mechanism cohorts.** These cohorts show which routes exist in
code. They use synthetic tools and fixtures and are not counted in any app's
denominator.

| Cohort | Path | Result | Relevance |
|---|---|---|---|
| Production `DockerObjectDispatcher` | `RV2/raw/container-dispatcher-full/verification.json` | 60/60 pairs pass | Isolated-worker container route for exact read-only file grants (`RV2/README.md:36`) |
| Operator-policy restarts | `RV2/raw/container-mac-full/verification.json` | 20/20 pairs | Same route (`RV2/README.md:42`) |
| Controller-crash guardian | `RV2/raw/container-crash-full-v2/verification.json` | 80/80 trials | Cleanup under stated assumptions (`RV2/README.md:48`) |
| Direct native filesystem matrix | `RV2/raw/native-filesystem-matrix/verification.json` | 320 observations, all checks pass; `rpc_identity` unsupported | Kernel filesystem grants (`RV2/acceptance.json` item 14) |
| OpenShell static projection | `RV2/raw/openshell-native/verification.json` | 20/20 trials; file size exposed 20/20 | Comparator only |

### 1c. "Unsupported means stopped": gates the records show

Gates recorded before the effect:

- **Runner gate (evaluation harness, not production).** B/C are recorded as `unsupported` without launching when a manifest lacks `integration` (`eval/src/slanggraph_eval/applications.py:156-162`). Regression test: `eval/tests/test_applications.py:12-33`. This is the source of "records unsupported B/C configurations without executing an unprotected fallback" (`eval/APPLICATIONS.md:25-26`).
- **pandas C.** The in-process tool body refuses with "Unconfined fallback is forbidden" (`APPS/pandas/integration.py:130`). Changed sandbox limits refuse (`APPS/pandas/integration.py:193`). The executor denies "any unsupported required obligation" (`docs/security/users/linux-host-execution.md:105-106`). Linux and Landlock tool profiles must be `@minimal` (`SEC/linux.py:308-317`, `SEC/landlock.py:215-218`). Any `pids` value other than 1 is unsupported (`SEC/linux.py:1716-1717`).
- **sql C.** The tool stub raises "no unconfined fallback" (`eval/remaining/sql_application_backend.py:163`). Mediator `assess` returns UNSUPPORTED outside the exact class, selector and lowering (`eval/remaining/sql_application_backend.py:110-121`). The parser refuses before opening the database (`eval/remaining/bounded_sql.py:21-154`): 160/160 refusals in S4.
- **notebook C.** The evaluation preflight refused 50/50 rows (N2).
- **Production template mediator.** It refuses activation and invocation until implemented (`SEC/mediators/template.py:1-6`). Landlock service rules without a broker are UNSUPPORTED, `broker:unavailable` (`SEC/landlock.py:819-822`).

Paths with **no gate** in the records:

- pandas and sql model requests, input loading and outer-graph publication (trusted runtime by declaration).
- pandas C private `/tmp` writes. The clause is unsupported, but the write succeeds.
- sql B, which authorizes the call and then runs the original effect unmediated.
- All A runs, by design.

---

## Step 2: Effect inventories

Each table is seeded from the app's `intake.json` `effects` string and refined
from its adapters and policies. For pandas, sql and notebook, adapter code and
runs exist. For the other five apps, **the application code was never
executed in the records**, so their rows list only what `intake.json` and the
app README record.

### pandas

Seed (`APPS/pandas/intake.json` `effects`): "Model calls in graph nodes;
generated computation in utils/sandbox.py:run_code_sandboxed_subprocess;
Streamlit upload and session storage outside graph." Refined from
`APPS/pandas/integration.py`, `APPS/pandas/worker.py`, `APPS/backend.py`,
`APPS/pandas/policy/{narrow-v3.json,compute-v3.slp.template,mapping.csv}`.

| Component | Operation | Protected resource | Data shape | Execution route | Enforcement point | Unsupported behavior and gate |
|---|---|---|---|---|---|---|
| Adapter input load (`APPS/backend.py:117-121`) | Read dataset in parent | Fixture `sales.csv` | CSV → DataFrame `data_raw` in graph state | trusted runtime | None. Input loading is declared trusted (`narrow-v3.json` `boundary`) | Not mediated; no gate |
| `pandas_data_analyst.py:373-378` `preprocess_routing` | Model request (routing) | Local Ollama endpoint; user request | Chat prompt → routing decision | trusted runtime | None. The router `model_invoke` hook is not placed on LangGraph model nodes (`docs/security/status.md:59`) | Ungated; model calls are outside the worker (`APPS/pandas/README.md:75-76`) |
| `data_wrangling_agent.py:735-806` `create_data_wrangler_code`, `:965` `fix_data_wrangler_code`, and the visualization equivalents in intake | Model request that generates Python | Dataset sample (`n_samples=100`, `APPS/backend.py:88-90`); user request | Prompt → Python source | trusted runtime | None | Ungated. Injected CSV-cell text reached model input in 15/15 attacked runs (`paper-macrobenchmarks.md:188`) |
| `data_wrangling_agent.py:883-886` `execute_data_wrangler_code` → `utils/sandbox.py` `run_code_sandboxed_subprocess`, replaced by `bridge` (`integration.py:149-228`) | Execute generated computation | Read `sales.csv`; read/write/create/delete `outputs/`; deny `supplement.csv` (narrow profile) and other fixture files; dataset read-only | JSON {code, function_name, data, memory_limit_mb=512, data_format} → JSON {result, error} (`integration.py:160-169`) | A: upstream subprocess sandbox (no slangGraph route). B: added ToolNode, then the upstream subprocess (trusted runtime). C: isolated worker (`LinuxSandboxExecutor`, `@minimal`, `pids 1`, `compute-v3.slp.template`) | B/C: ToolNode `dispatch` with `@dac(owner="analyst")` (`integration.py:122-142`); 4/4 dispatch checks each (P4). C: grant lowering and an activation receipt before generated code runs (`activation-receipts.json` per trial) | C in-process body refuses (`integration.py:130`). Changed limits refuse (`integration.py:193`). Unsupported required obligations deny (`docs/security/users/linux-host-execution.md:105-106`). C stopped 3/3 supported probes (P2) |
| Chart-code execution (`bridge` is also installed into `data_visualization_agent`, `integration.py:226-228`) | Execute generated chart code | Same grants as the row above | Same payload → Plotly figure JSON. v19 adds portable conversion and keeps `plot_native` (`APPS/backend.py:126-133`) | As above | As above | Monthly chart failed with an upstream `re.PatternError` in v7 (`application-pilot.md:42-44`); it passes in v19 |
| C guest writes to worker-private `/tmp` | Write | Worker-private `/tmp` | Files | isolated worker | Worker launch. Private `/tmp` is writable by design (`narrow-v3.json` `runtime_baseline`) | **Output-only guest writes are unsupported and not gated.** The write succeeds and the host is unchanged (`oracle-correction.json` in P2; `mapping.csv` row 6) |
| Network from generated code | Outbound connect | External destinations | Sockets | A/B: upstream network patch only. C: isolated worker | `@minimal` makes socket/connect fail with EPERM (`docs/security/status.md:64`) | Untested in this application (`mapping.csv` row 7) |
| Child processes from generated code | Spawn/exec | Descendant processes | fork/exec | C: isolated worker | `@minimal` plus `pids 1` (`SEC/linux.py:1716-1723`) | Untested in this application (`mapping.csv` row 8). This is why C replaces the upstream outer subprocess (`APPS/pandas/README.md:46-51`) |
| `human_review` nodes (`data_wrangling_agent.py:836-870`) | Human approval interrupt | — | Interrupt | Not exercised. The adapter passes no human-in-the-loop setting (`APPS/backend.py:87-90`) | None | Not recorded |
| Graph state and checkpointer (`pandas_data_analyst.py:493` `compile(checkpointer=...)`) | State write/read | Graph state holding dataset, generated code and results | State channels | trusted runtime. The adapter passes no checkpointer (`APPS/backend.py:112-116`) | None. State hooks are "Partial" and not auto-placed (`docs/security/status.md:53-55`) | Ungated; persistence not exercised |
| `finalize_output` (`pandas_data_analyst.py:448`), `get_plotly_graph` (`:204`) → `output.json` (`APPS/backend.py:122-135,165`) | Publish result | Result table, figure, full state | JSON | trusted runtime | None. Security is configured only on the added ToolNode graph (`integration.py:116-144`) | Ungated publication from the outer graph |
| Audit and receipts (B/C) | Append audit; write receipts | `security.sqlite`, `activation-receipts.json` in the run directory | SQLite audit; JSON | trusted runtime (`integration.py:98,215`) | — | — |
| Cleanup | Per-call worker teardown; per-run fixture | Worker; fixture directory | — | C: a fresh worker per call (`APPS/pandas/README.md:46-49`) | Teardown evidence is not recorded in the app records | The fixture is fresh per run and kept, never reused (`eval/APPLICATIONS.md:114-115`) |
| Streamlit upload and session storage (intake `effects`) | UI upload and storage | User files; session | — | none yet | — | Excluded from scope (manifest v19 `ui_scope`); not exercised |

### sql

Seed (`APPS/sql/intake.json` `effects`): "SQLAlchemy connection opened by UI;
schema sampling and model calls in graph; generated Python exec in
node_func_execute_agent_from_sql_connection … Metadata sampling may read
restricted tables before query dispatch." Refined from `APPS/backend.py`
(runner pilot), `eval/remaining/{sql_application_backend.py,bounded_sql.py,sql_worker.py,sql_campaign.py}`,
`eval/intake/sql-observations.json` and `APPS/sql/policy/mapping.csv`.

| Component | Operation | Protected resource | Data shape | Execution route | Enforcement point | Unsupported behavior and gate |
|---|---|---|---|---|---|---|
| SQLAlchemy engine and connection (`APPS/backend.py:137-147`; `sql_application_backend.py:252-256`) | Open a database connection handed to the graph | SQLite fixture (sales plus `payroll` table or `bob` row) | Live Connection object | A/B: trusted runtime on the real file. C: empty `sqlite:///:memory:` engine, so the real database is reachable only through the broker (`sql_application_backend.py:252-254`) | None in A/B | "C cannot pass SQLAlchemy connection authority into the current JSON worker" (`APPS/sql/README.md:33`). C substitutes the connection |
| `tools/sql.py:6` `get_database_metadata` | Read schema and sample rows | All tables, including restricted rows | `SELECT … ORDER BY RANDOM() LIMIT 1` per column plus DDL (`sql-observations.json`) → metadata in the prompt | A/B: trusted runtime, unmediated. C: mediated broker/adapter (`sql_access` op=schema → `bounded_sql.metadata`, owner-bound `LIMIT 3`, `bounded_sql.py:182-188`) | C: Cedar permit for `sales::schema` on selector `sales/alice` (`sql_application_backend.py:31-33`), evaluated before broker dispatch | A/B: no gate; canary in model input 26/50 and 27/50. C: 0/50 (S3) |
| `sql_database_agent.py:926-961` `smart_schema_filter`; `:647-729` `create_sql_query_code` | Model requests producing SQL text and a Python wrapper `def {function_name}(connection)` | Schema/sample metadata; user request | Prompt → SQL plus Python source | trusted runtime | None | Ungated |
| `sql_database_agent.py:565-631` `recommend_sql_steps` | Model request | — | — | Bypassed: `bypass_recommended_steps=True` (`APPS/backend.py:153`; `sql_application_backend.py:262`) | — | Not exercised |
| `sql_database_agent.py:983` `_validate_sql` (safe_mode) | Upstream query validation | — | SQL text | trusted runtime | Upstream check, `safe_mode=True` (`sql_application_backend.py:264`) | Upstream refusals are not separately recorded |
| `sql_database_agent.py:798` `execute_sql_database_code` → `agent_templates.py:631-685` (`exec(agent_code, …)`) | Execute generated Python against the live connection | Rows of other owners and restricted tables; database mutation | Python source plus Connection → DataFrame | A: trusted runtime, with `exec` in the parent (location: in-process). B: call authorization, then the original `exec` (`sql_application_backend.py:189-200,239-240`). C: generated Python **not executed**. The SQL text goes as data to the `sqlite.select.v1` mediator (`sql_application_backend.py:235-248`) | B: `host_executor._authorize` only. C: `ObjectBrokerDispatcher` assess returns EXACT only for class `sales`, ops schema/select, selector `sales/alice`, lowering `sqlite.select.v1` (`sql_application_backend.py:110-128`) | C: queries outside the grammar return `{"unsupported": …}` before any database access (S4: 160/160). The tool stub raises "no unconfined fallback" (`:163`). A/B: no gate. Database unchanged in 150/150 trials, but nothing enforced that in A/B |
| Broker-side query (C) | Read-only SELECT | `private/sales.sqlite` | Parameterized SELECT over a read-only URI, with `query_only`, ATTACH limit 0, a 1 s deadline and ≤1000 rows (`bounded_sql.py:157-169`) | mediated broker/adapter. The tool stub runs in an isolated Landlock worker (`SEC/object_broker.py:1-4,159`) and only sends `object_request` (`eval/remaining/sql_worker.py:6-7`) | Broker dispatch; principal must be `alice` (`bounded_sql.py:158-159`; `sql_application_backend.py:131-132`) | Assumes a fresh, trusted private directory and no alias discovery (`RV2/acceptance.json` item 9; `RM1/FAILURES.md:11`) |
| `sql_database_agent.py:851` `fix_sql_database_code` | Model repair loop | — | — | trusted runtime | — | Disabled in RM1 (`max_retries=0`, `sql_application_backend.py:266`) |
| `sql_database_agent.py:879` `report_agent_outputs` → `output.json` (`sql_application_backend.py:267-273`) | Publish result | Result table, SQL text, state | JSON | trusted runtime | None. Security covers only the inner ToolNode graph (`sql_application_backend.py:178-181`) | Ungated |
| Audit and evidence (C) | Write | `audit.sqlite`, `activation-receipts.json`, `grants.json`, `lowering.json`, `broker-audit.json`, `resource-trace.json` (`sql_application_backend.py:177,276-288`) | — | trusted runtime | — | — |
| Cleanup | Engine dispose; per-run private database directory (`sql_campaign.py:99-113`) | Fixture database | — | trusted runtime. The broker worker uses Landlock cleanup rules (`SEC/landlock.py:523-532`) | Database bytes are compared before and after (`database_changed`, `sql_campaign.py:179`) | — |
| UI (`app.py`, hosted-model selection) | — | — | — | none yet | — | Excluded. "Original UI only offers hosted GPT models" (`APPS/sql/README.md:33`) |

### notebook

Seed (`APPS/notebook/intake.json` `effects`): "Source retrieval/extraction in
content_process; save_source persists through SurrealDB; worker queues
embeddings; ask graph searches sources; chat uses SQLite checkpoints. API file
upload and async workers are outside graph." Refined from
`APPS/notebook/{README.md,backend.py,policy/manifest-v3.json}` and
`RM1/raw/notebook-disposition/plan.json`. Only A was executed (N1).

| Component | Operation | Protected resource | Data shape | Execution route | Enforcement point | Unsupported behavior and gate |
|---|---|---|---|---|---|---|
| Adapter model registration: `POST /models` if absent (`APPS/notebook/backend.py:41-52`) | Configuration write | SurrealDB model records | JSON | none yet (upstream API process) | None | Configuration injection is unmediated. B/C are refused (N2) |
| `api/routers/sources.py:709` `create_source_json` → `:566` `_create_source_sync_path` → `commands/source_commands.py:64-125` `process_source_command` (`source_graph.ainvoke`) | Submit and process a source through the command queue | SurrealDB queue; worker process | JSON text source | none yet. The API and `surreal-commands-worker` processes are not in the client trace (manifest-v3 `scope`) | None | The worker is required even with `async_processing=false` (`APPS/notebook/README.md:50-53`) |
| `open_notebook/graphs/source.py:160` `content_process` | Retrieve and extract URLs, YouTube links or files | Network endpoints; local files | URL/file/text → extracted content | none yet | None | The pilot used text ingestion only (`APPS/notebook/README.md:3-4`). URL and file extraction were not exercised |
| `source.py:270` `save_source` → `database/repository.py:103-221` (`repo_query/create/relate/upsert/update/delete/insert`) | Persist and read source records | SurrealDB namespace `slanggraph_eval` | RecordID records | none yet | None | "backing-store read: missing required production integration" (`plan.json` `coverage`) |
| `source.py:307-338` `trigger_transformations` / `transform_content` (Send fan-out), plus embedding queueing | Model requests; vector indexing | Source content | — | Excluded through request options (`APPS/notebook/README.md:54-55`) | — | Not exercised |
| `api/routers/sources.py:159-177` `_write_uploaded_file` / `save_uploaded_file` | Write an upload file | Upload folder | Bytes | Excluded (API upload is outside the graph, per intake) | — | Not exercised |
| `api/routers/source_chat.py:96,433` → `graphs/source_chat.py:48-192` (`build_context` `:77`, `model.invoke` `:192`) | Read source content into model input; model request | Per-collection source content; local llama3 | Context text → chat messages | none yet | None | "source lookup" and "model input" lack production integration (`plan.json`). There is no model-controlled source-selection tool (`APPS/notebook/README.md:73-75`) |
| `source_chat.py:226-233` `SqliteSaver`; `api/routers/source_chat.py:216,357` `get_state` | Checkpoint write, read and restore | SQLite checkpoints in the checkout's `data/sqlite-db/` (`APPS/notebook/README.md:72-73`) | Checkpoint blobs | none yet | None | "checkpoint restore/history" is missing. The stale-checkpoint probe was planned but never executed (`plan.json` `negative_probes`) |
| `api/routers/source_chat.py:351` `stream_source_chat_response` / API response | Publish the answer | AI answer text | Stream/JSON | none yet | None | "publication" is missing. The unauthorized-output probe was planned but never executed |
| `graphs/ask.py`, `api/routers/search.py:26-203` | Search and ask across sources | All sources | — | Excluded: vector search is out of scope (manifest-v3 `scope`) | — | Not exercised |
| Cleanup/reset | Stop the API and worker; `docker compose down`; keep `surreal_data/` and checkpoints | Database volume; checkpoint files | — | none yet (manual) | — | Only fresh IDs; a stronger reset procedure is not verified (`APPS/notebook/README.md:77-81`) |

### email (application code never executed; intake rows only)

Seed: "Gmail read/send/mark-as-read and Calendar SDK effects in eaia/gmail.py;
send_email_node calls SDK helper directly; preserve human_node approval
workflow. OAuth and ingestion outside graph; hosted inbox and LangGraph
persistence require separate trace."

| Component | Operation | Protected resource | Data shape | Execution route | Enforcement point | Unsupported behavior and gate |
|---|---|---|---|---|---|---|
| `eaia/gmail.py:30` `get_credentials` | OAuth credential acquisition | Gmail/Calendar tokens | Credential files/secrets | none yet | — | No dedicated test identity (`APPS/email/README.md`). Credential custody is "Phase two" (`docs/security/status.md:90`) |
| `eaia/gmail.py:187` `fetch_group_emails`; `scripts/run_ingest.py:12`; `eaia/cron_graph.py:17-54` | Read the mailbox; scheduled ingestion | User mailbox | Messages | none yet | — | Ingestion is outside the graph (intake) |
| `eaia/main/graph.py:30` `route_after_triage`, `:45` `take_action`, `:73` `bad_tool_name` | Triage and drafting model calls; routing | Email content | — | none yet | — | The reflection graph hard-codes hosted models and is excluded (`APPS/email/README.md`) |
| `eaia/main/graph.py:153` `human_node`, `:88` `enter_after_human` | Human approval interrupt and resume | — | Interrupt | none yet. The router approval/resume hook is "Implemented" (`docs/security/status.md:57`) but not applied to this app | — | Must be preserved (intake) |
| `eaia/main/graph.py:133` `send_email_node` → `eaia/gmail.py:152` `send_email` → `:147-148` `messages().send` | Send mail | Recipients; Gmail account | MIME message | none yet | — | No live send attempted (`application-pilot.md:97-99`). No Gmail handler in `SEC/` |
| `eaia/main/graph.py:148` `mark_as_read_node` → `eaia/gmail.py:288` | Mutate mailbox state | Gmail labels | — | none yet | — | — |
| `eaia/main/graph.py:115` `send_cal_invite_node` → `eaia/gmail.py:402`; `:310` `get_events_for_days` | Calendar read and write | Google Calendar | Events | none yet | — | — |
| LangGraph persistence/store (intake) | State and memory | Hosted persistence | — | none yet | — | "require separate trace" (intake) |
| Streaming/publication; cleanup | — | — | — | not recorded | — | not recorded |

Gate: the runner records B/C as `unsupported` and returns `blocked` for A
(`eval/src/slanggraph_eval/applications.py:156-164`). No attempt was recorded.

### research (application code never executed; intake rows only)

Seed: "Supervisor/researcher StateGraphs; tool.ainvoke in researcher_tools;
search provider and remote MCP effects in utils.py; model calls and report
synthesis. Local request mediation does not confine remote services."

| Component | Operation | Protected resource | Data shape | Execution route | Enforcement point | Unsupported behavior and gate |
|---|---|---|---|---|---|---|
| `deep_researcher.py:60-101` `clarify_with_user`, `:118-154` `write_research_brief`, `:178-214` `supervisor` | Model requests with structured output | User query | Messages → structured output | none yet | — | Needs a supported local structured-output model (intake `next_action`) |
| `deep_researcher.py:225-296` `supervisor_tools` (`researcher_subgraph.ainvoke`), `:365-415` `researcher` | Subgraph fan-out; model loop | — | — | none yet | — | Dispatch placement for subgraph/subagent is "Partial" (`docs/security/status.md:50`) |
| `deep_researcher.py:427-430` `execute_tool_safely` (`tool.ainvoke`), `:435` `researcher_tools` | Tool invocation | Search and MCP tools | Tool arguments as JSON | none yet | — | — |
| `utils.py:44` `tavily_search`, `:138` `tavily_search_async`, `:531` `get_search_tool`, `:607,639` provider web-search checks | Web search | Tavily/provider endpoints | HTTP JSON | none yet | — | Endpoint/name enforcement is "Phase two" (`docs/security/status.md:84`). The Linux worker isolates the network (`SEC/linux.py:1628`) |
| `utils.py:175-194` `summarize_webpage` | Model request over fetched content | Web content (untrusted) | Text → summary | none yet | — | Model-input placement is "Partial" (`docs/security/status.md:59`) |
| `utils.py:250` `get_mcp_access_token`, `:293,331,352` token get/set/fetch, `:385` `wrap_mcp_authenticate_tool`, `:449` `load_mcp_tools` | Remote MCP connection; token persistence | MCP servers; access tokens | JSON-RPC over a remote transport | none yet | — | `SEC/mcp_proxy.py` supports stdio servers only (`SEC/mcp_proxy.py:1,42-98`) |
| `utils.py:892` `get_api_key_for_model`, `:916` `get_tavily_api_key`; `configuration.py:237` `from_runnable_config` | Configuration and credential injection | API keys | RunnableConfig/env | none yet | — | Credential custody is "Phase two" (`docs/security/status.md:90`) |
| `deep_researcher.py:511-551` `compress_research`, `:607-650` `final_report_generation` | Synthesis and report publication | Report text | — | none yet | — | Output placement is "Partial" (`docs/security/status.md:60`) |
| `tests/run_evaluate.py:32-63` | Benchmark harness | LangSmith | — | none yet | — | Requires LangSmith; any subset must be labeled (intake) |
| Cleanup | — | — | — | not recorded | — | not recorded |

Gate: as for email.

### coding (application code never executed; intake rows only)

Seed: "Managed Deep Agents owns model loop, tools, checkpoints and sandbox.
Backend uses PostgreSQL and GitHub credentials; remote sandbox shell/files and
publication need execution-host instrumentation. Preserve upstream middleware
and sandbox."

| Component | Operation | Protected resource | Data shape | Execution route | Enforcement point | Unsupported behavior and gate |
|---|---|---|---|---|---|---|
| `openswe/threads/router.py:125-337` (`_create`, `_search`, `_create_run`, `_copy`, `_cancel_many`) | Thread and run management | Thread index; PostgreSQL backend (intake) | HTTP/ASGI | none yet | Upstream `_refuse_local` (`router.py:112`) | Not exercised |
| `mda/agent.py:165-319` `agent` → `define_deep_agent` | Model loop owned by Managed Deep Agents | Model provider; MDA credentials | — | none yet | — | MDA is a separate environment (`APPS/coding/README.md`) |
| `mda/rt/file_tools.py:64-65` `_GUARDED_WORDS`/`_SHELL`, `:174` `_screened`, `:199` `_run_remote`, `:272` `_guarded` | Screen and run tool calls | Remote sandbox shell | Command strings | none yet | Upstream screening middleware | Must be preserved (intake) |
| `mda/rt/managed_sandbox.py:39` `definition`, `:56` `opened_sandbox`, `:75` `awrap_tool_call` | Create and open a remote sandbox | Remote managed sandbox | — | none yet | — | "Local executor cannot confine a remote sandbox by itself" (`APPS/coding/README.md`) |
| `openswe/agent_api/graph.py:1195-1272` `_ls/_read/_write/_edit/_delete/_glob/_grep/_execute/_upload/_download` | Workspace file operations and command execution | Workspace files; subprocesses | Path and command requests | none yet | — | Production `@minimal` forbids process creation (Step 3 note). The exec-enabled profile is evaluation-only |
| `openswe/agent_api/graph.py:547,733` `check_shell` | Shell policy check | — | — | none yet | Upstream | — |
| `openswe/agent_api/graph.py:982` `refresh_github_proxy`, `:994-998` `reply_on_behalf` | GitHub publication and comments | GitHub App/repository | API calls | none yet | — | No dedicated GitHub App/repository (`APPS/coding/README.md`) |
| `openswe/agent_api/graph.py:551` `record_evidence`, `:897-914` `tool_started/tool_result` | Run state and evidence recording | Run state; PostgreSQL | — | none yet | — | — |
| `openswe/agent_api/graph.py:745` `reconnect_sandbox`, `:956` `sandbox_unreachable`, `:1008` `run_ended` | Sandbox lifecycle and cleanup | Remote sandbox | — | none yet | — | Cleanup not recorded |

Gate: as for email.

### newspaper (application code never executed; intake rows only)

Seed: "StateGraph Send fans out article subgraphs; search and model SDK calls in
nodes; publisher writes outputs; source photos or optional provider
illustrations. Preserve source-as-untrusted prompts and retries."

| Component | Operation | Protected resource | Data shape | Execution route | Enforcement point | Unsupported behavior and gate |
|---|---|---|---|---|---|---|
| `backend/graph.py:99` `assign_reporters` (Send), `:80-83` `reporter_node`, `:56-74` and `:107-117` graph builders | Subgraph fan-out | — | — | none yet | — | `Send` placement is not automatic (`docs/security/status.md:50`) |
| `backend/agents/search.py:16` `get_search_tool` (TavilySearch), `:35-37` `_search`, `:46` `_search_all`, `:82` `search_node` | Web search | Tavily API; API key | HTTP JSON | none yet | — | No Tavily credential or double (`APPS/newspaper/README.md`). Endpoint scoping is "Phase two" |
| `backend/agents/common.py:41` `chat_model`, `:59` `format_sources` | Model requests over source text | Untrusted sources | — | none yet | — | Source-as-untrusted prompts must be preserved (intake) |
| `backend/agents/illustrator.py:17-28` `illustrator_node` | Model request; optional image provider | Image provider | — | none yet | — | — |
| `backend/agents/publisher.py:16` `publisher_node`; `backend/config.py:87` `new_run_dir`, `:91` `public_url` | Write edition output files | Run output directory | Files | none yet | — | No edition attempted |
| `backend/graph.py:124` `stream_newspaper`; `common.py:46` `emit` | Stream progress and results | Stream events | — | none yet | — | Output placement is "Partial" (`docs/security/status.md:60`) |
| `backend/config.py:41-71` `get_settings` (env) | Configuration injection | Environment settings and keys | — | none yet | — | — |
| Cleanup | — | — | — | not recorded | — | not recorded |

Gate: as for email.

### finance (application code never executed; historical pin; intake rows only)

Seed: "Historical LangGraph analyst workflow; requests GET/POST to financial
data provider, local cache, model calls, optional graph PNG. Analysis only; no
brokerage or real-money trading."

| Component | Operation | Protected resource | Data shape | Execution route | Enforcement point | Unsupported behavior and gate |
|---|---|---|---|---|---|---|
| `src/main.py:46-64` `run_hedge_fund`, `:100-102` `create_workflow`, `:95` `start` | Graph orchestration | — | — | none yet | — | — |
| `src/tools/api.py:29-50` `_make_api_request` (`requests.post` `:48`, `requests.get` `:50`); `get_prices` `:63`, `get_financial_metrics` `:99`, `search_line_items` `:141`, `get_insider_trades` `:183`, `get_company_news` `:249`, `get_market_cap` `:315` | HTTP GET/POST | Financial-data provider; API-key headers | HTTP JSON | none yet | — | No frozen responses or credential (`APPS/finance/README.md`). Network scoping is "Phase two" |
| Local cache (intake) | Cache read and write | Local cache files | — | none yet | — | not recorded beyond intake |
| `src/llm/models.py:151` `get_model` (ChatOpenAI/ChatGroq/ChatOllama/GigaChat) | Model requests | Model provider | — | none yet | — | Local model settings are not frozen |
| `src/agents/portfolio_manager.py:25,96,177-239` | Model analysis and decision; no brokerage | — | — | none yet | — | Analysis only (intake) |
| Optional graph PNG (intake); `src/main.py:30` `parse_hedge_fund_response` | Write an image; publish results | Local file; output | PNG; JSON | none yet | — | — |
| Cleanup | — | — | — | not recorded | — | not recorded |

Gate: as for email.

---

## Step 3: Workload categories

**Verified fact: production workers cannot create processes.**

- `SEC/landlock.py:527-530`: "Without a cgroup the production worker's fixed minimal seccomp filter forbids all process/thread creation and executable replacement before releasing tool code. This lifetime rule does not cover the separate exec-enabled evaluation worker."
- `SEC/linux.py:1716-1717`: any `pids` limit other than 1 is unsupported (`minimal_seccomp_supports_pids_one_only`). `SEC/linux.py:1723` maps `pids` to `seccomp_no_process_creation`.
- The allowlist in `SEC/_linux_worker.py:24-103` contains no `clone`, `clone3`, `fork`, `vfork`, `execve`, `execveat`, `socket` or `connect`. The default action is EPERM (`SEC/_linux_worker.py:247-250`).
- Linux and Landlock profiles must be `@minimal` (`SEC/linux.py:308-317`, `SEC/landlock.py:215-218`).
- The only exec-enabled profile is evaluation-only (`eval/src/slanggraph_eval/isolation/binary_worker.py:1,74-83`), and it has no process-count quota under Landlock (`eval/reports/native-chain-v2/report.md:15`).

Subprocess-based coding therefore needs a production worker profile that does not exist yet.

| # | Category | Cohort apps (proposed mapping) | Best recorded evidence | Protected route in code today | Coverage (proposed) |
|---|---|---|---|---|---|
| 1 | Research with network/model access and report publication | research, newspaper; finance (data API plus analysis output) | None. All three are `blocked` with no runs (`eval/apps.csv`) | No network endpoint route (`docs/security/status.md:83-84`). Output placement is "Partial" (`:60`) | **uncovered** |
| 2 | Structured extraction with state/configuration injection | notebook is closest (source extraction into stored records; model registration through the API); research `from_runnable_config` | notebook A 1/1, baseline only (N1) | None. Notebook C refused 50/50 (N2) | **uncovered** |
| 3 | Service workflow with human approval and persistent memory | email (`human_node`, Gmail, persistence); notebook chat checkpoints (partial fit) | None for email. Notebook A 1/1 with an unmediated checkpoint path | The approval/resume router hook is "Implemented" (`docs/security/status.md:57`). Checkpoint integration is "Partial" (`:79`). Service credentials are "Phase two" (`:90`) | **uncovered** |
| 4 | Database/data analysis with scoped resources and artifacts | pandas, sql | pandas: C 50/50 in v19 (P10); C stopped 3/3 supported probes (P2); `outputs/` artifact grant (`narrow-v3.json`). sql: C 50/50 with 0/50 canary (S3); 200 probes (S4) | `LinuxSandboxExecutor` for pandas. Production broker plus the **evaluation-only** bounded mediator for sql | **covered by pandas** (proposed). sql is partial |
| 5 | Coding with isolated workspace and subprocesses | coding | None | None. `@minimal` forbids process creation (verified above). The Docker dispatcher supports read-only file grants only (`docs/security/docker-dispatcher.md:12,45-46`) | **uncovered** |
| 6 | MCP integration with declared server/tool/transport scope | research (optional remote MCP, `utils.py:250-449`) | None | A stdio-only MCP proxy for the broker (`SEC/mcp_proxy.py`) with unit tests (`libs/prebuilt/tests/security/test_mcp_proxy.py`). No application evidence; no remote transport | **uncovered** |

**Uncovered categories:** 1 (research/report), 2 (structured extraction),
3 (approval plus memory service), 5 (coding with subprocesses) and 6 (MCP).
Only category 4 has protected application evidence, and within it only pandas
uses production code end to end.

---

## Open questions for the advisor

1. **SQL class.** The C route rests on evaluation-harness code (`eval/remaining/bounded_sql.py`: one table, bounded SELECT grammar) that replaces the app's generated-Python execution. Does that count as an existing enforcement path ("supported" for the frozen 10 tasks), or must a mediator be promoted into `SEC/mediators/` first ("requiring an adapter", proposed here)?
2. **Pandas denominator.** Which cohort is frozen: v19-full (150/150, using request preservation, the `aggregate_periods` helper, serializer v2, Plotly normalization and 3 retries) or RM1 pandas-full (A 29/50, B 27/50, C 29/50 with 0 retries)? Are the v11–v19 adaptations acceptable as "not changing the application"?
3. **Trusted runtime and "supported".** Model requests, input loading and outer-graph publication run ungated in pandas and sql, and router placement for model input and output is "Partial" (`docs/security/status.md:59-60`). May a "supported" app declare these as trusted runtime?
4. **Private `/tmp` in pandas C.** Output-only guest writes are unsupported, but the write succeeds rather than being refused. Does this breach "unsupported means stopped", or is private `/tmp` an accepted runtime baseline (`narrow-v3.json` `runtime_baseline`)?
5. **Coding.** "Requiring a worker profile" (proposed) assumes the upstream remote MDA sandbox can be replaced by a local exec-enabled worker. If the remote managed sandbox must stay, should coding be "unsupported" instead?
6. **Notebook.** Is "requiring an adapter" right (a SurrealDB/source adapter plus model-input, publication and checkpoint placement inside the API and worker processes), or is the server boundary itself unsupported until it is defined (`RV2/acceptance.json` item 5)?
7. **Blocked apps and doubles.** Email, research, newspaper and finance depend on contract-preserving doubles or dedicated accounts. Will doubles count as evidence? Should archived email/research (email does not install) and historical finance (unverified pin) stay in the cohort denominator?
8. **Conflicting records.** Which record governs the freeze?
   - `application-pilot.md:87-91` and `APPS/sql/README.md:39-44` say SQL B/C are unsupported, and `eval/APPLICATIONS.md:148-150` describes only the fixed-schema `sqlite_record_mediator` ("a general SQL mediator would be new system work") without mentioning the RM1 sql-full cohort, but `RM1/RESULTS.md:36` records SQL C 50/50.
   - `RV2/README.md:19` reports v11 as 26/30, but the raw trials and `RV2/v11-summary.json` give 24/30.
   - The `apps.csv` `baseline_run` pointers for pandas and sql are early manifest-v2 runs with only a `source-recovery.json` source record.
