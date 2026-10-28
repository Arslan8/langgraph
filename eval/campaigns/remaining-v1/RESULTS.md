# slangGraph evaluation evidence — 26 October 2026

This package preserves the completed v2 cohorts and adds the remaining executable mechanism/application campaign. It is an evidence handoff, **not a claim that all acceptance gates passed**. `FAILURES.md` and `coverage.csv` bound every result. No original v2 measurement was rerun or overwritten.

## Existing measurements

`completed-v2/` is the intact first handoff: 69 timing cells, 6,900 measured calls, five process sessions, parent oracles, paired increments and normalized ratios. The two pasted reports describe one study. The census has 49 forbidden cases and ten controls, each repeated three times per host mode. The 132 explicit-denial trials correspond to 44 consistently denied cases, not the historical 45/49. Verified controls are four distinct cases times three trials. Landlock's `stat_metadata` exposure remains visible; the container has zero observed exposures only in this finite corpus. Native-chain rejection remains rejection, and its exec-enabled profile is separate.

The execution-only Pandas Landlock point estimate (+0.34%) has a paired increment interval crossing zero. It is neither demonstrated slowdown nor demonstrated zero overhead. Historical Bubblewrap, current evaluation adapters and production dispatchers are separate implementations. Missing contemporaneous source/host provenance is not repaired by assigning the public commit to a cohort.

## New mechanisms and utility

| Experiment | Executed denominator | Result and scope |
|---|---:|---|
| Production component suites | 128 tests x 20 fresh processes = 2,560 | All pass. Contract/unit evidence is separately labeled, including simulated fixture descriptions. |
| Grant matrix | 6 cases x 20 = 120 | Required control and optional `want` removal both succeed 20/20. Missing `need`, wrong grant/principal and activation failure refuse with no observed resource effects. |
| Real capability configurations | 2 configurations x 2 cases x 20 = 80 | Normal ABI7 controls pass; inherited seccomp genuinely makes Landlock unavailable and execution refuses. This is one Linux machine with two real configurations, not two physical hosts. |
| Container lifecycle | 3 key-change cases x 20 = 60 pairs | Broad-to-narrow, A-to-B and changed-forbid cases recreate containers; 60/60 allowed results and zero residual-authority effects. Evaluation adapter only; IDs, mounts and recreation costs retained. |
| Restricted manifests/MAC | 9 cases x 20 x paired control = 360 rows | No forbidden effects. RPC identity is unsupported on this route. Required refusals and runtime waiver rejection remain distinct from execution. |
| Confined broker manifests/MAC | 8 cases x 20 x paired control = 320 rows | All 160 paired controls succeed; correct-operation probes also succeed. Zero forbidden effects. Fixed operator forbid conflicts with a broad discretionary permit. |
| SQLite composition | 13 cases x 4 modes x 20 = 1,040 | Each mode completes 60/60 allowed read/write/delete controls. Production composition has zero observed forbidden effects in 200 negative trials; call-only and file-access modes each expose effects in 100 trials; incomplete broker harness in 40. Some negative reference cases are unsupported, not denials. |
| Pump composition | 6 cases x 3 modes x 20 = 360 | Each mode completes 60/60 controls. Production composition has zero forbidden effects in 60 negative trials, versus 40 call-only and 60 transport-only. Oracles use accepted-command logs and simulator state. |
| Bounded SQL deterministic probes | 10 cases x 20 = 200 | 20/20 allowed sums; no payroll disclosures or database changes. Owner substitution narrows to no rows; joins, subqueries, UNION, ATTACH, PRAGMA, schema changes, writes and extension loading are unsupported. |

Fresh private SQLite directories keep DB, WAL and SHM together. A separate trusted setup check rejects symlinks and multiply-linked database files (60 setup records). This is not production alias discovery and assumes no concurrent untrusted namespace writer. The useful SQLite task uses the fixed-record mediator; the SQL application uses a **separate bounded SELECT mediator**. Unsafe reference harnesses do not disable production integrity checks.

`worked-example/` contains actual Alice/Bob manifests, policy, grants, lowering decisions, activation evidence, allowed and denied traces and independent resource snapshots. A manually wired host-plus-broker configuration receives credit for the same enforcement; no retrospective labor advantage is claimed.

## Protected applications

All 10 tasks x 5 repetitions x A/B/C were retained and interleaved for each application, using local qwen3:8b with pinned digest/settings. Pandas and SQL are two applications in one upstream repository, not two independent repositories.

| Application | A task success | B task success | C task success | Model-input canary exposure A/B/C |
|---|---:|---:|---:|---|
| Original Pandas graph/sandbox | 29/50 | 27/50 | 29/50 | Clean utility tasks; not an injection corpus |
| Original SQL agent with bounded C adapter | 50/50 | 50/50 | 50/50 | 26/50, 27/50, 0/50 |

A is the upstream baseline; B adds call authorization; C binds production authorization/enforcement. Pandas C uses LinuxSandboxExecutor and retains the original generated sandbox program. SQL C mediates schema/sample collection before model input and passes generated SELECT text unchanged to a trusted parser. Allowed identifiers and parsed forms create trusted parameterized SQL with principal ownership bound independently of the model's predicate. Arbitrary generated Python SQL wrappers are replaced by this bounded executor, a documented adaptation; the original graph remains.

Pandas failures include Timestamp JSON serialization errors, unusable graph outputs, incorrect aggregations and chart formatting/series mismatches. No failing task was dropped. The chart series are independently decoded, including Plotly typed arrays, in `summaries/pandas-failures-and-series.json`; the original frozen oracle results remain intact. `application-tasks.csv` gives the full set, and `baseline-success-subset.csv` gives matching A-success task/repeat pairs.

Notebook remains an **unsupported protected configuration**: source lookup, backing reads, restore/history, model input and publication are not all mediated by the client adapter. Its 50 C disposition rows are preflight non-executions, not 50 successful protected runs. Native sources, pinned image identity, tasks and probes are retained separately.

## Costs

| Full workflow, all 50 runs/mode | A mean | C mean | Added | C/A |
|---|---:|---:|---:|---:|
| Pandas | 11,638.06 ms | 13,668.46 ms | 2,030.39 ms | 1.1745x (+17.45%) |
| SQL | 6,238.97 ms | 11,259.81 ms | 5,020.84 ms | 1.8048x (+80.48%) |

Paired resampling of ten task means gives C/A 95% intervals of [1.1317, 1.2283] for Pandas and [1.6542, 1.9925] for SQL. These are descriptive **shared-host** results: application work, builds, tests and other users' host work overlapped. They are not idle-host latency or isolated enforcement-only estimates. Failures remain in wall-time denominators. Token counts, model durations and remaining wall time are recorded per run; the remainder is not relabeled enforcement time.

New useful typed-counter timings use actual admission, binding and parent resource oracles: verified mean 20.791 ms and production broker mean 690.980 ms (100 measured calls each across five sessions, plus separately recorded first use and warmups). The direct in-memory backend is a sub-microsecond baseline, so its very large runtime multiples are numerically correct but a poor headline comparison; absolute latency and timer boundaries are prominent.

A separate cold-container read cohort measures actual one-shot execution: 2,138.76 ms container versus 100.86 ms plain subprocess, 21.2056x, +2,037.90 ms, n=100/mode across five sessions. Paired increment 95% session-t interval is [1,925.91, 2,149.88] ms. This is separate from the original warm invocation data and the explicitly **modeled** v2 amortization curve. Container recreation distributions use 20 pairs per key-change case.

Separate intrusive SQL attribution runs retain inclusive policy, broker/activation and SQLite audit spans; they must not be summed across nesting/threads or pooled with headline timings. Intrusive Pandas profile attempts failed at the worker protocol boundary and are retained. Per-phase policy/audit attribution for successful Pandas full runs is therefore still unavailable.

## Focused comparators and producer

Nono and Sandlock each complete all 60 allowed read/chain/metadata controls and block all 40 forbidden content-read/native-chain trials. Both expose the forbidden file's size in 20/20 `stat` probes under the selected content-access policy. Sandlock uses its documented no-supervisor mode; these results do not characterize its other profiles. Configurations, full source IDs, source archives and build failures are retained.

Progent's exact-path policy allows 20/20 controls and denies 20/20 forbidden arguments. An allowed call whose trusted native body reads Bob exposes the canary 20/20; this is outside the call-checker's tool-trust boundary, not a claim about an inferred policy. CaMeL's actual interpreter/AgentDojo adapter allows 20/20 controls and denies forbidden paths and untrusted argument flow (40 probes). Hidden native-callee reads remain outside its stated interpreter boundary (20 observed effects).

APF's official evaluator correctly handles 20 authorized, 20 operator-forbidden and 20 ungranted calls. The official OpenShell projector preserves exact read grants, no write grants and disabled implicit workdir access. Its 28 official projector tests pass. OpenShell runtime enforcement was not executed here; no widening or vulnerability claim follows from that gap.

The independent offline AST producer emits manual-equivalent requirements for ten literal fixtures. Four unknown forms reject. Manual and produced requirements each yield nine authorized successes and one expected Bob-record denial through unchanged authorization/enforcement. Underdeclared and overdeclared file manifests refuse. This is a fixture producer, not general inference or Progent reproduction. Stale output-only wording in its raw scope file is corrected by a separate evidence note without overwriting the original.

## Validation and remaining gates

Prebuilt format and lint pass; the full suite passes **3,864 tests** (16 snapshots). The repeated focused suites pass 2,560 tests separately. New SQL/oracle tests pass 17 tests. Security permutations pass. **Security completeness and regression gates fail**: 40 source-review SGV301 findings, 34 stale-waiver SGV302 findings and verifier-owned SGV901–903 proof gaps remain. No waiver was automatically refreshed and these static findings are not presented as executed bypasses. Formatting changed no prebuilt source bytes during this campaign.

Every headline cell is traceable to raw run IDs. The index identifies records whose required metadata must be joined from plans/configurations and fields that remain unrecorded. Per-session historical host telemetry, successful Pandas phase attribution, production container integration, a useful stricter production lowering adapter, APF runtime coverage and Notebook complete mediation are not established. Acceptance is bounded by these facts, not by passing component tests.
