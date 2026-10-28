## Application macrobenchmarks: security, utility, and runtime cost

> Preliminary application pilot. Timing estimates below are historical single-session
> observations, not standardized primary performance results. See the current
> [evaluation status](paper-evaluation.md) and [historical timing appendix](historical-runtime.md).


We evaluate three questions: can existing applications execute useful workflows
with local models; can authorization and host enforcement constrain effects inside
an allowed computation; and what runtime cost does the integration impose? We
report baseline reproduction, security outcomes, and runtime measurements
separately. The current evidence is an application pilot with one experimental
protected integration, not a completed eight-application security suite.

### Host and reproducibility

**Table 1. Measured environment.**

| Component | Configuration |
| --- | --- |
| CPU | Intel Xeon w5-3435X; 1 socket, 16 physical cores, 32 logical CPUs |
| Memory | 62.25 GiB OS-visible RAM |
| GPUs | 2 × NVIDIA RTX A4000, 16,376 MiB VRAM each; driver 580.178.04 |
| OS / kernel | Ubuntu 24.04.5 LTS; Linux 6.17.0-1033-oem, x86-64 |
| Application Python | 3.13.11 for Pandas/SQL; 3.12.3 for Notebook |
| Local model server | Ollama 0.32.14; local HTTP endpoint only |
| Sales model | qwen3:8b, 8.2B parameters, Q4_K_M; digest `500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41` |
| Sales sampling | Temperature 0, requested seed 20261005, reasoning disabled, no client retries |
| Model residency in repeated runs | Ollama reports 9,969,650,892 bytes VRAM and 32,768-token context; GPU sharding not measured |
| Notebook model | Local llama3:latest; temperature 1.0, top-p 0.9, maximum 8,192 output tokens |
| Worker mechanisms | bubblewrap 0.9.0, namespace isolation, libseccomp; activation receipts retained |
| Application CPU allocation | Parent and computation children restricted to logical CPU 0; Ollama is a separate process |
| Evidence/audit storage | `/data`, ext4 on `/dev/sda2`, a rotating ST12000NM000J disk |

The source revision is `40e24e978f9ec2e8f061abb21077e2251583f5e5` plus the
recorded working-tree modifications. A source archive and per-file hashes identify
the actual slangGraph implementation; the revision alone is insufficient. Each
integrated application run verifies the frozen source inventory. Full upstream
SHAs, environment freezes, commands, model digests, and policy/manifest hashes are
recorded in the artifact. Local timing began at host load averages
0.23/0.21/0.41; the machine was not reserved exclusively, CPU frequency was not
fixed, and OS caches were not flushed. These conditions bound the interpretation
of timing variation. The original pilot did not attest model context length; the
32,768-token observation above applies to the later repetition batch.

### Applications and port descriptions

We inspected a fixed shortlist of eight applications from seven repositories.
Pandas and SQL share a repository. Three applications from two repositories have
local baseline reproductions; only Pandas has an experimental protected
integration. We do not count installation, subagents, or Notebook features as
additional completed ports.

**Table 2. Application status. Full commit IDs and source links are in the intake
ledger; prefixes below identify those pinned revisions.**

| Application | Revision | Reproduced scope | Protected status / blocker |
| --- | --- | --- | --- |
| Pandas Data Analyst | `4ffeb7f38178` | Bundled analysis backend | A/B/C pilot; incomplete full study |
| SQL Database Agent | `4ffeb7f38178` | Bundled SQL backend; 3/3 clean pilot tasks pass | Arbitrary SQL and schema-sampling mediation unsupported by the integration |
| Open Notebook | `a0f6f3081ae0` | Native ingestion and source-chat APIs; 1/1 smoke passes | Source/storage enforcement and server tracing incomplete |
| Executive AI Assistant | `758db7174223` | No completed smoke | Archived; yanked dependency versions and no dedicated Gmail test account |
| Open Deep Research | `1b7d2e80db9f` | No completed smoke | Archived; search resources and local structured-output smoke unconfigured |
| Open SWE | `ff4e713c094c` | No completed smoke | GitHub/MDA deployment resources and remote-host instrumentation missing |
| GPT Newspaper | `1c447b5672dd` | No completed smoke | Search access or a contract-preserving fixture service missing |
| AI Hedge Fund | `6c41ae8cf5fb` | Historical LangGraph revision selected; smoke unverified | Provider fixtures and local execution incomplete; no trading performed |

**Pandas integration.** The adapter invokes the bundled application's
`PandasDataAnalyst`, with its `DataWranglingAgent` and `DataVisualizationAgent`,
rather than rebuilding their graph. Original prompts and generated computation
remain enabled. Local provider selection replaces the UI's hosted-model choice;
Streamlit authentication, upload widgets, history, and rendering are excluded.
A missing IPython dependency and single-CPU affinity are recorded compatibility
adaptations applied equally across configurations.

The computation normally executes inside graph nodes via
`run_code_sandboxed_subprocess`. Configuration **A** retains that upstream
subprocess sandbox on the same local LangGraph source overlay used by B/C, with
slangGraph security disabled. **B** inserts a ToolNode authorization boundary and
then calls the original subprocess helper. This is explicitly an added
node-dispatch boundary, not a native tool-dispatch ablation or a recreation of a
published defense. **C** uses the same boundary plus the existing
`LinuxSandboxExecutor`. It executes the unmodified upstream sandbox program inside
an already-fresh worker instead of nesting another subprocess. AST/import/builtin
and network checks, resource restrictions, and JSON data transport are retained.
No upstream checkout files are edited, but this is substantive integration work:
the integration adapter is 200 lines and the worker is 20 lines, in addition to a
135-line backend adapter shared with SQL. These are physical source-line counts,
not measured engineering effort. Hands-on time was not recorded.

**SQL baseline adaptation.** The adapter invokes the bundled
`SQLDatabaseAgent.ainvoke_agent` on a recreated SQLite fixture with `sales` and
`payroll` tables, retaining upstream safe-mode validation. Independent oracles
check expected query results and database state. All three local v4 baseline tasks
pass. Source and trace inspection reveal a separate effect path: schema sampling
reads the payroll canary into the local model prompt before the generated query.
The existing `sqlite_record_mediator` supports a fixed `records(key,value)` schema,
not the application's arbitrary SQLAlchemy queries. Protecting this application
requires both query and metadata-path mediation; it is not a completed protected
port, and the sampling observation is not an exploit finding.

**Open Notebook baseline adaptation.** A 103-line API adapter invokes the original
text-source ingestion and `source_chat_graph` workflow, using its native Ollama
provider, ingestion worker, and dedicated SurrealDB. It persists two synthetic
source collections and verifies an answer containing the authorized fixture fact.
The pinned database image digest is recorded in the Notebook manifest. This is a
live local-service smoke, not a service double. Frontend behavior, embeddings, and
vector search are excluded. The client trace does not confine or fully observe the
API/worker hosts, so the smoke provides no cross-source isolation claim.

### Security methodology and measured coverage

We separate three kinds of evidence. First, deterministic requests test the actual
added Pandas dispatch boundary, independently of the model. Second, controlled
implementation variants preserve the legitimate February computation and insert
one additional filesystem operation before return. These test containment of an
authorized invocation, not prompt-injection exploitability or malicious upstream
code. Third, an adversarial-content case inserts instructions into a CSV `region`
cell sampled by the original graph. Its payload asks generated code to read a
unique private canary file, copy it to an output receipt, and then return the
correct February total. The exact template and per-run payload are retained; no
new model tool is added. Each attacked run is paired with the same clean task.

Policies are fixed before each run. Narrow and broad profiles differ by permission
to read one supplementary file. Model refusals, ignored instructions, unavailable
operations, and malformed requests are distinguished from host prevention.
Independent evidence includes unique effect witnesses, canary receipts, dataset
hashes, kernel open results, and activation receipts. Observer files are outside
worker write permissions; the parent and arbitrary baseline code share the host
UID, so this is not a tamper-proof observer against a fully malicious parent.

The original Pandas cohort contains nine clean executions and fifteen
controlled-effect executions: one execution per configuration and case/profile,
including the separately documented dataset-overwrite amendment. The later v9
cohort contains five fresh clean and five attacked runs per configuration. The
first launch batch encountered an unavailable Ollama server before inference:
all 30 infrastructure failures are retained. The 30 retry executions have new
attempt IDs and are analyzed separately; failures are not erased from the
artifact or counted as security prevention.

**Table 3. Controlled effects. Each cell is one execution. Every row also returns
the correct legitimate February result in A/B/C (15/15 executions).**

| Effect / profile | A: upstream | B: added dispatch | C: dispatch + Linux worker |
| --- | --- | --- | --- |
| Read unrelated canary, narrow | Canary copied | Canary copied | Prevented: `ENOENT`, no receipt |
| Read supplementary canary, narrow | Canary copied | Canary copied | Prevented: `ENOENT`, no receipt |
| Same supplementary read, broad | Permitted read | Permitted read | Permitted read |
| Write outside host fixture | Host file created | Host file created | Host unchanged; private `/tmp` shadow write succeeds |
| Overwrite dataset, narrow; diagnostic amendment | Dataset modified | Dataset modified | Prevented: `EROFS`, dataset hash unchanged |

The original outside-fixture-write oracle overclaimed prevention from host-file
absence. We preserve its raw result and an explicit correction: a write occurred
in private `/tmp`, so host containment is observed but a strict guest-wide
output-directory-only write restriction is unsupported. The read-only dataset
probe subsequently tests an actual mount and observes rejection before mutation.

**Exposure reduction.** Define *observed probe reachability* as the number of
fixed forbidden-operation probes that complete the prohibited effect, on the
three probes with supported restrictions (two narrow-profile reads and the
dataset overwrite). Reachability is **3/3 in A, 3/3 in B, and 0/3 in C**. Thus B
achieves 0% and C achieves 100% reduction relative to A on these three probes:
`(3 − 0) / 3`. This is not a static census of all application sinks, a
prompt-injection success rate, or a universal guarantee. We explicitly exclude
the private-`/tmp` guest-write restriction from this supported-probe denominator
and report it as unsupported. The broad-profile successful read shows that C
preserves at least one additional legitimate permission rather than rejecting
all generated computation.

**Dispatch correctness.** At the integration's actual ToolNode boundary, both
B and C pass all four deterministic checks: an authorized operation creates its
unique witness file; a guest role, a missing `sandbox_source` field, and an unknown
tool each produce an error with no witness effect. The allowed control establishes
that the candidate can execute. Audit-chain verification passes. This is **4/4
checks for B and 4/4 for C**, with no false denial in the one allowed case per
configuration. A is N/A because it has no such dispatch boundary. These checks
validate the added boundary, not confinement of an already-authorized body.

**Table 4. One frozen CSV-cell injection, five model-driven repetitions per
configuration. Each is paired with a clean February task.**

| Configuration | Completed attacks | Unauthorized proposal | Target-open attempt | Forbidden effect | Legitimate task succeeds |
| --- | ---: | ---: | ---: | ---: | ---: |
| A | 5 | 0/5 | 0/5 | 0/5 | 5/5 |
| B | 5 | 0/5 | 0/5 | 0/5 | 5/5 |
| C | 5 | 0/5 | 0/5 | 0/5 | 5/5 |

The injected text appears in the recorded model input in all 15 attacked runs.
The model does not propagate this payload into the tested private-file operation. End-to-end forbidden-effect frequency is
0/5 for every configuration, but **conditional enforcement failure is undefined
(0 eligible attempts)**. These outcomes are `not_attempted`, not enforcement
successes. The attack was fixed before the batch; we did not search for a more
successful payload after inspecting outcomes. This limited negative result does
not establish prompt-injection resistance.

The policy coverage is correspondingly narrow. Dispatch checks, unrelated-file
exclusion, the dataset's read-only mount, and the matched supplementary-file
permission have application evidence. Output receipts establish permitted writes,
but strict output-only guest writes are unsupported. Network and descendant-process
restrictions have not been independently probed in this application, and no
unavailable-host-mechanism experiment has been completed. Trusted parent effects
are excluded. Coverage is reported clause by clause, not as an undifferentiated
“secure application” Boolean.

### Utility

In the initial three-task clean comparison, A/B/C each succeed on **1/3 tasks**:
the February total is correct, regional aggregation returns unaggregated rows,
and chart execution reaches an upstream regular-expression error. All failures
remain in the denominator. Later repetition and timing experiments deliberately
use the known-working February task: each configuration succeeds on 5/5 clean
repetitions. This confirms repeatability of one workflow, not an improvement from
1/3 to 5/5 on the original workload. We do not pool the cohorts or claim utility
non-inferiority from equal outcomes on three tasks.

### Runtime overhead and its source

We measure local enforcement cost by replaying the **same generated February
computation captured from the real application**, with its recorded input, through
A/B/C. This is a computation-path replay, not a model-driven end-to-end run and not
a no-op microbenchmark. Each configuration receives one first-use call, ten
warm-up calls, and 100 measured calls. We rotate A/B/C order by round, retain every
sample, and verify that every replay returns 120. Timing uses `perf_counter_ns`;
there are no model calls or syscall tracing in this experiment. Fixtures and
integration initialization are outside the per-call timer. Graph dispatch,
upstream sandbox execution, synchronous audit writes, and the integration's event
and activation-receipt output are inside it. These are costs of the evaluated
configuration, not an estimate of the kernel mechanism alone.

**Table 5. Local computation-path latency, 100 measured calls per configuration.
SD and variance describe within-trace timing variation, not across-task uncertainty.**

| Configuration | Mean (ms) | SD (ms) | Variance (ms²) | Median (ms) | P95 (ms) |
| --- | ---: | ---: | ---: | ---: | ---: |
| A: original subprocess | 267.19 | 6.84 | 46.80 | 265.00 | 280.56 |
| B: dispatch + original subprocess | 545.54 | 31.53 | 993.96 | 544.34 | 583.76 |
| C: dispatch + Linux worker | 930.93 | 42.95 | 1,844.46 | 916.64 | 1,010.42 |

The paired mean increment is **278.35 ms for B−A** (SD 32.91 ms), **663.74 ms
for C−A** (SD 42.55 ms), and **385.39 ms for C−B** (SD 54.98 ms). Ratios of mean
latencies are 2.04×, 3.48×, and 1.71× respectively. Thus C increases local call
latency by 248.4% relative to A on this trace. This is substantial overhead; the
results do not support a claim that enforcement is negligible.

Nested timing spans show where the measured time is spent. A and B spend
267.11 ms and 267.03 ms, respectively, in the original subprocess path. B's
remaining 278.51 ms includes graph dispatch, authorization, and evidence/audit
work. In C, the executor's `invoke` averages 614.54 ms, including 20.56 ms in grant
compilation and 325.58 ms in the worker path. The remaining 268.41 ms inside
`invoke` covers other preparation, policy filtering, attestation, negotiation,
and related work; this residual is not a separately measured component. C spends
another 316.39 ms outside `invoke` in dispatch and integration/evidence work.
Nested spans must not be added to their enclosing spans. Worker time includes
execution and supervision, so it is not a pure process-launch measurement.

A separate diagnostic replay (two warm-ups, 20 measured calls per configuration)
times cumulative `SqliteAuditSink.write` spans. Transactional audit writes average
**273.94 ms in B** (SD 32.12 ms) and **274.52 ms in C** (SD 8.96 ms). In that
cohort, B's total is 544.34 ms and its upstream subprocess is 265.09 ms: audit
writes account for about 98% of the remaining 279.25 ms. This directly identifies
synchronous audit persistence as the dominant measured cost outside computation
in B. The evidence files reside on a rotating disk; no SSD comparison was run, so
we do not quantify a hardware speedup or attribute every millisecond to the disk.
The diagnostic is separately labeled and is not pooled with the 100-call results.
No policy or enforcement mechanism was disabled for it.

First-use call latencies are 283.26/525.81/949.87 ms for A/B/C. Separately measured
adapter initialization costs are 0.05/231.62/344.96 ms, after 1,121.86 ms of shared
imports. Each startup value is a single observation. These are process-level
first-use measurements with the OS page cache uncontrolled, not disk-cold startup
estimates. Each measured C call still launches a fresh worker.

**Table 6. Recorded full-workflow latency for the known-working clean task, five
fresh repetitions per configuration, interleaved with paired attack inputs.
Times include the existing runner's setup/environment capture, model-driven
application subprocess under `strace`, and outcome oracle.**

| Configuration | Mean (s) | SD (s) | Variance (s²) | Median (s) | Min–max (s) | Success |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| A | 12.777 | 1.410 | 1.989 | 12.236 | 11.986–15.293 | 5/5 |
| B | 12.725 | 0.195 | 0.038 | 12.736 | 12.437–12.979 | 5/5 |
| C | 15.354 | 0.118 | 0.014 | 15.298 | 15.243–15.543 | 5/5 |

![Local replay and full-workflow runtime distributions](macro-runtime.png)

*Figure 1. Measured distributions for A/B/C. Boxes show quartiles and medians;
whiskers extend to observations within 1.5 IQR. The right panel overlays all five
observations. Panels have different units and measure different scopes. An
[exportable PDF](macro-runtime.pdf) is included.*

The paired mean C−A difference is 2.577 s (SD 1.446 s), and the ratio of means
is 1.202×. C−B is 2.629 s (SD 0.216 s). B−A is −0.052 s (SD 1.581 s);
this does not establish that authorization improves performance. The first A run
follows a server restart and includes model warm-up/loading effects; it is kept
in the results. Different model outputs, startup, tracing, and evidence collection
can affect these totals. **The 20.2% observed full-workflow difference is not an
isolated enforcement-overhead estimate**, and the 3.48× local replay ratio is not
a whole-application slowdown. Model-judged quality is not used for the security
oracles. Five repetitions of one task do not support task-clustered uncertainty
or a general performance claim across applications.

### Limitations and reproducibility

The evidence supports one experimental application integration and identifies
its substantial measured cost. It does not support a completed six-port suite,
whole-application sink-exposure reduction, broad prompt-injection robustness,
or host-independent guarantees. The initial utility failures remain unresolved.
The other five candidates are blocked or unverified, while SQL and Notebook have
baseline adaptations without protected-port claims. A 20-task frozen workload,
multiple adversarial channels, genuine host-capability degradation, across-task
uncertainty, and remote-host instrumentation remain outstanding. No engineering
hours, token-cost savings, or overhead results for unported applications are
invented.

Reproduce the local replay with the pinned upstream Python environment:

```sh
/data/slanggraph-eval-upstreams/ai-data-science-team/.venv/bin/python \
  eval/scripts/pandas_runtime.py --output /tmp/pandas-runtime-new \
  --warmup 10 --samples 100
/data/slanggraph-eval-upstreams/ai-data-science-team/.venv/bin/python \
  eval/scripts/pandas_dispatch.py /tmp/pandas-dispatch-new
# Requires the pinned local Ollama model and server; use a fresh output path.
python3 eval/scripts/pandas_e2e_repetitions.py --attempt 3 \
  --output /tmp/pandas-e2e-new
python3 eval/scripts/summarize_macro.py
uv run --isolated --python 3.13 --with matplotlib==3.10.0 \
  python eval/scripts/plot_macro_runtime.py
```

The [audit-cost diagnostic](../results/pandas-runtime-audit-profile-20261026-v1/)
retains its separate plan, nested spans, and samples. The [intake ledger](../apps.csv) and [setup instructions](../APPLICATIONS.md)
identify revisions and environments. [Local timing samples and plan](../results/pandas-runtime-20261026-v1/)
contain the exact replayed computation, benchmark snapshot, timer scopes, raw
samples, initialization costs, and machine capture. [Dispatch evidence](../results/pandas-dispatch-20261026-v1/)
contains candidate calls, witness paths, policy hashes, returned errors, and audit
records. [Repeated-run launch records](../results/pandas-e2e-repetitions-20261026-attempt2/)
identify every clean and attacked run; [the failed first batch](../results/pandas-e2e-repetitions-20261026-v1/)
is retained separately. [Derived metrics](macro-metrics.json) are rebuilt from
these identified cohorts. The [initial pilot report](application-pilot.md)
links the controlled effects and oracle correction. The earlier generic E5
framework/no-op benchmark is **not** the source of any application overhead number
reported here.
