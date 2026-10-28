# pandas application intake

Status: **baseline intake / pilot work; no completed port**.

Repository: https://github.com/business-science/ai-data-science-team

Pinned SHA: `4ffeb7f38178aa250917f29b01355f8b89ba809e`. Retrieved: 2026-10-26T00:10:30.649349+00:00. License text and SHA-256 are in `intake.json`; dependency inputs and the resolved environment are recorded there and in `resolved.txt`. 

## Executable path and effects

app.py: pandas_data_analyst.invoke_agent

Model calls in graph nodes; generated computation in utils/sandbox.py:run_code_sandboxed_subprocess; Streamlit upload and session storage outside graph. Preserve import/builtin restrictions, network patch, timeout and resource caps.

- [ai_data_science_team/multiagents/pandas_data_analyst.py](https://github.com/business-science/ai-data-science-team/blob/4ffeb7f38178aa250917f29b01355f8b89ba809e/ai_data_science_team/multiagents/pandas_data_analyst.py)
- [ai_data_science_team/agents/data_wrangling_agent.py](https://github.com/business-science/ai-data-science-team/blob/4ffeb7f38178aa250917f29b01355f8b89ba809e/ai_data_science_team/agents/data_wrangling_agent.py)
- [ai_data_science_team/agents/data_visualization_agent.py](https://github.com/business-science/ai-data-science-team/blob/4ffeb7f38178aa250917f29b01355f8b89ba809e/ai_data_science_team/agents/data_visualization_agent.py)
- [ai_data_science_team/templates/agent_templates.py](https://github.com/business-science/ai-data-science-team/blob/4ffeb7f38178aa250917f29b01355f8b89ba809e/ai_data_science_team/templates/agent_templates.py)
- [ai_data_science_team/utils/sandbox.py](https://github.com/business-science/ai-data-science-team/blob/4ffeb7f38178aa250917f29b01355f8b89ba809e/ai_data_science_team/utils/sandbox.py)

This inventory is source-backed, not a completed runtime trace. Missing paths, if any, are explicitly marked in `intake.json`. No dependency declaration alone is counted as graph evidence.

## Setup attempted

Run in the separate checkout, never this directory:

```sh
uv venv .venv
uv pip install --python .venv/bin/python . -r apps/pandas-data-analyst-app/requirements.txt -r apps/sql-database-agent-app/requirements.txt
uv pip install --python .venv/bin/python -r /data/langgraph/eval/apps/pandas/patches/compatibility-requirements.txt
```

Install logs: `../../intake/`. Upstream lockfiles are unchanged; pip-based installs record a resolved freeze rather than claiming to use a Poetry lock. No container image was used.

## Integrated pilot

The original bundled backend runs with local Ollama qwen3:8b. See
[the evidence report](../../reports/application-pilot.md) and
[setup commands](../../APPLICATIONS.md). No hosted model service is used.

```sh
cd /data/langgraph
uv run --project eval python eval/run.py --app pandas --configuration C --case february --repetition 1 --attempt 1 --manifest-version v8 --profile narrow --checkouts /data/slanggraph-eval-upstreams
```

A invokes the original subprocess sandbox. B adds an explicit node-dispatch
ToolNode boundary and invokes the original subprocess. C runs the original
sandbox program inside the existing LinuxSandboxExecutor fresh worker; it does
not nest the original subprocess. AST/import/builtin/network checks and resource
caps remain. This launch adaptation is required because the minimal executor
prohibits child creation. The original graph nodes and prompts are unchanged.
All three integrated configurations use the same recorded local core/prebuilt
source overlay. The earlier native-package baselines are separate cohorts.

`integration.py` replaces two helper aliases at import time. `worker.py` loads the
upstream sandbox program. `fault_variant` is explicitly enabled only for controlled
implementation cases and runs the legitimate function plus one effect. It is not
a finding about malicious upstream code. No upstream checkout file is edited.

Frozen v7 pilot: three clean tasks across A/B/C, three controlled effects across
A/B/C narrow, plus matched supplementary read across A/B/C broad. v8 adds a
read-only dataset overwrite diagnostic after a private-/tmp write oracle correction.
Policy v3 was fixed before these runs. v5/v6 failed integrations remain recorded.

The February task passes across configurations. Region aggregation fails its
value oracle; chart execution reaches an upstream malformed-regex error. These
are retained utility failures, not security successes. This is a pilot integration,
not a completed study or a full application confinement claim.

## Scope and limitations

Backend only: Streamlit authentication, upload, rendering and history excluded.
Local provider/model selection, synthetic fixture inputs, single-CPU affinity,
missing IPython dependency and JSON transport adaptation are recorded changes.
Generated computation remains enabled. Model calls and input loading occur in
the trusted parent, outside worker confinement. Installed packages/runtime roots
are readable and private `/tmp` writable. Output-only guest writes are therefore
not a supported blanket guarantee. See policy/mapping.csv for clause scope.

The expanded pilot adds four deterministic dispatch checks in B/C, one frozen
CSV-cell injection with five paired repetitions per configuration, and 100-call
local replay timing plus an audit-cost diagnostic. See the
[paper section](../../reports/paper-macrobenchmarks.md) for measured results.
No host-unavailability comparison or large workload is complete. Source snapshots
and raw failures are retained per run.

## Prospective remediation variants

`remaining/application_campaign.py` retains the original ten-task oracle and
records each new cohort separately. Manifest v19 selects the v5 request-preserving
workflow contract, recursive JSON v2, and `period-aggregation-v1`. Earlier
manifests and failed cohorts remain historical observations.

The computation API exposes `aggregate_periods(data, date_column, value_column,
operation="sum", frequency="M", bucket_column="period", result_column=None,
label_format=None, complete=True)` in all three sandbox configurations. It groups
original rows before filling missing calendar buckets and formatting labels.
Supported reductions are sum, mean, count, min and max; frequencies are D, W, M,
Q and Y. Missing dates and unsupported options fail explicitly. Empty sum/count
buckets contain zero; other empty reductions contain null after serialization.
The API receives data and column names, never task identifiers or oracle values.
Its globals use the upstream restricted builtins and existing Pandas/NumPy
bindings. Generated code still executes in the original upstream graphs and
sandbox routes. This evaluation integration is not a universal confinement proof.

`remaining/pandas_profile_campaign.py` profiles every task in configuration C
from an explicitly selected cohort snapshot. It checks the resulting output with
that cohort's preserved utility oracle and records policy/audit span coverage.
These intrusive, nested timings are separate from uninstrumented workflow times.
