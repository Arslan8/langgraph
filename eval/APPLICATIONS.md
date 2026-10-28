# Local-model application evaluation

This is a separate application study within the existing `eval/` artifact (the
assignment's `evaluation/` paths map to `eval/`). It does not reuse synthetic E1/E2
results as application evidence. The shortlist contains **eight applications from
seven repositories**; Pandas and SQL share one repository. Completed protected
ports: **zero**. See [apps.csv](apps.csv) for intake and [results/](results/) for raw
pilot attempts, including failures. Six ports remain an aspiration, not a result.

Only local models are in scope, following the user's October 25 instruction.
No OpenAI/Anthropic hosted calls or credentials are used. `ChatOpenAI` in the two
headless adapters is an HTTP client for **local Ollama**, not the OpenAI service.
Applications requiring hosted models without a usable local configuration remain
excluded/blocked. Upstream model-specific behavior is not claimed to be reproduced
by changing the provider.

## What is implemented

- Source intake for every candidate: full SHA, license text/hash, graph symbols,
  commit-pinned links, effect inventory, dependency input hashes and resolved packages.
- Isolated dependency installation attempts with raw logs. Email resolution fails;
  other environments installed, which alone does not establish reproducibility.
- Pandas/SQL headless backend adapters and an Open Notebook API adapter, fresh synthetic fixtures, unique canaries,
  local-model manifest, independent value/database oracles, per-attempt evidence.
- A runner that records unsupported B/C configurations without executing an
  unprotected fallback. Fixed manifests/policy intent are hashed before dispatch.
- Raw local model callbacks and descendant syscall metadata through `strace -f`.
  This is observation, not enforcement. SQL trace callbacks cover the fixture
  connection, not arbitrary connections a generated program might create.
- Pilot count reconstruction and fixture/oracle regression tests.

Pandas now has experimental A/B/C adapters, controlled implementation pilots,
deterministic dispatch checks, and one repeated CSV-cell attack case. Runtime
measurements and host details are in [the expanded evaluation](reports/paper-macrobenchmarks.md).
B uses an explicitly added node boundary; C uses the existing Linux executor.
See [the pilot report](reports/application-pilot.md) for scope and evidence.

Not implemented: a completed six-port suite, a broad adversarial-content matrix, service doubles, a 20-task
freeze, multi-task comparisons, clustered uncertainty, suite-wide overhead study, or
remote-host instrumentation. Non-sales smoke entries are explicitly unfrozen
placeholders. Pandas policy v3 is deployable; other application policies remain planning documents.

## Checkout and dependency reproduction

Use a separate directory, for example `/data/slanggraph-eval-upstreams`. For each
unique repository in `apps.csv`, clone its URL then check out the recorded SHA:

```sh
git clone https://github.com/business-science/ai-data-science-team.git /data/slanggraph-eval-upstreams/ai-data-science-team
git -C /data/slanggraph-eval-upstreams/ai-data-science-team checkout --detach 4ffeb7f38178aa250917f29b01355f8b89ba809e
cd /data/slanggraph-eval-upstreams/ai-data-science-team
uv venv --python 3.13 .venv
uv pip install --python .venv/bin/python . -r apps/pandas-data-analyst-app/requirements.txt -r apps/sql-database-agent-app/requirements.txt
uv pip install --python .venv/bin/python -r /data/langgraph/eval/apps/pandas/patches/compatibility-requirements.txt
```

The commands above reproduce dependency *resolution*, which can drift. To reproduce
the captured environment exactly, install `apps/pandas/resolved.txt` with `uv pip
sync --python ...` after reconstructing the pinned checkout at its recorded path;
the freeze includes that local package path. Other candidates have per-app setup
commands and resolved files. Preserve all upstream lockfiles. The intake script
captures new environment evidence; do not overwrite a published intake to conceal
a changed environment. Snapshot/version it first.

```sh
cd /data/langgraph
python3 eval/scripts/application_intake.py --checkouts /data/slanggraph-eval-upstreams
```

`intake/host.json` records kernel, Python/Node, bubblewrap namespace probe,
libseccomp discovery, slangGraph HEAD and dirty source state. This checkout had
pre-existing uncommitted security changes: HEAD alone does not identify the
implementation. Pandas/SQL use no container image; Notebook uses a pinned SurrealDB image (see its intake). Namespace availability is not an
activation receipt or evidence of a successfully confined application.

## Local pilot reproduction

Start Ollama in a separate terminal if it is not already running:

```sh
ollama serve
```

The frozen pilot uses the installed `qwen3:8b` model. Its complete manifest digest
is checked against `/api/tags` before launch. Do not silently substitute a tag's
new content. A new model, fixture, policy or resource setting needs a new manifest
and a new attempt. llama.cpp is an alternative provider for future versioned
manifests; it is not implemented or measured by this adapter yet.

```sh
cd /data/langgraph
uv run --project eval python eval/run.py --app pandas --configuration C --case february --repetition 1 --attempt 1 --manifest-version v8 --checkouts /data/slanggraph-eval-upstreams
uv run --project eval python eval/run.py --app sql --configuration A --case region-totals --repetition 1 --attempt 1 --manifest-version v4 --checkouts /data/slanggraph-eval-upstreams
uv run --project eval python eval/summarize.py
cd eval
make format
make lint
make test
```

Pandas pilot cases: `region-totals`, `february`, `monthly-chart`. SQL pilot cases:
`region-totals`, `february`, `total`. The command accepts configuration A/B/C,
case, repetition, attempt and narrow/broad profile. Pandas v7/v8 supports A/B/C. Other applications and earlier manifests record
unsupported B/C without running A under another name.
Exit zero requires an independently successful task.

Open Notebook's `smoke` case uses its original text-ingestion and source-chat APIs
with a dedicated SurrealDB and worker. See [its README](apps/notebook/README.md)
for service startup. It uses locally installed `llama3:latest`, not a service double.

Each result directory stores configuration, host/model identity, policy/manifest
hashes, request, command, fixture location, stdout/stderr, callback events,
descendant syscall trace, output, oracle and timings where execution reached those
stages. Missing stages remain visible. The fixture is a fresh temporary directory
and is retained for inspection; it is never reused on retry. Observer files are
outside it, but share the host UID and are **not tamper-resistant** against arbitrary
baseline code. Security conclusions require the independent effect oracle and, for C, activation
evidence. Logs alone do not establish prevention.

Manifest v2 records a single-CPU affinity setting for the application and child
processes, keeping upstream sandbox caps intact. GPU inference remains in the
separate Ollama process. Initial v1 failures are preserved. Adapter-debugging
attempts are pilots, not paper measurements. Model response metadata may name
`openai` because of the client protocol; the recorded endpoint is local Ollama.

Sales manifest v3 raises the request timeout to 600 seconds after observed local
inference timeouts. V4 additionally requests `reasoning_effort=none`, a separate
model-setting pilot using the [documented local Ollama interface](https://docs.ollama.com/api/openai-compatibility).
Do not pool those settings for comparisons. The summary groups by manifest and
policy hash. Notebook manifest versions are application-specific: its v3 corrects
worker scope metadata and records observed upstream sampling defaults.

Later runs snapshot harness sources, environment freeze and intake before launch.
Early adapter-debug attempts lack complete source snapshots; `source-recovery.json`
records which files could be recovered by matching their pre-run hashes. Those
early attempts are not exact reproducible paper measurements. Raw failures are
retained, including provider timeouts classified from their saved traceback.

## Completion gates and limitations

Both sales applications use direct graph-node effects. Pandas B is an explicitly
added node-dispatch adapter, not a native tool-dispatch-only ablation. C retains
the original sandbox program and its checks but runs it in the existing fresh
Linux worker instead of nesting another subprocess. Original prompts and graph
sources are unchanged. A/B/C v7 use the same local core/prebuilt source overlay;
native installed-LangGraph pilots remain separate.

SQL B/C were executed in RM1: A/B/C each passed 50/50 utility trials, while the
canary appeared in model input for A 26/50, B 27/50 and C 0/50. B adds call
authorization while retaining the upstream effects; only C used the
evaluation-harness bounded SELECT mediator in `remaining/bounded_sql.py`.
Production's `sqlite_record_mediator` still supports only the fixed
`records(key,value)` schema, so SQL C remains unsupported in production until a
general mediator is promoted into `security/mediators/`. Metadata sampling also
reads restricted rows before generated queries. See the RM1 cohort, the
source-backed intake and `intake/sql-observations.json`.

Before attacks, complete a baseline, validate independent oracles against allowed
and deliberately wrong outputs, write enforceable clause mappings and both useful
profiles, and implement the actual existing-interface integration. No generated
computation may be removed to manufacture a successful port. A/B/C policy intent
must stay matched; unsupported clauses stay visible. Email, research, notebook,
coding, newspaper and historical finance retain their fixed order and concrete
next actions in their intake records. No replacement applications were searched.

Only pilot attempt counts are summarized. There is no scheduled large-study task
list, so the summary does not claim a clean-success denominator over scheduled
tasks, paired utility, ASR, false-denial rate, uncertainty or local overhead. Those
analyses must be added after the relevant configurations and workload are frozen.
