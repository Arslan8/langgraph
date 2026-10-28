# Frozen evaluation handoff

Start with `RESULTS.md`, `coverage.csv` and `FAILURES.md`. Unsupported coverage and failed verification gates are results, not hidden successes. `completed-v2/` preserves the prior handoff unchanged; its “remaining tasks pending” wording is historical and is superseded by this root report.

## Regenerate without executing benchmarks

From this extracted directory, Python 3.11+ standard library suffices for all numerical summaries and record validation:

```bash
python3 scripts/summarize.py .
python3 scripts/supplement.py .
python3 completed-v2/regenerate.py --reports completed-v2/raw --output ../regenerated-v2
uv run --no-project --with matplotlib==3.10.7 python scripts/plots.py .
uv run --no-project --with matplotlib==3.10.8 python completed-v2/scripts/plot_handoff.py ../regenerated-v2
```

`../regenerated-v2` must not exist. These commands regenerate derived files only; they do not rerun a model or overwrite original raw runs. Application costs use paired task-mean bootstrap intervals; new microbenchmark increments use five paired session means and Student t with four degrees of freedom. First-use/warmups are retained and excluded from the 100 measured calls/mode. Every exported application task cell lists its run IDs; mechanism cells list JSONL line references. `summaries/raw-index.jsonl` and `raw-schema-gaps.json` make metadata joins and omissions explicit.

Check archive integrity before regeneration:

```bash
python3 scripts/verify_package.py .
```

The vector figures use Times-compatible STIX text. PDFs and SVGs are supplied. Figure source data and generating code are included. The amortization figure is a model derived from original v2 setup/invocation/teardown means, not a measured cold-container curve.

## Restore the experimental code

Do this in a **new empty checkout**, not over a working tree or evidence directory. Keep `evidence` as an absolute path to this extracted archive:

```bash
mkdir reconstructed
cd reconstructed
tar -xzf "$evidence/configurations/base-source.tar.gz"
tar -xzf "$evidence/configurations/release-overlay.tar.gz"
tar -xzf "$evidence/configurations/source-overlay.tar.gz"
mkdir -p eval/remaining
cp "$evidence"/configurations/executed-sources/*.py eval/remaining/
```

The clean base is `40e24e978f9ec2e8f061abb21077e2251583f5e5`. It alone is not the experimental revision. The explicit overlays contain the imported production code and evaluation code. `executed-sources/` retains the bytes used in the main cohorts, before later reporting/style cleanup; SQL runtime source hashes are checked against its plan. Current cleaned reporting scripts are under `scripts/`. The original v2 archives remain independently frozen. Do not substitute reconstructed current sources for a historical cohort.

Runtime experiments used Linux with Landlock ABI7, libseccomp, rootless Docker 29.9.2, Python 3.13.11 and Ollama. Host probes, image identity, mounts, security profiles, resource limits and dependency freezes are in configurations and raw plans/lifecycle records. New performance results are shared-host observations, not idle-host measurements. Per-session host captures missing from historical data remain missing.

Restore the clean upstream archives into `/data/slanggraph-eval-upstreams/ai-data-science-team` and `/data/slanggraph-eval-upstreams/open-notebook` (or update the explicitly recorded path constants for a new cohort). Their full source IDs and archive hashes are in `configurations/upstream-sources.json`. The application upstream working trees were clean. Dependency files contain absolute local package references; preserve those paths or deliberately update them and record a new configuration:

```bash
uv venv --python 3.13.11 libs/prebuilt/.venv
uv pip sync --python libs/prebuilt/.venv/bin/python "$evidence/configurations/prebuilt-dependencies.txt"
uv venv --python 3.13.11 /data/slanggraph-eval-upstreams/ai-data-science-team/.venv
uv pip sync --python /data/slanggraph-eval-upstreams/ai-data-science-team/.venv/bin/python "$evidence/configurations/application-dependencies.txt"
```

The pinned qwen3:8b digest is in `release.json` and the task plans. Do not silently substitute another model. The local image digest is `sha256:3bcfa1622e24814afee022c71236dadd92e31a5fff41ad99a23925bc98311504`; an unavailable image/model is a setup blocker, not permission to publish a matching-label replacement.

## Explicit experiment entry points

These commands are for a **new campaign only**, after inspecting configuration and restoring sources/dependencies. They are not needed to validate this handoff. Output paths must be new. Run from the reconstructed repository root:

```bash
export PYTHONPATH=libs/prebuilt:libs/langgraph:eval/remaining:eval/scripts:eval/src
libs/prebuilt/.venv/bin/python eval/scripts/repeat_mechanism_tests.py --output fresh/production-repeats --repetitions 20
libs/prebuilt/.venv/bin/python eval/remaining/grant_matrix.py --output fresh/grant-matrix
libs/prebuilt/.venv/bin/python eval/remaining/capability_config.py --output fresh/capability-configurations
libs/prebuilt/.venv/bin/python eval/remaining/manifest_mac.py --output fresh/manifest-mac
libs/prebuilt/.venv/bin/python eval/remaining/broker_mac.py --output fresh/broker-mac
libs/prebuilt/.venv/bin/python eval/remaining/composition.py --output fresh/sqlite-composition --repetitions 20
libs/prebuilt/.venv/bin/python eval/remaining/pump_composition.py --output fresh/pump-composition --repetitions 20
libs/prebuilt/.venv/bin/python eval/remaining/container_lifecycle.py --output fresh/container-lifecycle
libs/prebuilt/.venv/bin/python eval/remaining/typed_costs.py --output fresh/typed-costs
libs/prebuilt/.venv/bin/python eval/remaining/cold_container.py --output fresh/cold-container
libs/prebuilt/.venv/bin/python eval/remaining/producer_evaluation.py fresh/producer
python3 eval/remaining/application_campaign.py --output fresh/pandas --repetitions 5
python3 eval/remaining/sql_campaign.py --output fresh/sql --repetitions 5
```

The application driver invokes the pinned upstream virtualenv. SQL negative probes, alias setup probes and comparator probes have explicit output constants in their archived scripts: select a new empty campaign root before invoking them. Comparator clean archives include manifests/lockfiles. Nono/Sandlock built with Rust 1.95.0; exact commands/settings are retained in build logs and trial `command` arrays. Progent/CaMeL use the official local packages with offline deterministic policies (`SECAGENT_GENERATE=false`). `configurations/apf_probe/` contains the independent harness, lockfile and official path dependencies for evaluator and OpenShell projector; restore vendor archives under the documented relative paths before building.

The prebuilt gate commands, complete logs, wall durations and exit statuses are under `raw/library-gates/`. Formatting made no prebuilt source changes. No library code was introduced by this evaluation; pre-existing repository changes were preserved. The release includes separate cleaned-harness lint and focused SQL/oracle test logs.

## Evidence organization

- `configurations/`: source archives/overlays, dependencies, host/model identities and comparator source pins.
- `raw/`: all trials, failed pilots, model requests/responses, SQLite audit files, resource snapshots, receipts, lifecycle observations and complete logs.
- `summaries/`: regenerated counts, uncertainty, oracles, source correspondence, schema gaps and verification reconciliation.
- `worked-example/`: actual production Alice/Bob authorization/enforcement chain.
- `claims.csv`, `coverage.csv`, `backend-map.csv`, `tasks.json`, `integration.csv`: scope and implementation indexes.

Absolute paths inside raw records are historical evidence and may no longer exist. Use run IDs and packaged relative files to resolve evidence. Neither a missing field nor a skipped phase is silently converted into successful enforcement. Engineering time before prospective tracking is unrecorded; the timestamp span is not a labor-hour estimate.
