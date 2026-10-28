# Matched Pandas complete-system overhead campaign

This campaign compares reader-facing `Baseline` and `slangGraph` conditions on
the same ten Pandas tasks with five paired repetition blocks. `Baseline` is the
adapted application with direct dataset loading and native vendor computation;
it installs no slangGraph enforcement. `slangGraph` is internal configuration
`C-full-lean` with every protection and runtime check enabled.

The raw artifact is `raw/`. Its `plan.json` and `preflight.json` freeze the
common settings, treatment difference, task order, dataset/source identities,
model warmup, timer, timeout treatment, and internal configuration names.
`trials.jsonl` retains every attempt and its task/repetition pairing.

The campaign was run from framework revision
`ff671388bdf034077f394bac439e4edb5fcb05d3`; the harness sources used by each
subprocess are frozen under `raw/harness/` and hashed in `preflight.json`.
`raw/workerRoute` is the selected 122 MB Lean executable and is identified by
SHA-256 in `plan.json`; it is retained in the local artifact but omitted from
Git because it exceeds the hosting limit.

Regenerate the statistics and graph with:

```sh
libs/prebuilt/.venv/bin/python eval/apps/pandas/analyze_matched.py \
  --raw eval/campaigns/pandas-matched-v1/raw \
  --output eval/campaigns/pandas-matched-v1
libs/prebuilt/.venv/bin/python eval/apps/pandas/validate_matched.py \
  eval/campaigns/pandas-matched-v1/raw \
  --output eval/campaigns/pandas-matched-v1/validation.json
```

The interval is a paired repetition-block percentile bootstrap, not a
task-level interval. `C-full` remains a checks-disabled supporting ablation and
is not the Baseline.
