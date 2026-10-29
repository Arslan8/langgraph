# Argus evaluation of ordinary LangGraph demos

This campaign freezes five historical upstream applications at
`23961cff61a42b52525f3b20b4094d8d2fba1744`, runs every Baseline task once,
and attempts full Argus integration without redesigning the applications.

The baseline preflight results are 2/5 (D1), 5/5 (D2), 0/5 (D3), 5/5
(D4), and 4/5 (D5). All five full-Argus integrations are unsupported at the
boundaries in `CONFIGURATIONS.md`. Consequently, the paired 50-trial timing
protocol was not started and no overhead ratio is reported.

Regenerate and validate the result files from retained evidence with:

```sh
eval/campaigns/langgraph-demos-v1/reproduce.sh
```

The full preflight commands are the five executable adapters under
`eval/apps/demos/`; exact prompts and oracles are in `tasks.json`. Raw outputs,
process traces, chart observers, interrupt decisions, and database before/after
snapshots are retained under `preflight/`, `integration-probes/`, and
`raw/preflight.jsonl`.

The tutorial travel database is 114 MB uncompressed. Git retains its 30 MB
gzip (`fixtures/customer-support/travel2.sqlite.gz`) and SHA-256; the local
campaign additionally retains the uncompressed input and per-run reset copies.
Those large SQLite copies are omitted from the pushed commit. Recreate the
input with `gzip -dk travel2.sqlite.gz` before rerunning D5.
