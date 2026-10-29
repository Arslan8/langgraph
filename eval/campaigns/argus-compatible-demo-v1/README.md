# Argus compatible ordinary-demo pilot

Prerequisites: the pinned `qwen3:8b` model server at `127.0.0.1:11434`, the
Pandas campaign's retained `workerRoute`, and the evaluation virtual
environment.

Run from the repository root:

```bash
PYTHONPATH=libs/prebuilt:libs/langgraph:libs/checkpoint \
  /data/slanggraph-eval-upstreams/ai-data-science-team/.venv/bin/python \
  eval/campaigns/argus-compatible-demo-v1/run_pilot.py
```

The pilot runs five tasks once in each mode, in a seeded interleaving. It is a
compatibility check, not the five-repetition performance campaign, so its
runtime ratio has no confidence interval and must not be used as a paper
headline.

Run the broader ten-example compatibility survey with:

```bash
PYTHONPATH=libs/prebuilt:libs/langgraph:libs/checkpoint \
  /data/slanggraph-eval-upstreams/ai-data-science-team/.venv/bin/python \
  eval/campaigns/argus-compatible-demo-v1/run_expanded.py
```

This preserves completed raw records and process-level failure traces under
`raw/expanded/` and regenerates `expanded_statistics.json`.
