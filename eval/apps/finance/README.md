# finance application intake

Status: **baseline intake / pilot work; no completed port**.

Repository: https://github.com/virattt/ai-hedge-fund

Pinned SHA: `6c41ae8cf5fb4e30eb8cdb6a816eb56ff234989d`. Retrieved: 2026-10-26T00:10:30.649349+00:00. License text and SHA-256 are in `intake.json`; dependency inputs and the resolved environment are recorded there and in `resolved.txt`. **Historical revision.** Current HEAD 29b32f71861480e9bfd48b82cf0d3ca3e5680955 lacks StateGraph workflow. Selected 6c41ae8cf5fb4e30eb8cdb6a816eb56ff234989d, parent of a7a99e5b4cbbe789f4e16bd02d794e86a2a3a3d2 which removed src/main.py. This is a candidate historical pin, not a claim of last reproducible release.

## Executable path and effects

src/main.py:run_hedge_fund -> create_workflow -> compile -> invoke

Historical LangGraph analyst workflow; requests GET/POST to financial data provider, local cache, model calls, optional graph PNG. Analysis only; no brokerage or real-money trading.

- [src/main.py](https://github.com/virattt/ai-hedge-fund/blob/6c41ae8cf5fb4e30eb8cdb6a816eb56ff234989d/src/main.py)
- [src/tools/api.py](https://github.com/virattt/ai-hedge-fund/blob/6c41ae8cf5fb4e30eb8cdb6a816eb56ff234989d/src/tools/api.py)
- [src/llm/models.py](https://github.com/virattt/ai-hedge-fund/blob/6c41ae8cf5fb4e30eb8cdb6a816eb56ff234989d/src/llm/models.py)
- [src/agents/portfolio_manager.py](https://github.com/virattt/ai-hedge-fund/blob/6c41ae8cf5fb4e30eb8cdb6a816eb56ff234989d/src/agents/portfolio_manager.py)

This inventory is source-backed, not a completed runtime trace. Missing paths, if any, are explicitly marked in `intake.json`. No dependency declaration alone is counted as graph evidence.

## Setup attempted

Run in the separate checkout, never this directory:

```sh
git checkout --detach 6c41ae8cf5fb4e30eb8cdb6a816eb56ff234989d
uv venv .venv
uv pip install --python .venv/bin/python -e .
```

Install logs: `../../intake/`. Upstream lockfiles are unchanged; pip-based installs record a resolved freeze rather than claiming to use a Poetry lock. No container image was used.

## Current blocker / next action

Historical dependencies installed. No recorded Financial Datasets provider responses or dedicated service credential configured. No workflow or trading operation attempted. Historical pin is not yet proven reproducible.

Freeze financial-provider responses and local model settings; run historical analysis only. Reproducibility of selected historical revision remains unverified.

## Experimental scope

Only local models are allowed. No hosted-model credentials or personal service accounts were used. `cases.jsonl` contains pilot tasks or a labeled unfrozen smoke placeholder, not a completed security matrix. `policy/` files are intent/planning documents until a mapping is validated; hashes do not establish enforcement. No attack case has been run. B/C availability is recorded in each manifest.
