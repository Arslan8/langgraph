# research application intake

Status: **baseline intake / pilot work; no completed port**.

Repository: https://github.com/langchain-ai/open_deep_research

Pinned SHA: `1b7d2e80db9faa586165c60e09096dbbfd483a64`. Retrieved: 2026-10-26T00:10:30.649349+00:00. License text and SHA-256 are in `intake.json`; dependency inputs and the resolved environment are recorded there and in `resolved.txt`. GitHub archive status: `True` (API captured during intake). 

## Executable path and effects

langgraph.json -> src/open_deep_research/deep_researcher.py: deep_researcher

Supervisor/researcher StateGraphs; tool.ainvoke in researcher_tools; search provider and remote MCP effects in utils.py; model calls and report synthesis. Local request mediation does not confine remote services.

- [langgraph.json](https://github.com/langchain-ai/open_deep_research/blob/1b7d2e80db9faa586165c60e09096dbbfd483a64/langgraph.json)
- [src/open_deep_research/deep_researcher.py](https://github.com/langchain-ai/open_deep_research/blob/1b7d2e80db9faa586165c60e09096dbbfd483a64/src/open_deep_research/deep_researcher.py)
- [src/open_deep_research/utils.py](https://github.com/langchain-ai/open_deep_research/blob/1b7d2e80db9faa586165c60e09096dbbfd483a64/src/open_deep_research/utils.py)
- [src/open_deep_research/configuration.py](https://github.com/langchain-ai/open_deep_research/blob/1b7d2e80db9faa586165c60e09096dbbfd483a64/src/open_deep_research/configuration.py)
- [tests/run_evaluate.py](https://github.com/langchain-ai/open_deep_research/blob/1b7d2e80db9faa586165c60e09096dbbfd483a64/tests/run_evaluate.py)

This inventory is source-backed, not a completed runtime trace. Missing paths, if any, are explicitly marked in `intake.json`. No dependency declaration alone is counted as graph evidence.

## Setup attempted

Run in the separate checkout, never this directory:

```sh
uv sync --frozen
```

Install logs: `../../intake/`. Upstream lockfiles are unchanged; pip-based installs record a resolved freeze rather than claiming to use a Poetry lock. No container image was used.

## Current blocker / next action

Dependencies installed. No dedicated search-provider credential or frozen contract-preserving search/MCP corpus configured. No clean report attempted; source inspection is not reproduction.

Configure dedicated search service or frozen contract-preserving corpus double and supported local structured-output model. Existing benchmark requires LangSmith; label any subset.

## Experimental scope

Only local models are allowed. No hosted-model credentials or personal service accounts were used. `cases.jsonl` contains pilot tasks or a labeled unfrozen smoke placeholder, not a completed security matrix. `policy/` files are intent/planning documents until a mapping is validated; hashes do not establish enforcement. No attack case has been run. B/C availability is recorded in each manifest.
