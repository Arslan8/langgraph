# newspaper application intake

Status: **baseline intake / pilot work; no completed port**.

Repository: https://github.com/rotemweiss57/gpt-newspaper

Pinned SHA: `1c447b5672dd5ca8cd91a18bfa6daefe257c4fbe`. Retrieved: 2026-10-26T00:10:30.649349+00:00. License text and SHA-256 are in `intake.json`; dependency inputs and the resolved environment are recorded there and in `resolved.txt`. 

## Executable path and effects

app.py -> backend/graph.py:stream_newspaper / graph

StateGraph Send fans out article subgraphs; search and model SDK calls in nodes; publisher writes outputs; source photos or optional provider illustrations. Preserve source-as-untrusted prompts and retries.

- [app.py](https://github.com/rotemweiss57/gpt-newspaper/blob/1c447b5672dd5ca8cd91a18bfa6daefe257c4fbe/app.py)
- [backend/graph.py](https://github.com/rotemweiss57/gpt-newspaper/blob/1c447b5672dd5ca8cd91a18bfa6daefe257c4fbe/backend/graph.py)
- [backend/config.py](https://github.com/rotemweiss57/gpt-newspaper/blob/1c447b5672dd5ca8cd91a18bfa6daefe257c4fbe/backend/config.py)

This inventory is source-backed, not a completed runtime trace. Missing paths, if any, are explicitly marked in `intake.json`. No dependency declaration alone is counted as graph evidence.

## Setup attempted

Run in the separate checkout, never this directory:

```sh
uv sync --frozen
```

Install logs: `../../intake/`. Upstream lockfiles are unchanged; pip-based installs record a resolved freeze rather than claiming to use a Poetry lock. No container image was used.

## Current blocker / next action

Dependencies installed. Local models are supported by upstream configuration, but no dedicated Tavily credential or frozen service corpus is configured. No edition attempted.

Configure local model and dedicated Tavily access or labeled contract-preserving search double; reproduce edition and verify citations/output files.

## Experimental scope

Only local models are allowed. No hosted-model credentials or personal service accounts were used. `cases.jsonl` contains pilot tasks or a labeled unfrozen smoke placeholder, not a completed security matrix. `policy/` files are intent/planning documents until a mapping is validated; hashes do not establish enforcement. No attack case has been run. B/C availability is recorded in each manifest.
