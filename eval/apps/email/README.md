# email application intake

Status: **baseline intake / pilot work; no completed port**.

Repository: https://github.com/langchain-ai/executive-ai-assistant

Pinned SHA: `758db7174223da7864feea7c9f8d1aba12923037`. Retrieved: 2026-10-26T00:10:30.649349+00:00. License text and SHA-256 are in `intake.json`; dependency inputs and the resolved environment are recorded there and in `resolved.txt`. GitHub archive status: `True` (API captured during intake). 

## Executable path and effects

langgraph.json -> eaia/main/graph.py: graph

Gmail read/send/mark-as-read and Calendar SDK effects in eaia/gmail.py; send_email_node calls SDK helper directly; preserve human_node approval workflow. OAuth and ingestion outside graph; hosted inbox and LangGraph persistence require separate trace.

- [langgraph.json](https://github.com/langchain-ai/executive-ai-assistant/blob/758db7174223da7864feea7c9f8d1aba12923037/langgraph.json)
- [eaia/main/graph.py](https://github.com/langchain-ai/executive-ai-assistant/blob/758db7174223da7864feea7c9f8d1aba12923037/eaia/main/graph.py)
- [eaia/gmail.py](https://github.com/langchain-ai/executive-ai-assistant/blob/758db7174223da7864feea7c9f8d1aba12923037/eaia/gmail.py)
- [eaia/cron_graph.py](https://github.com/langchain-ai/executive-ai-assistant/blob/758db7174223da7864feea7c9f8d1aba12923037/eaia/cron_graph.py)
- [scripts/run_ingest.py](https://github.com/langchain-ai/executive-ai-assistant/blob/758db7174223da7864feea7c9f8d1aba12923037/scripts/run_ingest.py)

This inventory is source-backed, not a completed runtime trace. Missing paths, if any, are explicitly marked in `intake.json`. No dependency declaration alone is counted as graph evidence.

## Setup attempted

Run in the separate checkout, never this directory:

```sh
uv venv .venv
uv pip install --python .venv/bin/python -e .
```

Install logs: `../../intake/`. Upstream lockfiles are unchanged; pip-based installs record a resolved freeze rather than claiming to use a Poetry lock. No container image was used.

## Current blocker / next action

Documented install fails resolution of yanked langgraph-api 0.2.x versions. No dedicated Gmail OAuth test identity/controlled recipients configured. Reflection graph hard-codes hosted models; exclude that path from local-only work unless a documented local configuration is established. No live send attempted.

Resolve documented install failure with a separately reviewed dependency patch; provision dedicated Gmail OAuth test account and controlled recipients. No personal mailbox use.

## Experimental scope

Only local models are allowed. No hosted-model credentials or personal service accounts were used. `cases.jsonl` contains pilot tasks or a labeled unfrozen smoke placeholder, not a completed security matrix. `policy/` files are intent/planning documents until a mapping is validated; hashes do not establish enforcement. No attack case has been run. B/C availability is recorded in each manifest.
