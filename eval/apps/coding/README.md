# coding application intake

Status: **baseline intake / pilot work; no completed port**.

Repository: https://github.com/langchain-ai/open-swe

Pinned SHA: `ff4e713c094c0abb8c76b3193de464d9b4f1e570`. Retrieved: 2026-10-26T00:10:30.649349+00:00. License text and SHA-256 are in `intake.json`; dependency inputs and the resolved environment are recorded there and in `resolved.txt`. 

## Executable path and effects

openswe/threads/router.py -> Managed Deep Agents project mda/agent.py

Managed Deep Agents owns model loop, tools, checkpoints and sandbox. Backend uses PostgreSQL and GitHub credentials; remote sandbox shell/files and publication need execution-host instrumentation. Preserve upstream middleware and sandbox.

- [langgraph.json](https://github.com/langchain-ai/open-swe/blob/ff4e713c094c0abb8c76b3193de464d9b4f1e570/langgraph.json)
- [openswe/threads/router.py](https://github.com/langchain-ai/open-swe/blob/ff4e713c094c0abb8c76b3193de464d9b4f1e570/openswe/threads/router.py)
- [mda/agent.py](https://github.com/langchain-ai/open-swe/blob/ff4e713c094c0abb8c76b3193de464d9b4f1e570/mda/agent.py)
- [mda/rt/file_tools.py](https://github.com/langchain-ai/open-swe/blob/ff4e713c094c0abb8c76b3193de464d9b4f1e570/mda/rt/file_tools.py)
- [mda/rt/managed_sandbox.py](https://github.com/langchain-ai/open-swe/blob/ff4e713c094c0abb8c76b3193de464d9b4f1e570/mda/rt/managed_sandbox.py)
- [openswe/agent_api/graph.py](https://github.com/langchain-ai/open-swe/blob/ff4e713c094c0abb8c76b3193de464d9b4f1e570/openswe/agent_api/graph.py)

This inventory is source-backed, not a completed runtime trace. Missing paths, if any, are explicitly marked in `intake.json`. No dependency declaration alone is counted as graph evidence.

## Setup attempted

Run in the separate checkout, never this directory:

```sh
uv sync --frozen --all-extras
```

Install logs: `../../intake/`. Upstream lockfiles are unchanged; pip-based installs record a resolved freeze rather than claiming to use a Poetry lock. No container image was used.

## Current blocker / next action

Backend dependencies installed, but Managed Deep Agents project is a separate environment. No dedicated GitHub App/repository, MDA credentials/runtime or isolated PostgreSQL configured. No remote sandbox or publication attempted. Local executor cannot confine a remote sandbox by itself.

Provision dedicated GitHub App/repository, PostgreSQL and MDA runtime credentials; instrument sandbox execution host. Local minimal executor cannot support shell descendants.

## Experimental scope

Only local models are allowed. No hosted-model credentials or personal service accounts were used. `cases.jsonl` contains pilot tasks or a labeled unfrozen smoke placeholder, not a completed security matrix. `policy/` files are intent/planning documents until a mapping is validated; hashes do not establish enforcement. No attack case has been run. B/C availability is recorded in each manifest.
