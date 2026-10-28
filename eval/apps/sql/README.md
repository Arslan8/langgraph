# sql application intake

Status: **baseline intake / pilot work; no completed port**.

Repository: https://github.com/business-science/ai-data-science-team

Pinned SHA: `4ffeb7f38178aa250917f29b01355f8b89ba809e`. Retrieved: 2026-10-26T00:10:30.649349+00:00. License text and SHA-256 are in `intake.json`; dependency inputs and the resolved environment are recorded there and in `resolved.txt`. 

## Executable path and effects

app.py: handle_question -> SQLDatabaseAgent.ainvoke_agent

SQLAlchemy connection opened by UI; schema sampling and model calls in graph; generated Python exec in node_func_execute_agent_from_sql_connection. Preserve safe_mode query validation. Metadata sampling may read restricted tables before query dispatch.

- [ai_data_science_team/agents/sql_database_agent.py](https://github.com/business-science/ai-data-science-team/blob/4ffeb7f38178aa250917f29b01355f8b89ba809e/ai_data_science_team/agents/sql_database_agent.py)
- [ai_data_science_team/templates/agent_templates.py](https://github.com/business-science/ai-data-science-team/blob/4ffeb7f38178aa250917f29b01355f8b89ba809e/ai_data_science_team/templates/agent_templates.py)
- [ai_data_science_team/tools/sql.py](https://github.com/business-science/ai-data-science-team/blob/4ffeb7f38178aa250917f29b01355f8b89ba809e/ai_data_science_team/tools/sql.py)

This inventory is source-backed, not a completed runtime trace. Missing paths, if any, are explicitly marked in `intake.json`. No dependency declaration alone is counted as graph evidence.

## Setup attempted

Run in the separate checkout, never this directory:

```sh
See Pandas: both bundled apps use the same pinned package environment.
```

Install logs: `../../intake/`. Upstream lockfiles are unchanged; pip-based installs record a resolved freeze rather than claiming to use a Poetry lock. No container image was used.

## Current blocker / next action

Original UI only offers hosted GPT models. Local-model backend pilot uses the same bundled graph. C cannot pass SQLAlchemy connection authority into the current JSON worker or enforce table grants with a filesystem mount. Schema sampling is an additional direct read path.

All three v4 local clean pilots pass. `../../intake/sql-observations.json` records
schema sampling of the payroll canary into the local model prompt before query
execution. This direct path also needs mediation.

The existing `libs/prebuilt/langgraph/prebuilt/security/mediators/sqlite.py`
`sqlite_record_mediator` supports only `records(key TEXT PRIMARY KEY, value TEXT
NOT NULL)` and fixed single-record operations. It explicitly excludes arbitrary
schemas/SQL/connection objects. Replacing this SQL app with that demo would not
preserve its useful behavior; general SQL mediation requires documented new system
work. B/C remain unsupported for this application in production.

B/C were nevertheless executed in RM1
(`eval/campaigns/remaining-v1/raw/sql-full/trials.jsonl`). B is call
authorization only; only C used an evaluation-only bounded SELECT mediator and
C passed 50/50 utility trials. C remains unsupported in production (see route
`sql-bounded-select` in `docs/security/supported-surface.json`).

## Experimental scope

Only local models are allowed. No hosted-model credentials or personal service accounts were used. `cases.jsonl` contains pilot tasks or a labeled unfrozen smoke placeholder, not a completed security matrix. `policy/` files are intent/planning documents until a mapping is validated; hashes do not establish enforcement. No attack case has been run. B/C availability is recorded in each manifest.

The headless adapter in `../backend.py` instantiates the exact classes/settings in bundled `app.py` and invokes its backend workflow. It excludes Streamlit authentication, upload widgets, history and display. Changes: local endpoint/model, temperature 0/seed, disabled external tracing, synthetic CSV/SQLite fixture, missing IPython dependency, and (v2) inherited single-CPU affinity. Original graph/prompt sources and safe_mode/sandbox protections are unchanged. The app is installed from the pinned checkout, not an unrelated PyPI release. Run commands are in `../../APPLICATIONS.md`.
