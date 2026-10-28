# Record corrections (proposed; records not edited)

Source: `eval/scope/cohort-inventory-draft.md` (Step 1, Q8).

1. `eval/APPLICATIONS.md:148-150`
   - Current: "SQL's existing sqlite_record_mediator supports only a fixed `records(key,value)` schema and fixed operations, not this application's arbitrary SQLAlchemy queries. A general SQL mediator would be new system work." The passage does not say B/C are unsupported; it omits the RM1 sql-full cohort entirely (`APPLICATIONS.md` has no mention of `sql-full` or RM1).
   - Correct: a C cohort exists. It used the evaluation-harness bounded mediator (`eval/remaining/bounded_sql.py`) and passed 50/50, with the canary in model input 0/50 (`eval/campaigns/remaining-v1/raw/sql-full/trials.jsonl`; `eval/campaigns/remaining-v1/RESULTS.md:36`).
   - Proposed: "SQL B/C were executed in RM1 (A/B/C 50/50 each; canary in model input A 26/50, B 27/50, C 0/50). B is call authorization only, with upstream effects unchanged; only C used an evaluation-only bounded SELECT mediator. The production `sqlite_record_mediator` still supports only `records(key,value)`, so SQL C remains unsupported in production until a mediator is promoted into `security/mediators/`."
2. `eval/apps/sql/README.md:39-44`
   - Current: "B/C remain unsupported for this application."
   - Correct: same evidence as item 1.
   - Proposed: "B/C were executed in RM1 (`remaining-v1/raw/sql-full/trials.jsonl`). B is call authorization only; only C used an evaluation-only bounded mediator (C 50/50). C remains unsupported in production (`docs/security/supported-surface.json`, route `sql-bounded-select`)."
3. `eval/reports/application-pilot.md:87-91`
   - Current: "B/C are unsupported for this application."
   - Proposed: "In this pilot B/C were not run. RM1 later executed them with an evaluation-only mediator (`eval/campaigns/remaining-v1/RESULTS.md:36`); production support remains absent."
4. `eval/campaigns/remediation-v2/README.md:19`
   - Current: "`raw/pandas-v11` ... 26/30 outputs pass."
   - Correct: 24/30 (A 8/10, B 8/10, C 8/10) per `eval/campaigns/remediation-v2/v11-summary.json` and the raw trials.
   - Proposed: "`raw/pandas-v11`: original-request preservation, no graph retries. 24/30 outputs pass (8/8/8)."
5. `eval/apps.csv:2` (pandas) and `eval/apps.csv:3` (sql), column `baseline_run`
   - Current: `results/pandas-A-region-totals-r1-ae814e761b5449219bec6b3be8d2162b/result.json` and `results/sql-A-region-totals-r1-4410e692af5b48a2b5d86dd8482ad0a1/result.json`. Both are early manifest-v2 runs whose only source record is `source-recovery.json`.
   - `baseline_run` is a single-run `result.json` column, so it must not be repointed at cohort aggregates. Neither newer cohort contains per-trial `result.json` files (trial directories under `remediation-v2/raw/pandas-v19-full/` and `remaining-v1/raw/sql-full/` hold `output.json`, `request.json`, `events.jsonl`, etc., not `result.json`), so there is no representative single-run `result.json` to point at.
   - Proposed: leave `baseline_run` unchanged (historical) and add a separate `cohort_evidence` column: pandas `eval/campaigns/remediation-v2/raw/pandas-v19-full/verification.json` (frozen A 50/50; utility evidence only) and sql `eval/campaigns/remaining-v1/raw/sql-full/trials.jsonl` (A 50/50).
6. `eval/apps.csv:2-3`, column `next_action` (stale summaries)
   - pandas: "Resolve original utility failures ... before completed-port claim." This predates v19 (150/150). Proposed: "v19 A/B/C 50/50; SGV901-903 and ungated model/publication/`/tmp` gaps remain (see `docs/security/supported-surface.json`)."
   - sql: "Local baseline passes; fixed-record sqlite mediator does not support arbitrary SQL." Proposed: "RM1 A/B/C 50/50; B is call authorization only, and only C used the evaluation-only bounded mediator; production SQL mediator not yet promoted."
