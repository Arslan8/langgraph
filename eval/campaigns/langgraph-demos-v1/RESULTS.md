# Ordinary LangGraph demo evaluation

All five baseline preflights were attempted before Argus integration. Every full-Argus integration requires a missing adapter or runtime capability, so no application entered the paired timing campaign. Unsupported applications are reported rather than replaced or measured under a weakened configuration.

| Application | Integration status and adaptations | Baseline success / attempts | Argus success / attempts | Baseline mean | Argus mean | Full-system overhead and interval |
|---|---|---:|---:|---:|---:|---:|
| D1: SQL agent | Unsupported; Model wrapper; full custom graph retained | 2/5 preflight | 0/0 (not run) | — | — | unavailable |
| D2: Agentic RAG | Unsupported; Frozen HTML, local TF-IDF retriever, frozen RAG prompt | 5/5 preflight | 0/0 (not run) | — | — | unavailable |
| D3: Plan and execute | Unsupported; Frozen-search backend; async graph retained | 0/5 preflight | 0/0 (not run) | — | — | unavailable |
| D4: Multi-agent network | Unsupported; Frozen-search backend, Agg and plotting observer; REPL retained | 5/5 preflight | 0/0 (not run) | — | — | unavailable |
| D5: Customer support Part 3 | Unsupported; Frozen date/policy backend and deterministic approval harness | 4/5 preflight | 0/0 (not run) | — | — | unavailable |

## Baseline observations

- D1 passed tasks 1 and 3. Tasks 2 and 5 ended with empty answers; task 4 returned only five of 24 countries.
- D2 passed the frozen required-fact checklists for all five answers.
- D3 failed all five preflights: the pinned model produced empty plans or the unchanged graph reached its recursion limit. These are baseline compatibility failures.
- D4 passed all five numeric-series and chart-artifact checks. The observer validates years and values rather than PNG pixels or model claims.
- D5 passed tasks 1, 2, 4, and 5. Task 3 exposed the tutorial tool's broad `UPDATE`: both ticket legs became flight 1472 rather than only the intended leg.

## Timing conclusion

No full-system overhead ratio or graph is reported. Preflight durations are retained as diagnostic data but do not have matching Argus observations or the frozen paired timing boundary. Reporting them as application overhead would be misleading.

See `CONFIGURATIONS.md` and `integration-probes/` for the five exact unsupported boundaries.
