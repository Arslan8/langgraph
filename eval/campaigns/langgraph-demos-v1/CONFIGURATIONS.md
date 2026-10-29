# Configurations and integration status

`Baseline` is the same adapted upstream application without Argus. `Argus`
means closed admission, authenticated-principal and sealed-operator policy,
production host isolation/resource lowering, audit, output mediation, and the
route's required runtime checker. Checks are not disabled to make a demo run.

| ID | Baseline route | Required Argus route | Trusted orchestration boundary | Integration result |
|---|---|---|---|---|
| D1 | Ordinary graph plus SQLDatabaseToolkit and SQLite | Mediated read-only SQLite access plus isolated ToolNodes | model/query-control nodes only | Unsupported: `list_tables` directly invokes `SQLDatabase` inside an orchestration node; no registered SQL adapter can lower this without changing the graph |
| D2 | Ordinary graph plus prepared local retriever | Isolated retriever with mediated index/document reads | agent, grade, rewrite, generate | Unsupported: retriever closes over an in-process index and no registered retriever adapter/worker preserves its contract |
| D3 | Async graph and frozen-search tool | Async isolated search with audit and per-call checker | planner, replanner, executor orchestration | Unsupported: selected per-call Lean lifecycle route is synchronous-only and refuses async dispatch |
| D4 | Two-agent graph plus one persistent PythonREPL | Isolated stateful Python tool and mediated output artifact | researcher/chart handoff nodes | Unsupported: production Linux route creates a fresh worker per call and cannot preserve the required REPL namespace |
| D5 | Part-3 graph, memory checkpointer, mutable tutorial DB | Mediated mutable SQLite across interrupt/resume | assistant, routing, user-info orchestration | Unsupported: no registered adapter preserves the mutable SQLite handle and checkpointed interrupt/resume authority |

The retained `integration-probes/` logs are integration-preflight refusals, not
completed Argus trials and not evidence that an enforcement component blocked
an attack. No application code is declared trusted to bypass these boundaries.
Because all five require redesign or a new adapter/runtime capability, the
50-trial measurement protocol was not started for any demo.
