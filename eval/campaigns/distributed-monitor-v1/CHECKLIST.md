# Experiment-to-review checklist

| Review item | Status | Evidence or limitation |
|---|---|---|
| Full-protection Pandas application | Complete | `raw/pandas-full`, 45/50 in each configuration |
| Per-call Lean configuration and proof replay | Complete | Pinned binary used; final Lake build, negative controls, and fresh kernel replay passed |
| Attacked application read/write | Complete | `raw/pandas-attack-*`, 10/10 legitimate, zero effects |
| Wrong record, hidden update/delete, direct DB/WAL, pump socket | Complete | `raw/sqlite-composition`, `raw/pump-composition` |
| Sealed operator conflict | Complete | `raw/policy-conflict`, reads succeed and all writes fail |
| Invocation authority lifetime | Partially complete | Replay/substitution blocked; production broker fresh-spawns, so exact reused-worker experiment is structurally unsupported |
| External sandbox/configuration probes | Complete | One repeated ACE `ToolExecutionSandbox` availability probe and IsolateGPT standalone-sandbox probes; neither is a full-system comparison |
| Corresponding baseline agent requests | Outstanding | Fixed invocations establish effects; only fare scenarios include agent requests |
| ACE-style fare adaptations | Complete | Actual slangGraph graph/tool execution with exact-value oracle; not an ACE/IsolateGPT execution |
| Retry boundary | Complete | `retry_broker_then_direct` |
| Path substitution | Complete | sealed-dispatcher test swaps a symlink and remains denied |
| Import-time effect | Complete | lifecycle test confirms isolation precedes module initialization |
| Workload-specific phase timings | Complete | five sessions × 20 measured calls; file routes use direct file baseline, broker uses direct SQLite baseline |
| Cedar subprocess versus in-process | Infeasible on frozen host | No in-process Cedar Python binding installed; no optimization claim made |
| Two-stage compilation/two hosts | Complete | Exact parsed manifest and policy objects reused across Linux/container compilers; only host capability changes in fail-closed case |
| Tool census | Complete | 13 ACE sources: 5 pass-only placeholders excluded; of 8 real tools, 0 language-unchanged, 6 host-isolated, 2 need adaptation |
| Document workflow | Complete | allowed report plus forbidden read/write cases |
| HTTP resource adapter | Complete | allowed reads/modify control and mediated/direct attacks |
| Full prebuilt suite | Complete | 5,426 passed, 264 skipped, zero failed |
| Component/trusted-code inventory | Complete | `raw/environment/component-inventory.json` |
| Anonymous artifact URL | Outstanding | No anonymous artifact service/credential available; repository bundle prepared |
