# Experiment-to-review checklist

| Review item | Status | Evidence or limitation |
|---|---|---|
| Full-protection Pandas application | Complete | `raw/pandas-full`, 45/50 in each configuration |
| Per-call Lean configuration | Complete as runtime experiment | Pinned binary used; final Lake replay prerequisite missing |
| Attacked application read/write | Complete | `raw/pandas-attack-*`, 10/10 legitimate, zero effects |
| Wrong record, hidden update/delete, direct DB/WAL, pump socket | Complete | `raw/sqlite-composition`, `raw/pump-composition` |
| Sealed operator conflict | Complete | `raw/policy-conflict`, reads succeed and all writes fail |
| Invocation authority lifetime | Partially complete | Replay/substitution blocked; production broker fresh-spawns, so exact reused-worker experiment is structurally unsupported |
| ACE and IsolateGPT fixed-invocation baselines | Complete | ACE configuration could not mount fixtures; IsolateGPT restrictions cannot express record/operation policy |
| Corresponding baseline agent requests | Outstanding | Fixed invocations establish effects; only fare scenarios include agent requests |
| ACE-style fare adaptations | Complete | 20 fixed plus 20 agent trials per cell, both execution orders where applicable |
| Retry boundary | Complete | `retry_broker_then_direct` |
| Path substitution | Complete | sealed-dispatcher test swaps a symlink and remains denied |
| Import-time effect | Complete | lifecycle test confirms isolation precedes module initialization |
| Common workload and phase timings | Complete | five sessions × 20 measured calls; `raw/common-*` and `raw/broker-costs` |
| Cedar subprocess versus in-process | Infeasible on frozen host | No in-process Cedar Python binding installed; no optimization claim made |
| Two-stage compilation/two hosts | Complete | `raw/host-compilation`; unchanged prepared hash and fail-closed missing-capability case |
| Tool census | Complete | 13 ACE tools: 5 unchanged, 4 adapter, 4 host isolation; adapted tools not counted as executed |
| Document workflow | Complete | allowed report plus forbidden read/write cases |
| HTTP resource adapter | Complete | allowed reads/modify control and mediated/direct attacks |
| Full prebuilt suite | Complete | 5,426 passed, 264 skipped, zero failed |
| Component/trusted-code inventory | Complete | `raw/environment/component-inventory.json` |
| Anonymous artifact URL | Outstanding | No anonymous artifact service/credential available; repository bundle prepared |
