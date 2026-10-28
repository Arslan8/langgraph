# Distributed-monitor consolidated evaluation

This campaign evaluates revision `12d01121391d3a0526210c0b6c48567d50f69740`
of the implementation. Subsequent commits on this branch change the evaluation
harness and records, not that frozen implementation. The frozen host,
dependencies, models, policies, plans, per-trial records, and full prebuilt test
log are under `raw/`.

The headline Pandas configurations use closed admission, principal Cedar policy,
sealed operator policy, Linux host isolation, exact-file/resource mediation, and
audit together. `C-full-lean` additionally invokes the pinned Lean decision
binary per call. Both completed 45/50 tasks. The five refusals in each cohort
are the retained monthly-mean non-finite-output cases; output validation was not
weakened. The attacked read and write variants each preserved the legitimate
result in 5/5 trials and produced no forbidden effect.

The deterministic SQLite, pump, policy-conflict, invocation-lifetime, HTTP, and
document cases use five fresh-state repetitions. The ACE-inspired fare
adaptations use 20 trials for each fixed-invocation and agent-request cell and
execute through protected slangGraph `StateGraph`/`ToolNode` with closed
admission, principal authorization, sealed operator policy, isolated Linux
workers, and audit. They are not ACE or IsolateGPT executions. Full slangGraph blocked
every tested unauthorized effect while retaining the paired allowed operations.
Call-check-only and transport-only ablations did not. Denying the whole SQLite
database also denied Alice's allowed control and is not counted as success.
The fare result-manipulation failures are reported as authorized-output attacks
outside the current enforcement guarantee, not as resource-monitor bypasses.

`RESULTS.md` contains the generated application, performance, and attack tables;
`statistics.json` is their machine-readable source. Run
`libs/prebuilt/.venv/bin/python eval/distributed/regenerate_results.py --raw
eval/campaigns/distributed-monitor-v1/raw --output
eval/campaigns/distributed-monitor-v1` to regenerate them.

The ACE and IsolateGPT records remain limited sandbox/configuration probes.
Full-system external comparisons are outstanding and are not inferred from
those probes.

## Reproduction

`reproduce.sh` is the one-command full campaign and refuses to overwrite an
existing raw directory. `setup_baselines.sh` pins ACE at
`e88f6dc16e5404131fbefe5684c7f05f856edbdd` and IsolateGPT at
`c6020f977d20f9f80776cae5d4e2930455733ce5`. The full run requires Docker,
Cedar CLI 4.13.0, Ollama with the frozen Qwen model, and Lean/Lake 4.34.1.

The superseded first proof replay failed because `lake` was absent from `PATH`.
After adding the already installed pinned toolchain at `~/.elan/bin`, the
authoritative replay in `raw/lean-check` passed: the model built, generated kernel audit
typechecked, all five malformed controls were rejected, and fresh kernel replay
succeeded. The report still sets system/runtime/compiler/OS completeness claims
to false, as intended; it proves the captured finite decision model only.

No anonymous upload service or credential was available on the evaluation host,
so a real anonymous artifact URL remains outstanding. This repository bundle is
the prepared artifact; no URL is fabricated. The portable checksum manifest
intentionally excludes frozen source-tree copies, Python bytecode, Lean
snapshots, and the 122 MB runtime executable duplicated inside each Pandas
directory. Their source revisions and digests remain recorded, and
`reproduce.sh` rebuilds or captures them locally.
