# Operation-level comparison of trusted execution and host isolation

See the [combined evaluation](paper-evaluation.md) for application security, port descriptions, host configuration, and matched runtime overhead with variance and stage attribution. This document retains the original security-only E6 cohort.

We evaluate the distinction between restrictions on submitted source and
restrictions on effects performed by code below that boundary. The experiment
uses 59 deterministic operation/surface cases across five conditions, with three
repetitions in seeded shuffled order: **885 fresh-worker trials**. Ten cases are
allowed-operation controls; 49 attempt effects outside the configured workload
authority or file-size ceiling. Full methodology, trusted computing bases, and
reproduction commands appear in [the E6 protocol](../ISOLATION.md); raw results,
per-case outcomes, and source snapshots appear in
[the generated report](e6/isolation-v1/report.md).

The language comparator is a synthetic mechanism ablation. Its restricted
frontend admits arithmetic and calls to a prebound trusted helper; the helper
condition deliberately places the tested operation inside that helper. This
models an explicit trust assumption, not an exploit of a released sandbox. The
host comparator executes the same operations through the actual Linux executor,
including namespace isolation, filesystem mounts, seccomp, resource limits, and
activation receipts. It exercises the executor directly rather than graph-level
admission. The separate application study provides application integration
evidence and must not be pooled with these synthetic trials.

| Condition | Allowed effects, trials | Forbidden effects, trials | Explicit operation denials, trials |
| --- | ---: | ---: | ---: |
| Ordinary trusted Python | 30/30 | 147/147 | 0 |
| Restricted language, direct operation | 3/30 | 0/147 | 0 |
| Restricted language, trusted helper | 30/30 | 147/147 | 0 |
| Linux host executor | 30/30 | 0/147 | 135 |
| Restricted language/helper plus Linux executor | 30/30 | 0/147 | 135 |

All 49 forbidden cases produced the intended effect in every baseline
repetition, validating their feasibility on this machine. The language frontend
rejected 58 of 59 cases, including nine of ten legitimate controls. Its zero
forbidden effects therefore cannot support a utility-preserving security claim.
Moving the operation into an explicitly trusted helper restored all legitimate
operations and also permitted all forbidden effects. That result follows from
the tested trust boundary: admission checks constrain submitted caller code,
while the helper's implementation retains the process's authority.

Both host conditions preserved all ten legitimate controls in all repetitions
and exhibited no forbidden effects. We credit **45 distinct cases** with explicit
runtime denial, each accompanied by activation evidence. Four cases receive no
such credit: directory globbing and environment lookup returned empty/absent
values, while SQLite read and write produced generic operation errors. Thus
“no forbidden effect observed in 49 cases” is deliberately distinguished from
“explicit denial observed in 45 cases.” There were no unavailable setups or
inconclusive launch/protocol outcomes in this run.

The writable-surface cases are particularly informative. Legitimate writes,
append, truncation, deletion, file creation, and directory creation succeeded;
metadata changes, rename/link operations, and child-process attempts were denied
on the same writable surface. This separates permitted mutation from the
forbidden operation set instead of measuring only inaccessible paths. The
bounded resource probe attempted a 2 MiB write under a 1 MiB file-size ceiling;
the parent checked the resulting file size, allowing a partial write without
mistaking it for a ceiling violation. A 4 KiB control completed successfully.

The run was recorded on 2026-10-26 UTC. Exact Python/kernel identifiers, installed
distributions, source inventory, interpreter digest, and launch evidence are
retained in the artifact. The complete working-tree Python source snapshot is
archived because a Git revision alone would not identify the measured code.
Median dispatch times over the heterogeneous corpus were 23.55 ms for trusted
Python, 20.80 ms for direct language admission, 24.86 ms for trusted-helper
execution, 299.93 ms for the host executor, and 295.15 ms for the combined
condition. These include fresh-worker startup, exclude executor construction,
and are descriptive rather than a matched-workload overhead estimate. Admission
failures do less work than successful operations. The machine was not reserved;
other validation work could overlap. No performance superiority or precise
application slowdown is inferred from these medians.

These results support a finite, mechanism-specific conclusion: on this host and
policy, host enforcement constrained the exercised trusted-helper effects while
preserving the selected legitimate operations. They do not establish universal
containment, superiority over a fully mediated language, prompt-injection ASR,
or service-level authorization. API/surface variants and repeated deterministic
runs are dependent observations, so we report counts rather than a binomial
confidence interval. Real language-runtime baselines, concurrent races, broader
resource exhaustion, external services, cross-session flow, and additional host
backends remain separate experiments explicitly enumerated in the protocol.
