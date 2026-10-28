# Current-implementation evaluation

This campaign freezes implementation revision
`bdb0cb9d467e426354ad8beba20407374947ce51` and evaluates it without modifying
that source tree. The full machine/model/dependency definition is in
`frozen-config.json`; commands are in `reproduce.sh`; additive timing boundaries
are in `timing-boundaries.md`.

## Short result

- The immutable-language, Docker, and object-broker routes ran with closed
  admission, sealed mandatory policy, Cedar, matching activation evidence, and
  durable audit. Each route has five fresh sessions, one retained first use, ten
  excluded warmups, and 20 measured calls per session. Their reused means were
  46.301 ms, 172.837 ms, and 651.435 ms, respectively. Docker first use was
  1501.742 ms and final removal was 646.212 ms.
- The Lean-backed Landlock route averaged 610.509 ms, including 279.777 ms of
  Lean checking. It is not called a headline protected mode: the frozen
  runtime-MAC allowlist rejects direct `LinuxSandboxExecutor` dispatch.
- Matched Pandas A/B/C utility was 50/50 in every configuration. Mean task wall
  time was 9.888 s, 10.490 s, and 11.743 s. C-closed was 45/50 at 13.867 s; all
  five misses are retained `monthly_mean` non-finite-output refusals.
- In the Alice/Bob SQLite ablation, production composition preserved all 15
  allowed operations and produced zero forbidden or direct-file effects.
  Call-authorization-only and filesystem-accessible baselines also preserved
  the 15 allowed operations but each produced 25 forbidden effects.
- The frozen correctness pass produced 66 passes and three opt-in skips; the
  skipped native Lean cases were then enabled explicitly and all three passed.

`RESULTS.md` contains the regenerated timing tables and confidence intervals.
`statistics.json` and `statistics.csv` are their machine-readable sources.
`composition-summary.json` contains Alice/Bob and pump ablation counts. Raw
per-trial records, model transcripts, retries, receipts, refusals, audits, and
test logs are under `raw/`.

The commit excludes two generated 122 MB copies of the Lean executable and
Python bytecode caches. The executable's SHA-256 and reproduction path are
frozen in `frozen-config.json`; source snapshots and all trial evidence remain.

## Interpretation boundaries

Intervals are 95% Student-t intervals over five independent session means.
Phase rows are additive: nested spans are subtracted and any unassigned time is
reported as framework residual. Microsecond upstream baselines make relative
multiples very large, so absolute milliseconds are primary.

The two `*_authorization_only` microbenchmarks in `RESULTS.md` are retained
secondary evidence, not headline protected routes. The Pandas v19 and C-closed
cohorts are separate protocols and are not pooled. Lean proves a finite route
model; it does not prove refinement of Python, source extraction, the compiler,
the JSON decoder, or the operating system.

The failed first attempt to admit the language task is retained at
`raw/language-useful-work-v1.failed-initial/`: comparing two runtime strings is
outside the frozen interpreter's closed branch grammar. The final admitted task
compares each immutable input against a fixed literal, which demonstrates the
supported bounded decision form without weakening admission.

See `CHANGELOG.md` for differences from prior evaluations,
`pandas-change-evidence.md` for the 29/50-to-50/50 evidence, and
`paper-restructure.md` for the manuscript rewrite plan.
