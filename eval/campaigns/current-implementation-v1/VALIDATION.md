# Validation record

The statistics regeneration command completed successfully and rejected no
matrix, count, invalid-result, or phase-overlap condition. Each of the four
current route cohorts contains exactly five setup records, five first-use calls,
50 excluded warmups, 100 measured protected calls, and 100 paired direct
baselines. All 400 protected measured calls have `valid=true`.

The matched Pandas verifier reports 150 trials, A/B/C at 50/50 each, and an
empty `issues` list. The closed verifier reports 50 trials, 45 successes, the
five exact `monthly_mean-C-closed-{0..4}` failures, and an empty `issues` list.
Its overall `passed=false` therefore records utility failure, not malformed or
missing evidence.

The frozen targeted test run covered the SQLite mediator, Docker execution,
object policy, and native Lean test module: 66 passed and the three opt-in Lean
native cases skipped. Re-running that module with
`LANGGRAPH_REQUIRE_LEAN_NATIVE=1` and the pinned Lean executable produced three
passes, including useful file read, undeclared-file denial, fork denial, and
confirmed termination. Logs are `raw/checks-current.log` and
`raw/checks-lean-native.log`.

The evaluation harness and statistics source pass Ruff formatting, Ruff lint,
Python bytecode compilation, `bash -n reproduce.sh`, and JSON parsing of the
freeze definition. Library source was not modified, so the monorepo's
library-change `make format`, `make lint`, and `make test` gate is not triggered.

`SHA256SUMS` covers every commit-eligible campaign file at final hashing except
`SHA256SUMS` itself. Generated Lean executable copies and Python bytecode caches
are intentionally ignored; verification with `sha256sum -c` completed
successfully.
