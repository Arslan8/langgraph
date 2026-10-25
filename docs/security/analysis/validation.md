# Validation record

Implementation base: `Arslan8/slanggraph:wip`,
`5bebea0ffbce3a68895deb266838291165719e1f` (checked October 25, 2026).
The implementation is split into six logical commits on `analysis-runtime`.

Environment: Linux 6.17.0-1033-oem, uv 0.9.18; prebuilt Python 3.13.11,
core Python 3.10.19, pytest 9.1.1, bubblewrap 0.9.0. Provider libraries remain
optional. No live model, model digest or classifier accuracy is reported: the local
Ollama service was unavailable. No Corridor analyzePlan tool was available.

## Commands and observed results

From the repository root:

```sh
make -C libs/prebuilt format
make -C libs/prebuilt lint
make -C libs/prebuilt test
make -C libs/langgraph format
make -C libs/langgraph lint
make -C libs/langgraph test NO_DOCKER=true TEST=tests/test_input_guard.py
uv run --directory libs/prebuilt pytest tests/analysis -q
```

Both libraries' format and lint commands passed. The core input-guard tests passed
(2 tests). The full prebuilt suite reported **3,701 passed, 58 failed, 4 skipped**
in 434.51 seconds. Every failure reported `bubblewrap isolation is unavailable on
this host`; an independent `bwrap --unshare-user --ro-bind / / -- true` probe failed
with `setting up uid map: Permission denied`. These host execution tests remain
unvalidated here; they were not disabled or changed to pass.

The final analysis suite passed 42 tests, including a later whole-container flow
regression check. The full suite predates that final store/fixture adjustment;
targeted provenance, interpreter and model-role tests cover it. A separate security
regression run covering analysis, guarded tools, ToolNode and mediation passed
123 tests. The core's entire test suite was not run: its prescribed `make test`
command was scoped to the changed callback boundary.

Source-bound mediation summaries were explicitly extended for the awaited prepare
path, final request freezing and non-executing analysis result helpers. Their
reviewed source digests changed with those implementations. Existing verification
remains enabled; the summaries do not establish new arbitrary-code proofs.

## Offline effects and overhead

See [demo commands](repeat-after-me-demo.md). Recorded ledger counts were A=1,
B=0, C=1, D-retrieval=0, D-tool=0, quoted-A=0, quoted-B=0 and deliberate
false-negative=1. The last case demonstrates a detection failure, not a runtime
security guarantee. The confidentiality fixture recorded public=0, cleared=1,
unknown-authority=0; public model submission was denied and cleared submission
allowed under one fixed policy configuration.

An offline measurement of 100 operations with one scripted no-op analyzer and
in-memory SQLite reported mean **0.504 ms**, maximum **1.063 ms** per operation.
This includes instrumented processing, not a differential benchmark against an
uninstrumented graph, and is environment-specific. The corpus SHA-256 was
`7dd20fa47b991351c99f8360a55095b24e6eeca533182015aff10ff2c5f886ec`.
Live latency, held-out confusion matrix and policy block rate require running the
optional evaluation command. They are not inferred from scripted classifications.

## Review limitations

[Coverage](coverage.md) distinguishes integrated boundaries from explicit adapters
and unsupported paths. In particular arbitrary reducers/caches, native I/O and
unadapted provider callbacks are not automatically tracked. The finite interpreter
and model-role fixtures are integration contracts, not complete research systems.
The synthetic evaluation labels need independent human review. Subscription replay
is process-local and retained history is bounded. Trusted Python plugins and the
composition root remain inside the trusted computing base.

This validation record does not claim every acceptance item has been demonstrated:
live evaluation and host isolation validation are outstanding, and applications
must explicitly instrument the unsupported paths before requiring their coverage.
