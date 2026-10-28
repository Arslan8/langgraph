# Evaluation change log

## Freeze and protocol

- Replaced the manuscript's historical `715a9db0` plus working-tree description
  with exact revision `bdb0cb9d467e426354ad8beba20407374947ce51` and captured
  lockfile hashes, packages, host/kernel, Cedar, Docker/image, Lean binary, and
  model digest.
- Replaced the earlier three warmups/40 calls in one process with five fresh
  sessions, ten excluded warmups and 20 measured calls per session. First use is
  retained separately. Confidence intervals use the five session means.
- Made setup, Cedar, Lean, activation, execution, audit, cleanup and framework
  residual explicit. Nested spans are subtracted rather than summed twice.
- Split upstream, authorization-only, and fully protected definitions. The
  current runtime-MAC dispatcher allowlist is reported as a limitation: it does
  not accept the direct `LinuxSandboxExecutor`, so that route is not promoted to
  the mandatory-MAC headline configuration.

## Pandas

- Reran the same ten tasks and five repetitions for A/B/C on the frozen source,
  model, seed, oracle, serializer and three-retry workflow; all attempts and
  event logs are retained.
- Added a separate C-closed v21 rerun rather than pooling its safe output
  refusals with v19. Non-finite-output refusal remains mandatory.
- Replaced the ambiguous “29/50 to 50/50” narrative with the retained
  configuration diff and one-factor serializer/period evidence in
  `pandas-change-evidence.md`.

## Current routes and applications

- Added production current-route cohorts for immutable-language useful work,
  the Lean-backed Linux/Landlock worker, Docker container reuse/lifetime, and
  the typed object broker.
- Added cold container creation and confirmed removal rows; reused calls require
  an unchanged authority identity.
- Recentered the database evaluation on a single Alice/Bob SQLite fixture and
  on useful allowed operations plus Bob-record/direct-file denial. A whole-file
  deny is not counted as a functional baseline.
- Reproduced SQLite and pump composition ablations from the frozen sources.

## Formal and coverage reporting

- Added exact statements, assumptions, model size, commands, implementation
  connection and checking cost for the five central Lean properties.
- Explicitly separated proved finite decision-core facts from unproved
  Python/source/compiler/decoder/OS refinement.
- Did not invent retrospective implementation hours where the repository has no
  prospective per-adapter time log; adapter source size and the missing effort
  evidence are reported separately.
