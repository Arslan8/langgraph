# Evaluation closed: route-scoped acceptance passes

The agreed evaluation is complete under decisions D2 and D5–D11. Security
acceptance passes for six supported routes; whole-system completeness remains
not established. `acceptance.json` retains dispositions for all fourteen original
items and records the current closeout separately from historical results.

## Final closeout (2026-10-28)

The accepted routes are language-sandbox-tool, tool-node-dispatch,
linux-worker-compute, output-publication, model-invoke-hook and dataset-read.
The runtime operation catalog is required by the route gate, and both Lean
audits pass. Application graph code and the runtime are trusted under D11;
tool bodies and generated code remain untrusted. Claims require the application
to follow the deployment rule in `docs/security/threat-model.md`. Direct LLM
calls inside trusted pandas nodes are outside the model-operation hook.

The separate C-closed cohort (`raw/pandas-closed-v1/full-v1/verification.json`)
records **45/50 utility successes**, with no evidence-integrity issues.
`monthly_mean` fails in all five repetitions with
`output_data:nonfinite_float`; these remain utility failures even though output
was refused safely. The cohort verifier correctly reports `passed: false`.
The v21 `json-null-v1` adapter transformation converts integer keys to strings
and non-finite values to null at the input/compute transport boundary. Vendor
code, tasks, oracle, model and retry limits were unchanged; the vendor recreates
NaN later for `monthly_mean`. This configuration has its own cohort identity;
the earlier A/B/C 150/150 result is a separate observation.

Final implementation validation retained by Claude: lint passed; the host
prebuilt suite recorded **5,621 passed, 8 skipped, 58 failed** due to unavailable
bubblewrap. The two affected test files passed **63/63** in the unconfined Docker
harness. The host suite itself did not pass. The eight closed-integration and
inventory tests passed. Logs: `raw/checks/claude-final-{lint,full-prebuilt,linux-docker}-v1.log`.
The cohort used rootless Docker with a mounted Cedar CLI, on the shared host.
The record discloses six unretained development runs; these are a provenance
limitation, not measured cohort evidence. Historical failures and open
out-of-scope limitations remain preserved.

No additional experiments or expanded proofs are required for this closeout.
Repairing `monthly_mean` would be prospective compatibility work with a new
cohort. The sections below retain the campaign history.

Closeout verification: `raw/checks/codex-eval-closeout-v1.json` records a fresh
six-route PASS with both Lean audits under `codex-eval-closeout-lean-v1`.
All check source identities match the current tree. Closeout lint passes and
the eval suite passes **152 tests, 2 skipped**; logs are
`raw/checks/codex-eval-closeout-{gate,lint,tests}-v1.log`.

## Earlier verified progress (historical)

- `make security-verify-regressions` passes. Forty current agent/model/hook/branch sites were explicitly reviewed against compile placement and the analysis adapter. Thirty-four stale reviews were removed. Repository waivers now bind the exact finding and analyzed source hash, and tests reject source changes at unchanged fingerprints. The review and trust assumptions are in `docs/security/escape-waiver-review-20261026.json`. This is source review, not proof of arbitrary callback confinement.
- At the grant-v3 checkpoint, `make security-verify` passed for `tool-node-dispatch`, `linux-worker-compute`, and `output-publication`. The final six-route result is recorded above. Whole-system completeness remains not established. The permutation gate passed separately.
- At the container-guardian-v2 checkpoint, prebuilt formatting, lint and the full suite passed: 3,905 tests (see `raw/checks/container-guardian-v2-full-tests.log`). The focused source-review/placement/analysis run passed 43 tests. The evaluation unit suite passed after the period API change; 22 focused serializer, contract, utility-oracle and period API checks also passed. The original failed full-suite log is retained; it found a stale waiver count assertion (56 versus the reviewed 61).
- New application versions preserve the original user request through the real upstream wrangling and visualization graphs. This fixes observed routing losses such as dropping “mean sales.” The adapter removes irrelevant generic cleanup instructions that could remove duplicates or impute missing values.
- Portable Plotly output expands typed buffers into equivalent JSON arrays and retains `plot_native`. It neither invents missing points nor changes values. The frozen utility oracle remains unchanged for valid outputs.
- `recursive-json-v2` explicitly supports Pandas Period values and PeriodIndex keys. Its six real A/B/C paired regression cases pass. Version 1 retains its prior refusal behavior.
- New cohorts use their own framework source tree and content-addressed source archive, with before/after per-trial identities. They do not execute a moving development checkout. `v11-source-capture-limitation.json` retains the earlier development cohort's provenance limitation.

## Retained development cohorts

All cohorts use the same frozen ten tasks and utility oracle. They are separate observations, not replacements for the original fifty trials per condition.

- `raw/pandas-v11`: original-request preservation, no graph retries. 24/30 outputs pass (8/10 in each of A, B and C). Remaining failures include dropping the first observed month and omitting a requested reduction.
- `raw/pandas-v12`: added period-boundary and aggregation guidance. 26/30 pass; retained failures expose incorrect generated joins between periods and raw timestamps.
- `raw/pandas-v13-pilot`: three successful date-filtered-total workflows from cohort-owned framework sources. This only validates the snapshot execution route.
- `raw/pandas-v14`: period-key guidance with zero retries. 20/30 pass; retained failures include unsupported Period serialization and generated-code errors. More instructions alone did not establish reliable utility.
- `raw/pandas-v15`: bounded upstream repair with three retries. Every model/computation attempt remains in the raw event logs. It still uses serializer v1, so the Period repair requires a subsequent cohort.
- `raw/period-serialization`: six deterministic original/repaired computation checks, all expected outcomes observed.

The latest default driver configuration is manifest v19: original-request preservation, explicit period handling, three bounded upstream repair attempts, and cohort-owned framework sources. A zero-retry development cohort can be requested explicitly with `--graph-retries 0`; original routing and serialization require `--workflow-contract original --sandbox-serialization original`. None of these commands recovers historical observations.

Production persistent-container execution now has a bounded implementation and a 60-pair useful-work cohort. Notebook's server boundary and the full mediation/composition proofs remain open. Controller-crash cleanup now has a production guardian and scoped runtime evidence; guardian/daemon/host failures still require external recovery. The new direct native filesystem matrix passes its supported cases; RPC identity remains unsupported on that route. Historical evidence and shared-host timing limitations remain as originally recorded.

`raw/pandas-v17` completed with 25/30 passes. Five monthly-total/chart failures remain. `raw/pandas-v18` completed with 30/30 utility passes with a general period-aggregation API, computing from input data and column names in the existing restricted execution namespace. It receives no task identifiers or oracle answers. This is one repetition of ten tasks per configuration; the full five-repetition acceptance cohort remains pending. The separate `raw/pandas-profiles-v18` cohort passes all ten utility checks and records policy/audit spans for every workload in C. Each nested span remains separate; no profiler times enter workflow timing. The full `raw/pandas-v19-full` cohort passes 150/150 trials, 50/50 per configuration. `verification.json` recomputes all outputs against the unchanged oracle, checks the exact matrix and validates source identities. `raw/pandas-v15` completed with 21/30 passes; its failed observations remain unchanged.

`raw/native-filesystem-matrix` contains 320 observations (20 repetitions of eight control/case pairs). Its verifier requires all controls, witnessed kernel denials for omitted reads, operator-policy replacement refusal, unchanged fixture content, zero resource RPC decisions and stable framework identities. All checks pass; RPC identity is explicitly unsupported. No injection claim follows from these deterministic manifest tests. The earlier pilot is retained in `raw/native-filesystem-pilot`.

`raw/openshell-native` adds 20 passing native OpenShell 0.1.3 trials using the official APF static projection. Direct and child-process reads allow Alice and deny Bob; effective authority matches the projected file policy. All sandbox deletions succeed. Bob file size remains visible in every trial. `raw/openshell-setup` retains release checksum verification, image/source identities, projection build, failed setup pilot, successful runtime pilot and lifecycle logs. This is static-policy runtime coverage, not dynamic APF service integration. Historical runtime unavailability is unchanged.

Production `DockerObjectDispatcher` is integrated with `cedar_security` and the real `ObjectPolicyHostExecutor` for exact read-only native file grants. `raw/container-dispatcher-full` passes 60/60 pairs: 20 principal changes, 20 graph-local policy changes and 20 broad-to-narrow transitions. Each pair includes useful sum computation, a same-authority persistence control, whole-container replacement, old-container absence, and cleanup checks. The independent saved-evidence verifier passes receipt consistency, source-archive integrity and exact-matrix checks. The driver was formatted after this cohort; the executed source bytes remain archived by hash, and production sources were unchanged throughout the run. Original evaluation-adapter results are separate and untouched.

The adapter pins the Docker daemon endpoint and tool/image bytes, checks confinement before releasing the worker, bounds pipe writes and response reads, and waits for cleanup across repeated cancellation. Tests exercise the pre-import activation barrier, process-creation denial, timeout cleanup and identity-bound reuse. The contract and limitations are in `docs/security/docker-dispatcher.md`. Runtime MAC now admits the exact production dispatcher at supported graph/ToolNode boundaries. Deployment policy changes require a fresh controller; live replacement remains forbidden. Controller-crash reclamation is now covered by a guardian under its stated survival and daemon-availability assumptions. No universal lifecycle guarantee follows. The failed component pilot, all earlier cohorts and failed check logs remain retained.

Latest checks: prebuilt `make format`, `make lint`, and `make test` pass, with 16 snapshots passing; test service cleanup also succeeds. All 108 evaluation unit tests pass. Eight negative verifier cases reject incomplete matrices, leaked private content, stale container state, missing reuse, lost utility, repeated nonces and failed cleanup. Security regressions and permutations pass; the full gate retains SGV901–903 with zero implementation tasks. Raw logs and source-bound JSON reports are under `raw/checks/container-final-*`.

`raw/container-mac-full` adds 20/20 passing operator-policy restart pairs (10 sync and 10 async). Each pair uses fresh real controllers and deployment policy files with the same application permit and manifest. The narrow operator policy removes the optional private-file grant while required-input computation still succeeds. Same-authority reuse, whole-container cleanup, old-state absence and refusal to replace sealed policy are checked. Independent verification validates the matrix, saved policies/results, cleanup coverage and source archive. Twelve negative verifier tests reject incomplete or inconsistent evidence. The original pilot and failed focused test run are retained; that run expected a resource-level error while its broader test forbid correctly denied the call earlier.

Cleanup backend exceptions now produce an unconfirmed outcome and retain quarantine rather than reaching a generic error path that could report termination confirmed. Focused runtime-MAC, container and lifecycle tests pass 46/46. Full security verification still reports SGV901–903, with zero implementation findings.

After runtime-MAC admission and cleanup exception handling, the full prebuilt suite passes 3,897 tests and 16 snapshots; service cleanup exits successfully. Formatting and lint pass. The evaluation suite passes 120 tests. Security regression and permutation gates pass, while full security verification retains SGV901–903. Latest logs are `raw/checks/container-mac-*` and `raw/checks/eval-container-mac-tests-v2.log`.

`raw/container-crash-full-v2` passes 80/80 real controller SIGKILL trials, twenty each for idle containers, active workers, delayed real creation replies and descendants retaining the controller pipe. Every trial first computes a useful result through the production host executor. Container absence and guardian exit are witnessed before harness cleanup. Independent verification checks the exact matrix, raw per-trial records, source archive, executed controller payload, wrapper identity and receipt consistency. The guardian records ownership before creation, checks labels before removal, preserves uncertain-create quarantine, and uses a controller-opened pidfd transferred at spawn to avoid PID lookup/reuse races. Its acknowledged source digest participates in runtime identity. A separate shutdown frame handles normal close with inherited pipe writers.

The first 80-case guardian cohort remains intact in `raw/container-crash-full`; it tested post-startup behavior and does not establish PID-reuse safety. The four-case pilot and failed test attempts remain recorded. One failed wrapper buffered the worker protocol; another exposed this Python build's missing `os.pidfd_open` wrapper. The implementation uses the actual libc kernel API and rejects missing capability. Neither failed attempt is replaced within a cohort. Guardian survival and a reachable Docker daemon remain explicit requirements; killing both controller and guardian, host failure, or persistent daemon failure is not a bounded-cleanup claim.

Final guardian checks: the full prebuilt suite passes 3,905 tests and 16 snapshots with service cleanup confirmed. Formatting, lint, security regressions and permutations pass. The evaluation suite passes 130 tests. Full security verification still fails on SGV901–903; no check was disabled or converted into a regression-only acceptance gate. See `raw/checks/container-guardian-v2-*`, `raw/checks/container-guardian-lint-v9.log` and `raw/checks/eval-container-crash-tests.log`.

The source verifier now follows function-local imports through supplied source exports and helper bodies. Unknown or executable initializers and package-export overwrites remain unresolved. Compiler symbol tables prevent unbound/deleted locals and cleared exception targets from falling back to globals, and reject global/nonlocal writes even when their declaration is in an untaken branch. `raw/verifier-local-binding-regression` records a prospective source-only comparison: the repository baseline accepted a candidate that can replace an authorizer with a forged decision; the revised checker refuses it. This is new regression evidence, not recovered historical evidence.

The final publication analysis visits 96 obligations (previously 87; the intermediate import implementation visited 116 before requiring parent initializer source), with the same 54 entries: 10 verified and 44 unresolved. Expanded analysis is not additional proof completion. Full security verification still retains SGV901–903 with zero implementation findings. The failed fixture-development logs and intentionally interrupted full test run are preserved under `raw/checks/local-import-*`.

The final import boundary also requires supplied source for every parent package initializer. Formatting and lint pass; the focused verifier suite passes 2,333 tests, and all 130 evaluation tests pass (two skipped). Security regression and permutation gates pass; full security verification still fails. See `raw/checks/local-import-v7-*` and `local-import-v7-eval-tests.log`. The full v6 suite was already running when the parent-initializer guard was added; the v7 focused suite exercises the final checker and all verifier regressions.

The full v6 prebuilt run completed successfully: 3,928 tests and 16 snapshots pass, and Docker test-service cleanup exits successfully (`raw/checks/local-import-v6-full-tests.log`). The final parent-initializer check was separately validated by the 2,333-test v7 verifier suite and the 130-test v7 evaluation suite. Full acceptance remains false.

A subsequent runtime regression exposed an output framing bypass: ordinary application dictionaries containing `type`/`data`, and some tuple shapes, were mistaken for framework stream envelopes. Fields outside the inferred payload escaped the output hook. The framework now supplies explicit private envelopes on a separate stream-filter route; ordinary final callback values are mediated in full. V2 interrupt values are included in the routed content, and label collection traverses framework `Interrupt.value`. Denied/redacted content is never reconstructed from the original payload. Framework-generated mode/namespace framing remains structural metadata; this is not a general metadata secrecy or derived-value provenance claim.

`raw/output-envelope-regression/comparison.json` records a prospective real-router comparison with archived baseline/current source bytes: the baseline returns the synthetic secret field, while the revised mediator returns `[redacted]`. A failed pilot used `repr` to inspect a field deliberately omitted from representation; its correction checks the returned object's actual value field. The pilot failure remains recorded. Core graph streaming/interruption tests pass 694 cases, with 115 Docker-dependent cases skipped under the explicit `NO_DOCKER=true` invocation. Both libraries' formatting and lint pass. The full system gate still rejects SGV901–903; additional stream entrypoints are unresolved proof obligations, not implicitly certified APIs.

The final focused placement suite passes 44 tests, covering both dict and tuple shape confusion, sync/async paths, both stream formats, multiple modes, subgraph framing and interrupt redaction. The 130-test evaluation suite passes. Security regression and permutation gates pass. The current publication denominator is 58 entries: 10 verified and 48 unresolved, with 46 analyzed publication obligations; the extra stream/helper entrypoints are included rather than excluded from verification. See `raw/checks/output-envelope-*`.

Ordinary v2 values retain the existing output-hook payload contract: the hook receives application fields directly, as in v1. Only a values emission containing interrupts bundles its data and interrupts for joint mediation. Four compatibility regressions verify this across sync/async and v1/v2; the final focused placement run passes 48 tests. `final-source-supplement.json` archives the final code separately from the initial runtime comparison.

The full prebuilt run passes 3,950 tests and 16 snapshots, with Docker test services removed successfully. That run started before the final core v2 compatibility adjustment and eight additional placement cases; final-code validation separately passes the 694-test core suite (115 explicit skips), all 48 placement tests, formatting/lint in both libraries, and 130 evaluation tests (two skips). Full acceptance remains false: the complete security gate exits 2 and retains SGV901–903; regression and permutation gates pass. The final reports are `raw/checks/output-envelope-final-*`, the full run is `output-envelope-prebuilt-full-tests.log`, and final focused/core checks are `output-envelope-placement-tests-v6.log` and `output-envelope-langgraph-tests-v2.log`.

Legacy `astream_events` v1/v2 had a separate publication bypass: inner-node stream/end events retained protected values even when ordinary graph output was redacted. The event iterator now routes each complete event through the configured output mediator. Allowed records retain their structure; when policy replaces an event with another value, a fresh synthetic custom event carries only that effective value, with empty tags, metadata and parent IDs. The original event's fields are not copied into the replacement. Approval continuation uses the same event reconstruction. Denial, cancellation and explicit consumer close close the underlying event producer. The installed upstream's synchronous legacy event API remains unsupported; no sync execution coverage is claimed.

`raw/legacy-event-regression/before.json` records two leaking inner-node events for each async legacy version. The final `after.json` records zero in the same synthetic probe; the preliminary post-fix observation remains separately in `after-pilot.json`. Five selected runtime source files are archived by hash per probe; this is a bounded prospective regression, not a complete environment capture or historical provenance reconstruction. The initial probe import-path failure and test fixture failures are preserved in raw logs. SGV109 now detects the original direct-return pattern and its local aliases; `source-regression.json` confirms it finds the archived baseline and clears the repaired path. The checker expressly does not certify arbitrary filter helpers.

Focused validation passes 91 prebuilt tests and 9 core tests (three context-variable-version skips in the core Python 3.10 environment). Both libraries' format/lint checks pass. The 130 evaluation tests pass. This work covers legacy event iterator publication, not every user-provided callback handler, log/state API or derived-value provenance path. These remain within the broader open placement/composition obligations; no universal publication claim is made.

A follow-up audit separately found the inherited `astream_log` API publishing the synthetic canary in two of five patches (`raw/legacy-event-regression/log-api-open-gap.json`). This was an explicit runtime publication failure, not merely a source-model limitation; the event-only repair did not close it. The subsequent log repair is recorded below. The broader goal remains incomplete. The final core run passes 703 tests with 118 explicit skips under `NO_DOCKER=true`; the skip count includes Python-version context-variable exclusions.

The subsequent log repair authorizes complete states from `astream_log(diff=False)` internally and emits only fresh root-replacement patches or snapshots built from the effective state. It never returns the producer's raw operation history. Root replacement remains applicable after redaction, and a deep copy prevents a consumer from mutating the internal state through a published patch. Allowed logs retain their application outputs; replacement values become a fresh synthetic log with no original node logs. Approval continuations reconstruct the same patch/snapshot type. Both modes close their producers on denial, cancellation and consumer close. Unsecured graphs retain the upstream log implementation.

`raw/legacy-event-regression/log-api-repair.json` records zero canary-bearing patches in both modes and successful reconstruction of the redacted final state. The original leaking observation remains unchanged in `log-api-open-gap.json`. Final focused tests pass 104 prebuilt cases; 17 core checks pass with three Python-version skips. The failed utility fixture expected values-mode output, but the log API uses node-keyed updates by default; the corrected fixture checks the explicit expected node-keyed computation result and retains the failure log. SGV109 now covers direct-return/alias patterns for both event and log iterators, and the required-method inventory rejects silently inheriting an unmodeled log boundary. This does not prove all callback handlers, state APIs or derived-value provenance paths.

The full prebuilt event-phase run completed with 3,972 passing tests and 16 snapshots, and Docker test services were removed successfully. That run began before the subsequent log repair; final-code validation separately passes 104 focused prebuilt checks, 711 core graph checks (118 explicit skips), and 130 evaluation checks (two skips). Both libraries' formatting/lint pass. Security regression and permutation gates pass; the strict security gate still exits 2 on SGV901–903 with zero implementation findings. The current source inventory has 2,850 definitions and 58 publication entries (10 verified, 48 unresolved). Final event runtime capture is `after-final.json`; the saved log repair source hashes also match the final selected source bytes. No completion claim follows from these checks.

Direct callback observers had an independent publication leak: the saved synthetic baseline delivered one canary-bearing `on_chain_end` record in each sync/async case despite redacted graph output. Callback managers now wrap ordinary observers and stream taps before framework execution. Each callback record includes an opaque observer binding and passes through output mediation before delivery. Redacted callbacks are reconstructed from effective values, preserving only validated framework control UUIDs where collector correlation requires them. Error callbacks receive payload-only exceptions without live tracebacks or approval continuations. This does not establish metadata secrecy or isolate arbitrary host callback code.

Stream taps see mediated values while graph computation retains its original values; guards reject tap changes to output identity/cardinality and observer retargeting. Reused managers are rebound to the current invocation configuration. Approval continuations perform the withheld observer delivery; asynchronous observer continuations use `aresume`. Cancellation prevents delivery even when a policy converts cancellation into another result. Tests cover allowed useful output, denial, redaction, approval, interruption and error observers, sync/async handlers, tap preservation and authority rebinding. Failed proxy/protocol/fixture iterations remain in `raw/checks/callback-*` and `raw/callback-regression/pilot-failures.json`.

`raw/callback-regression/after-final.json` records zero canary-bearing callback records for both paths and archives selected final source bytes. The original `before.json` and intermediate captures are retained. Final focused validation passes 86 prebuilt checks and 25 core callback/event checks. The broader core run passes 720 tests with 118 explicit skips; it began before the final two tap-retargeting tests and guard check, which the final focused run validates. The evaluation suite passes 130 tests with two skips. Both libraries' formatting and lint pass. The full prebuilt run and strict gate are recorded separately below when complete; no successful regression is treated as complete mediation.

The final callback security reports retain SGV901–903: strict gate exit 2, regression gate exit 0, permutation gate exit 0. The source inventory contains 2,873 definitions and 60 publication entries (10 verified, 50 unresolved, 51 publication obligations), with zero implementation findings. See `raw/checks/callback-final-*.json`. Adding callback mediation increased the explicit proof surface; it did not close the proof model.

The full prebuilt run completed with 4,003 passing tests and successful Docker test-service cleanup (`raw/checks/callback-prebuilt-full-tests.log`). It started before the final tap observer-binding check and two corresponding core tests; those final changes pass the separate 25-test core focused run. Final prebuilt focused coverage passes 86 cases. Strict acceptance remains false despite the passing compatibility suite.

Current-state and history inspection exposed a further canary despite redacted live output. `raw/state-publication-regression/before.json` records the canary in both current snapshots and two history rows per sync/async path. All four state inspection APIs now mediate the complete `StateSnapshot` with the caller's output boundary, including snapshots returned by delegated subgraphs. A replacement value produces a fresh snapshot containing only that effective value, with empty task/interrupt/config fields and no original metadata, timestamp or parent config. Allowed snapshots retain their useful values and checkpoint identity. Redacted snapshots are intentionally not checkpoint navigation handles; callers retain their original invocation configuration.

History output authorization uses the current caller configuration rather than the stored checkpoint's configuration. Bound graph configuration is merged before subgraph delegation. Delegated history iterators close on denial or consumer close. Snapshot approval continuations reconstruct the same effective snapshot representation. Labels on interrupt values and task results participate in complete-snapshot mediation. No claim follows for untracked derived values, arbitrary opaque objects, general metadata secrecy or arbitrary host callback isolation.

`raw/state-publication-regression/after.json` records no canary in either current state or history, with selected runtime source bytes archived. The original and pilot captures remain unchanged. `source-regression.json` shows SGV110 detecting eight raw snapshot return/yield patterns in the archived baseline and none in the repaired source. Required source inventory now includes all four state inspection methods. This is an observed-pattern check, not an arbitrary helper or complete provenance proof.

Focused validation passes 106 prebuilt publication cases, 74 state/verifier/report cases and eight core subgraph cases. Failed setup/fixture attempts remain in raw logs and `pilot-failures.json`; the existing utility node appends `!`, and final assertions check that output. Formatting and lint pass for both libraries, and evaluation tests pass 130 cases with two skips. Strict security verification still exits 2 on SGV901–903; regression and permutation gates pass. The inventory contains 2,876 definitions and 60 publication entries (10 verified, 50 unresolved); no proof gap is waived. Full library results are recorded below after completion.

The state-publication prebuilt run completed with 4,030 passing tests and successful Docker service cleanup. The selected core streaming/state suite passed 685 tests and 44 snapshots, with 115 explicit Docker skips. These runs predate the subsequent language-sandbox work. The evaluation goal was paused at the user’s request before that new task.

After the goal resumed, language admission gained a structural type/effect
checker for the actual lowered program. Every instruction and branch must derive
inert local/result types and a finite set of statically admitted terminal calls.
Unknown constructs, unbound locals, mutable instructions, unsupported types,
invalid call signatures and analysis-budget exhaustion refuse admission before
any effect. Execution recomputes the derivation, snapshots terminal/contract maps,
and validates terminal result types. This adds an enforced component obligation;
it does not discharge SGV901–903 or certify interpreter/terminal/host composition.

`raw/proof-language/derivations-v2.json` contains fresh derivations for actual
sync, async and two-read admitted tools, plus archived source bytes. The earlier
capture is retained. Reports bind the source text and lowered program, enumerate
effects and retain open composition dependencies with `system_complete=false`.
Initial formatting/test attempts remain in `raw/checks/proof-language-*`.

The program-proof batch's full prebuilt run passes 4,073 tests and 16 snapshots,
with successful Docker service cleanup. It started before the final terminal-map
snapshot guard and its regression test; the final focused run separately passes
166 checks. Formatting/lint pass, and evaluation unit tests pass 130 cases with
two skips. The strict system gate remains incomplete; this batch does not
replace the outstanding placement, adapter or host-composition proofs.

The next proof extension checks the router's normal-return protocol on every
source path. All 21 discovered entries must return their exact authorized
dispatch result; framework permission routes may additionally return the
unchanged authorization record on an ESCALATE branch. Resume and tool-call
routes have no pending-approval return alternative. Mutation, possible aliases
to mutable primitive inputs, substituted values, missing entry contracts and
unknown analysis prevent a proof. This provenance evidence grants no publication
permission and does not classify exception payloads.

The factory's existing source/loaded-code admission check now requires these
return obligations. Tests compile source candidates without executing them and
confirm that matching loaded bytecode is refused when the source returns raw
input after dispatch. `raw/router-return-proof/capture-v1/capture.json` records
the actual router's fresh source proof and runtime binding, plus four rejected
source-only counterexamples and archived selected source bytes. No candidate
body was run. The source-only observations are not runtime leak measurements.

The final transfer-engine and router checks pass 2,411 tests, including the
two source/bytecode-matched admission refusals. Failed initial assertions are
retained in `raw/checks/router-return-tests-v2.log`. The strict security report
retains SGV901–903 with zero implementation findings and 60 publication entries
(10 verified, 50 unresolved). Caller receiver binding, handling of return
alternatives and broader adapter/host composition still require proofs.

The full prebuilt run passes 4,112 tests and 16 snapshots, with successful Docker
test-service cleanup (`raw/checks/router-return-full-tests.log`). It started
before the final conservative input-alias dependency refinement and four added
tests; the final 2,411-test transfer-engine run separately validates that delta.
Formatting/lint pass. Strict security verification exits 2, and the regression
gate exits 0; these results remain separate from system acceptance.

Receiver binding is now modeled for explicit native exact-type guards over
source classes with checked fixed slots and a direct `object` base. A class
annotation or `isinstance` is insufficient; ordinary dictionary-bearing inputs
can shadow methods and remain unresolved. Unknown slot presence has both normal
and exceptional paths, and input aliasing conservatively invalidates grants.
Source method bodies are analyzed after the guard rather than declared opaque
authorizers. `HostRouter` now has fixed `policy`/`host` slots; admission checks
their native descriptors and instance methods cannot be replaced.

Output publication captures and checks the exact router at use, and approval
continuations retain that router across later mediator rebinding. The bounded
sync/async capture at `raw/receiver-binding-proof/capture-v1/capture.json` records
rejected instance method replacement, successful useful approval release through
the original router, and refusal of a later unsupported router with zero calls
to its methods. This is a targeted runtime refusal/continuation check, not an
injection-security or complete-mediation claim.

The current publication analysis now enters the actual `HostRouter.output_emit`
and `route` bodies (and their async counterparts) from `OutputMediator`. It still
reports policy/host slot calls, input shapes and continuation publication as
unresolved. Exact method receiver identity does not establish the authority of
slot contents. The report retains 60 publication entries (10 verified, 50
unresolved) and now exposes 58 publication obligations; none is silently omitted.

Focused source/runtime checks pass 2,498 tests. Initial capture fixture errors
(missing escalation checkpointer and using the compiled graph instead of the
builder's mediator) remain in `raw/checks/receiver-binding-tests-v2.log`.
Formatting/lint and the regression gate pass; strict acceptance remains false
on SGV901–903. Full-library results are recorded separately when complete.

The full prebuilt run passes 4,154 tests and 16 snapshots, with successful Docker
test-service cleanup (`raw/checks/receiver-binding-full-tests.log`). It began
before the final repository-publication regression and report metadata; the
2,498-test focused run includes that regression, and the fresh capture contains
the final metadata and matching selected source hashes. The permutation command
passes 28,800 source-binding cases and 2,444 runtime-denial cases. The final strict
gate still exits 2 with SGV901–903; these tests do not close composition evidence.

The next composition batch validates exact native principal/configuration shapes
before identity or credential hooks. It checks string keys through a native item
snapshot rather than copying an unvalidated dictionary: a sparse dictionary copy
can invoke equality on colliding foreign keys. The source transfer engine now
derives the actual guarded copy loop by induction, without treating its helper
name as authority. Principal credential containers and locks are validated while
module-owned values remain opaque. Unsecured ToolNode calls read direct principal
bindings without probing unrelated runtime contexts; secured calls retain strict
context admission. Read-only transform arguments use a validated tuple-backed
mapping, because an exact mapping proxy need not wrap a native dictionary.

`read_text` now pins the authorized canonical file with Linux `openat2`, opens
only its owned descriptor, checks regular-file identity and closes descriptors on
all exits. Real leaf/ancestor symlink-swap tests refuse; a swap after pinning
continues to read the pinned object. Missing descriptor mechanisms refuse without
a pathname fallback. The contract binds the object at terminal open, not a prior
inode/content snapshot. Invalid UTF-8 errors retain no decoding payload context.
Direct native async executors wait through repeated cancellation; Landlock
cleanup checks worker, cgroup when present and broker lifetime and refuses
unconfirmed success. Production no-cgroup lifetime reasoning depends on the
fixed minimal seccomp filter; historical exec-enabled evaluation workers remain
outside that argument.

The output mediator and object host now have fixed slot layouts, and label
collection, routing and approval continuations check the captured router/host
pair. The saved pre-validator source derivation is
`raw/composition-proof/capture-v1`: it proves guarded dictionary normalization
under its synthetic caller contract and conditional host output correspondence
for that source snapshot. Parenthesized annotations are rejected in dataclass,
NamedTuple and TypedDict models; annotations that do not create fields cannot
supply phantom data projections.

A later prospective audit found three additional output failures.
`raw/output-data-admission/before-v2/capture.json` records missed confidentiality
inside a nested labeled value and message metadata, a custom mapping method
executed during label collection, and approval of content changed after
escalation. Closed bounded data traversal now collects nested and message fields,
refuses unknown capabilities before their protocols run, and conservatively
inherits state-channel labels without payload equality. Effective output requests
are re-admitted after transforms and at host dispatch. Output approvals include
a tagged structural content digest. `after-v1/capture.json` records both secret
labels, zero hostile mapping calls and refusal of the changed approval. Its
selected source bytes are retained. The failed initial probe import and
development tests remain separate.

These runtime repairs add proof obligations. The current source checker derives
the exact native request guards but leaves the reachable output validator
unproved; its earlier component proof is not substituted for current evidence.
The final v2 strict report has 2,940 declarations, 60 publication entries (9
verified, 51 unresolved), 30 publication obligations and 21/21 router entries.
Zero implementation findings remain; SGV901–903 still fail. Input validation
does not detach mutable payloads, authenticate untracked provenance, prove
class/runtime bindings or establish atomicity against concurrent controller
mutation.

The first full prebuilt run of this batch retained 113 failures and 4,156 passes.
Most failures came from unsecured ToolNode identity probing; the remaining
cleanup test expected its earlier broker-specific error. The repaired versions
of all 113 recorded cases pass separately. Final formatting/lint, 33 core
publication checks and 130 evaluation checks (two skips) pass. The replacement
full-library result is recorded below when complete. No failed observation was
overwritten or removed from its measured cohort.

The replacement full-library run is **not green**: `composition-full-prebuilt-v2.log`
retains 4,496 passes and one failed assertion in
`test_actual_decision_transform_copies_arguments_into_readonly_view` (16 snapshots
pass). The tuple-backed decision argument constructor now needs an additional
source derivation; the fixture currently supplies only `Decision` source, and
the checker cannot certify its new helper. The positive assertion remains in
place. Runtime mapping tests passing do not discharge it. This is a concrete next
proof dependency alongside the output walker, not a waived test or replaced
observation. Docker test-service cleanup completed successfully.

Final focused output checks pass 88 cases, and the post-format runtime comparison
is `raw/output-data-admission/after-v2/capture.json`. The v2 strict/regression/
permutation gates exit 2/0/0 respectively. `raw/composition-proof/final-v2`
archives all 229 Python source files used by the current placement inventory,
plus selected tests/docs (250 files total), and verifies every inventory source
digest against the report. This is a current source snapshot, not a complete
dependency/environment archive or reconstructed historical provenance. Full
acceptance and the goal remain open.

## Lean worker lifecycle component (2026-10-27)

The opt-in synchronous Linux route now executes a captured Lean decision core
before `GO` and after confirmed cleanup. [The formal audit](raw/checks/lean-worker-formal-v3/report.json)
checks 29 model theorems through 17 fixed semantic obligations, the identity
schema, 15 driver tests, and Lean kernel replay. Replay uses Lean
itself; it is not an independent checker. Source, runtime, compiler, decoder,
OS refinement, and system completeness remain false.

[155 focused tests](raw/checks/lean-worker-final-runtime-v1.log) pass using the
final captured executable. [Three native cases](raw/checks/lean-worker-native-v5.json)
exercise a useful permitted read, undeclared-file denial and fork denial through
real bubblewrap/seccomp activation and cleanup. The outer Docker harness runs
on the same host with its AppArmor/seccomp/systempaths restrictions explicitly
relaxed. This does not add an independent VM, a production application cohort,
or universal confinement evidence.

The strict [system report](raw/checks/lean-security-v2.json) still fails with
SGV901–903. The [regression report](raw/checks/lean-regressions-v2.json) and
[finite permutation report](raw/checks/lean-permutations-v1.json) pass their
respective gates. A [443-file source capture](raw/lean-integration-v1/source-capture.json)
retains selected framework, tests and configuration; [verification](raw/lean-integration-v1/verification.json)
checks all 199 declared inventory source identities in the fresh strict report.
It is not a complete dependency/OS archive and was captured after broad-suite
startup; that timing is explicit in its manifest. The previous source index is
retained beside it before refreshing `current-sources.json`.

Failed native setup pilots, the earlier JSON decoder counterexamples, the
source-hygiene audit failure and the first full-suite failure remain under
`raw/checks/lean-*`. Existing historical observations are unchanged. See the
[implementation guide](../../../docs/security/lean-worker-route.md) and
[timestamped work log](../../status.md).

The final full-library `make test` run passes **4,886 tests and 16 snapshots**
with three native opt-in cases skipped in that run; all three pass separately
in native-v5. `make format` and `make lint` pass. The first full-suite failure is
retained. See [final check accounting](raw/lean-integration-v1/final-checks.json).
Remote GitHub Actions has not been dispatched.

## 2026-10-27T14:40:43.242554+00:00: Receipt, descriptor and native setup repairs

New prospective evidence is retained in [raw/composition-activation-v1/final-checks.json](raw/composition-activation-v1/final-checks.json). The receipt gate now requires exact unique adapter evidence and matching obligation coverage. Output descriptor capture refuses substituted non-native layouts before invoking them. Linux cleanup signals a pidfd after rechecking recorded identity; resource opens reject symlinks across every component; command setup retains ownership until transfer and attempts independent cleanup on failure.

Prebuilt format/lint pass. Full `make test`: **5053 passed, 3 skipped, 16 snapshots passed**. The three native Lean cases separately pass against the retained formal-v3 executable on the current sources. Output-wrapper/constructor/descriptor source derivations pass 337 focused checks; they remain conditional source results, not additional Lean proofs. The 451-file capture preceded the full suite and remained stable; each fresh strict/regression report matches all 233 declared inventory source identities.

Strict verification still exits 2 with SGV901–903, zero implementation tasks and publication 9/60 (51 unresolved). Regression and permutation gates pass without overriding strict acceptance. Earlier Linux and receipt source-review digests remain stale; they were not refreshed to manufacture acceptance. The Lean sources/executable still match the earlier audit; no new kernel replay is claimed. The proposed receipt-composition plan is unimplemented.

Recorded PID/start-time provenance, stable procfs and namespace/content assumptions remain. Failed artifact deletion can leave residue; arbitrary interruption is not proved. Inherited caller exception context and traceback frames remain observable, now correctly stated by the source report and a reproducing regression. Shared-host timings are validation durations only. Historical failures, unselected routes and original acceptance dispositions remain unchanged.

## 2026-10-27T16:15:55.037726+00:00: Lean receipt-v2 composition

The optional synchronous Linux route now supplies actual assignment, native-plan and activation-evidence rows to the compiled Lean core before GO and after confirmed cleanup. The detached certificate is reused without mutable aliases; old protocols and incomplete coverage refuse. [Final checks](raw/receipt-integration-v1/final-checks.json) retain commands and identities.

The captured [formal audit](raw/checks/receipt-formal-v1/report.json) checks 54 model theorems, 37 fixed typed obligations, 18 driver tests, two negative controls and fresh same-kernel replay. The exact audited artifact passes 180 bridge tests, 118 selected integration tests and three direct native cases. Full prebuilt: {'passed': 5162, 'skipped': 3, 'seconds': 565.98, 'snapshots_passed': 16}; eval: {'passed': 143, 'skipped': 2, 'seconds': 4.74, 'snapshots_passed': 0}. Format/lint pass. All 457 captured files remain unchanged, and both strict/regression inventories match all 233 source identities.

The new [150-trial Pandas cohort](raw/pandas-receipt-v2-full/validation.json) retains the original tasks/repetitions/oracle and explicitly selects the pinned v2 artifact for C. Passes: {'A': 50, 'B': 50, 'C': 50}; failures: []. A separate pilot remains retained. These are useful execution observations on a shared host, not a security proof or isolated performance result.

Strict verification still exits 2 for SGV901–903; regression and permutation gates exit 0. Grant inventory completeness, semantic lowering, Python placement/binding, outer-graph effects, publication and runtime/compiler/decoder/OS correspondence remain open. The model covers supplied assigned obligations; it does not derive the grant requirements or hash preimages. System acceptance and goal remain open.

The [formatter incident](raw/formatter-incident-v1/README.md) is disclosed separately: 1,334 archived Python files were accidentally formatted, then restored; 1,323 match prior recorded hashes and 11 rely on recorded source writes without prior hashes. One additional timestamp candidate was unchanged. Quarantined bytes and all recovery records are retained. Protected formatting now leaves archived evidence unchanged. The old-binary native harness failure and every failed pilot remain visible; no recorded expected hash was updated to disguise a failure.

## 2026-10-27T17:44:24-04:00: Route-scoped acceptance and grant-v3 Linux worker

The advisor-approved acceptance boundary is now the declared routes in
`docs/security/supported-surface.json`, not whole-system completeness. The current
grant-v3 audit (`raw/checks/codex-grant-lean-audit-v2/report.json`) passes 72 fixed
Lean obligations, five negative controls, 20 driver tests, fresh kernel replay,
and stable source identities. The exact audited binary
`6097be9b7b84639959c7a0b9de31c79f23486e9f01bf1b6de575dfab25c7cb08`
passes 349 focused bridge/integration tests and three direct native cases.

`raw/pandas-grant-v3-full-v1` is a new, separate 150-trial cohort against that
binary. Independent verification passes the complete A/B/C matrix (50/50 each),
the unchanged utility oracle, frozen framework identities, and twelve current
route/application source hashes. The receipt-v2 cohort and all failed grant-v3
pilots remain historical evidence.

`linux-worker-compute` is promoted only for generated computation inside the
worker. Worker-private `/tmp` remains intentionally writable, and network/kernel
enforcement remains an explicit OS premise. Pandas model calls, input loading,
checkpointer state, human-review continuations, Streamlit/session storage, and
outer-graph publication are outside this route and gain no support claim.
Whole-system completeness, compiler/decoder/OS refinement, and the audit's other
listed premises remain not established.
