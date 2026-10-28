# Security remediation handoff

Updated **2026-10-27, approximately 08:43 UTC**. This is a handoff of the working
tree, not a completed security proof or a release approval.

## Read this first

The evaluation has substantial prospective repairs, and the known implementation
findings in the last strict report are cleared. **System acceptance still fails
on SGV901, SGV902 and SGV903.** Restricting the tool language removes many Python
escape paths, but does not itself prove the surrounding framework, authorization,
publication, host activation or worker lifetime.

The user's policy is: **if a path cannot be proved, disallow it**. Apply that at
the actual admission/execution boundary. Do not turn an unsupported analysis into
success, replace a useful positive test with blanket denial, make a helper name
or digest an opaque proof exemption, or change the acceptance gate to hide a gap.

The user also clarified terminology: a source-available, admission-tested tool
is a **language-sandbox tool**. `inprocess` describes its execution location.
Neither means that its body belongs to the trusted computing base. The actual
controller, policy engine, mediators and kernel assumptions remain distinct.

The checkout is `/data/langgraph`, branch `wip`, HEAD
`40e24e978f9ec2e8f061abb21077e2251583f5e5`. There are extensive uncommitted changes
and untracked files from this campaign and earlier work. **Preserve that tree;
do not reset or assume every dirty file belongs to the latest batch.** No commit
or PR was created for this handoff.

Start with these records:

- [Campaign narrative](campaigns/remediation-v2/README.md).
- [Acceptance dispositions](campaigns/remediation-v2/acceptance.json).
- [Last strict report](campaigns/remediation-v2/raw/checks/composition-security-final-v2.json).
- [Source verification design](../docs/security/source-verification.md).
- [Historical failures](campaigns/remaining-v1/completed-v2/FAILURES.md).

The campaign narrative, acceptance JSON, `current-sources.json`, and `final-v2`
source archive **predate the newest edits described here**. They retain their
historical observations; they need a new prospective update after the next full
verification pass. This file records the newer state without rewriting them.

## What has been implemented

### Tool language and Python escape paths

- `EnforcementKind.LANGUAGE_SANDBOX = "language_sandbox"` is canonical.
  `TRUSTED_TOOL` remains an alias; parsing `"trusted_tool"` is deprecated.
- Source admission lowers a small language into immutable instructions. Execution
  interprets those instructions rather than invoking the original Python tool
  body. Imports, reflection, arbitrary attributes/calls, dynamic compilation,
  arbitrary helpers and library capabilities are outside that language.
- Structural type/effect derivations check every instruction, including otherwise
  unreachable branches. Calls must target registered terminal contracts; inputs
  and results must be admitted inert data. Unknown constructs refuse.
- Captured terminal implementations and source/loaded-code checks prevent a
  post-admission replacement of the tool function from selecting a new Python
  execution path. Terminal and interpreter implementation correspondence still
  need composition evidence.
- Native type checks now use identity rather than membership in a set of types:
  a foreign metaclass can execute `__hash__` or `__eq__` during the latter.
- Function globals/default containers are checked before their protocols can
  run. Loaded code is compared through a native tagged fingerprint, not equality
  on arbitrary `co_consts` values. The newest fingerprint includes
  `co_exceptiontable`.
- The latest review found forged nested `Signature` and `TerminalContract`
  metadata that could run foreign methods before rejection. The saved repair
  validates and reconstructs these records and executes using captured local
  program/signature/terminal/contract snapshots. An exact mapping proxy alone is
  insufficient: signature admission inspects its native backing through
  `gc.get_referents`, accepts only exact dict/OrderedDict storage, validates keys
  before lookup, preserves OrderedDict order, and refuses unsupported layouts.
  This is a bounded interpreter-layout dependency, not a portable Python theorem.

Main files:
[inprocess.py](../libs/prebuilt/langgraph/prebuilt/security/inprocess.py),
[_language_sandbox.py](../libs/prebuilt/langgraph/prebuilt/security/_language_sandbox.py),
[language_verification.py](../libs/prebuilt/langgraph/prebuilt/security/language_verification.py),
[language_sandbox.py](../libs/prebuilt/langgraph/prebuilt/security/language_sandbox.py).
Tests: `test_language_sandbox.py`, `test_language_verification.py`,
`test_manifest_admission.py` in `libs/prebuilt/tests/security/`.

### Principal, configuration and policy-result shapes

- Configuration dictionary keys are checked through native item snapshots before
  copying or hashing. Even a native sparse dictionary copy can invoke equality on
  foreign colliding keys; a saved probe demonstrates that issue.
- Principal admission checks exact Principal, native identity/credential fields,
  Blobs/Slot storage and native locks before hooks. Module-owned slot values remain
  opaque; this is not an immutable-credentials theorem.
- Unsecured ToolNode calls avoid probing an unrelated runtime context while still
  honoring a directly bound principal. Secured calls retain strict admission.
- Decision transform arguments use a validated tuple-backed `_DecisionArguments`
  mapping. A mapping proxy is not accepted just because the proxy type is exact.
- The generic source verifier now follows the actual Decision constructor,
  `_decision_arguments` and `__getitem__`. The original positive copy/index
  preservation assertion is retained and passes. Explicit initializer semantics,
  effects and alias mutation are analyzed; unmodeled Mapping mixins/truth remain
  unresolved.

Main files: [binding.py](../libs/prebuilt/langgraph/prebuilt/security/binding.py),
[types.py](../libs/prebuilt/langgraph/prebuilt/security/types.py),
[verification.py](../libs/prebuilt/langgraph/prebuilt/security/verification.py).
Relevant tests include `test_principal_admission.py`, `test_decision_admission.py`,
`test_verification_dictionary_admission.py`, `test_verification_mapping_records.py`
and `test_verification_records.py`.

### Output mediation and output data

- OutputMediator and ObjectManagerHost have fixed slot layouts. Mediation captures
  the exact router/host pair, checks it before label collection and routing, and
  retains it through approval continuations. Replacing the captured router's host
  is refused.
- Closed bounded output traversal replaces arbitrary object/mapping/serializer
  traversal. Explicit framework and LangChain record projections include nested
  labeled values, message metadata, extras and private storage. Unknown types
  refuse before their protocols run.
- Matching state-channel keys conservatively inherit labels without comparing
  arbitrary payload values. Effective output requests are admitted again after
  transforms and at host dispatch.
- Output approval subjects include a tagged structural content digest plus
  destination, output ID, labels, clearance and principal context. Changing
  content after escalation invalidates the prior approval.
- These changes **do not detach mutable payloads**, authenticate untracked derived
  provenance, or establish atomicity against concurrent privileged-controller
  mutation. Those premises/obligations must remain visible.
- `output_verification.py` derives request classification and identifies the
  reachable validator dependency. Current host-output correspondence remains
  `proved=false`; an earlier proof of the branch before validator integration is
  preserved only as evidence for that earlier source snapshot.
- `output_data_verification.py` derives seven conditional primitive contracts:
  `_Walker.__init__`, `charge`, `string`, `pairs`, `string_set`, `labels`, and
  `channel_labels`. It consumes their source grammar and derives native operations,
  ownership, finite snapshot inductions and source descriptor projections.
- The newest extension checks the scalar-return prefix of `walk` for None,
  exact str/bool/int/finite float/bytes. **The recursive suffix and whole method
  remain unproved.** Compiler symbol tables prevent a later lexical binding from
  changing the prefix's builtin lookup. Actual callee signatures are now checked
  at helper calls, including keyword binding.
- Layered/developer reports now include `output_data_primitives` and
  `output_data_primitive_contracts_complete`. These fields do not close the
  validator, effect-safety, runtime-binding, initialization or system gates.

Main files:
[output_data.py](../libs/prebuilt/langgraph/prebuilt/security/output_data.py),
[output_data_verification.py](../libs/prebuilt/langgraph/prebuilt/security/output_data_verification.py),
[output_verification.py](../libs/prebuilt/langgraph/prebuilt/security/output_verification.py),
[object_manager.py](../libs/prebuilt/langgraph/prebuilt/security/object_manager.py),
[stack.py](../libs/prebuilt/langgraph/prebuilt/security/stack.py),
[layered_verification.py](../libs/prebuilt/langgraph/prebuilt/security/layered_verification.py).
Tests are the `test_output_data*`, `test_output_*binding.py`,
`test_output_verification.py` and layered/developer report tests.

### File terminals, typed resource transport and worker lifetime

- `read_text` uses Linux `openat2` to pin the authorized canonical regular file
  without traversing symlinks, reopens its owned descriptor and checks identity.
  There is no unsafe pathname fallback. The binding is at terminal open, not a
  historical inode/content snapshot. Invalid UTF-8 refusal retains no decoding
  payload exception context.
- Direct native async executors wait for worker completion despite repeated
  cancellation. Landlock cleanup requires confirmed worker/cgroup-when-present/
  broker cleanup and does not report successful completion on unknown lifetime.
- The production minimal seccomp profile prevents process/thread creation; the
  historical exec-enabled evaluation profile remains a separate contract.
- The latest typed resource audit reproduced foreign result-key equality and
  custom payload membership running during validation. Native TypedDict result
  keys are now validated before hashing/lookup. The resource transport passes the
  validated tuple-backed argument record, and typed backend payload admission
  snapshots it before membership or binding. An initial repair rejected the
  framework's own mapping-proxy transport; that compatibility failure is retained,
  and the record transport repair passes the native broker test.

Main files: `inprocess.py`, `linux.py`, `landlock.py`,
[mediators/contracts.py](../libs/prebuilt/langgraph/prebuilt/security/mediators/contracts.py),
[resource_mediator.py](../libs/prebuilt/langgraph/prebuilt/security/resource_mediator.py).
Relevant tests: `test_language_file_binding.py`, `test_native_async_lifetime.py`,
`test_typed_mediators.py`, `test_resource_binding.py`, `test_resource_mediator.py`.

### Earlier campaign work that should not be repeated blindly

| Area | Prospective result / remaining limit |
| --- | --- |
| Pandas utility | `raw/pandas-v19-full`: 150/150 trials, 50/50 in A/B/C, against the unchanged ten-task oracle. Original failures remain. |
| Pandas profiling | `raw/pandas-profiles-v18`: all ten workloads in C have useful runs with policy/audit spans. Separate inclusive profiling scope; not all configurations or historical phases. |
| Production containers | Dispatcher 60 lifecycle pairs; operator-policy cohort 20 pairs; guardian v2 80 real SIGKILL trials with pidfd ownership. These are runtime evidence, not a complete lifecycle proof. |
| OpenShell | Pinned native 0.1.3 runtime, official APF static projection, 20/20 paired trials. Dynamic APF service integration is outside this result. |
| Unbrokered native filesystem | 320 observations over 20 repetitions; 160 useful positive controls. Direct route has no broker RPC identity payload. |
| Publication repairs | Legacy event iterators, async log streams, observer callbacks and state/history APIs now mediate outputs; bounded before/after leak probes are retained. Full composition remains open. |
| Notebook C | Still unsupported: incomplete server boundary, rejected before tasks run. Disposition records are not execution successes. |
| Historical provenance/hours | Missing contemporaneous evidence and retrospective labor hours cannot be reconstructed. No current capture substitutes for them. |
| Host/namespace assumptions | Shared host, same-host capability variants, metadata exposure and SQLite private-namespace assumptions remain explicit. No general hardlink discovery, metadata secrecy or idle-host performance claim. |

Paths in this table are relative to `eval/campaigns/remediation-v2/`. The campaign
README and acceptance JSON give the longer history and all fourteen original
dispositions. Preserve all failed pilots and original measured cohorts.

## Verification state at handoff

**Do not say the current full suite is green.** The latest full run predates
several fixes, and no replacement full run has been started.

| Check | Recorded result | Scope / log under `campaigns/remediation-v2/` |
| --- | --- | --- |
| Handoff focused tests, current tree | **373 passed** | `raw/checks/handoff-focused-20261027-v1.log`: language admission/proof, output primitives/data, report integration, typed resources and broker/resource integration. |
| Handoff selected Ruff check | Pass | `raw/checks/handoff-lint-20261027-v1.log`. This is selected `ruff check`, not full `make lint` or a formatting check. |
| Generic verifier after Decision repair | **2,417 passed** | `raw/checks/decision-proof-v5.log`. Includes the retained positive assertion and adversarial Mapping/initializer cases. |
| Typed resource repair | **119 passed** | `raw/checks/typed-resource-shapes-after-v3.log`; included again in the handoff run. |
| Seven primitive proof/runtime tests | **103 passed** | `raw/output-data-proof/primitive-tests-final.log`, before the scalar-prefix extension. |
| Scalar checker development run | **90 passed** | `raw/output-data-proof/scalar-tests-v1.log`, a narrower test selection; not a replacement for the 103-case run. Current handoff run covers both proof and runtime files. |
| Language nested-metadata development run | **92 passed** | `raw/checks/newlanguage-shape-tests-v1.log`; current handoff run includes the files again. |
| Full prebuilt, composition v1 | 4,156 passed, 113 failed | `raw/checks/composition-full-prebuilt-v1.log`. Unsecured runtime probing and compatibility issues were then repaired; all 113 recorded cases passed a separate recheck. |
| Full prebuilt, composition v2 | **4,496 passed, 1 failed; 16 snapshots passed** | `raw/checks/composition-full-prebuilt-v2.log`. Failure was the real Decision copy/read source-proof assertion, subsequently repaired. Docker test-service cleanup completed. |
| Prior full format/lint | Pass for their snapshot | `raw/checks/composition-format-v2.log`, `composition-lint-v2.log`; stale for newest changes. |
| Core publication checks | 33 passed | `raw/checks/composition-core-publication-v1.log`. |
| Evaluation tests | 130 passed, 2 skipped | `raw/checks/composition-evaluation-v1.log`. |
| Strict / regression / permutation gates, v2 | Make exits **2 / 0 / 0** | `raw/checks/composition-{security,regressions,permutations}-final-v2.{log,json}`. These reports predate the newest proof/language/resource changes. |

The last strict report contains **zero implementation tasks**, router **21/21**,
2,940 declaration obligations, and publication **9 verified / 51 unresolved out
of 60** (30 publication obligations). SGV901–903 remain. The declaration count is
a conservative inventory including helpers/verifier code, not a coverage rate.

Additional failed development observations are retained, including
`typed-resource-shapes-before-v1.log` (two reproduced failures),
`typed-resource-shapes-after-v1.log` (mistyped test filename, no tests collected),
`typed-resource-shapes-after-v2.log` (mapping-proxy compatibility failure), and
`primitive-report-integration-v1.log` (mutation fixture did not match the actual
signature). Their corrected runs are separate files.

No live subagents remained in the tool inventory at handoff. No long-running
pytest/security-verification job was observed, and the final focused run has
completed. `runtime-state.json` contains historical session handles; revalidate
them before acting. Do not kill unrelated services on this shared machine.

## Why SGV901–903 are still blockers

These are missing proof implementations and composition obligations, not merely
three remaining linter patterns.

- **SGV901 — placement:** `inventory_sources()` in `layered_verification.py`
  deliberately reports `path_cover_proved=False`. Syntactic call discovery cannot
  show every protected effect crosses authorization. Alias/inheritance behavior,
  callback/error paths, state APIs and every admitted publication route need
  coverage, or a runtime refusal before an unsupported route can execute.
- **SGV902 — adapter composition:** `check_adapters()` detects specific bad
  patterns; its `proof=False` is intentional. Publication analysis enters actual
  source methods but does not yet establish full identity/label/transform/
  approval/atomicity preservation. Router success alone does not grant a caller
  permission to publish raw values or pending approval objects.
- **SGV903 — host composition:** `developer_verification.py` still emits this
  gap unconditionally because no composed host proof has been installed. The
  current host-output proof stops at `validate_output_request`. For isolated
  routes, exact grant lowering, activation-before-execution, authenticated channel
  identity, cancellation and descendant lifetime also need composition. Assuming
  a correct kernel/LSM does not prove the adapter uses it correctly.

Do not simply change those false flags or remove the unconditional diagnostic.
Replace them only with recomputed evidence for a precisely defined admitted
execution surface, with explicit premises and runtime enforcement of exclusions.

## Recommended next work

### 1. Stabilize and audit this checkpoint first

Review the newest signature/contract snapshots and primitive source checker before
adding more constructs. In particular, verify the native mapping-proxy backing
assumption, capture/use consistency, compiler lexical scope, helper keyword
binding, useful normal paths, ownership and exceptional paths. Two concrete
checker pitfalls found during review were later suffix bindings shadowing
builtins and renamed keyword-only parameters leaving callers unbindable. Repairs
are saved; add/confirm direct regressions for both before relying on the contracts.

Run full formatting, lint/type checking, focused tests and a fresh full prebuilt
suite. The new scalar checker has not had a completed final full formatting/type
pass. Preserve positive assertions; a useful mediated operation must still work.

### 2. Close one real output composition chain

The most concrete next proof target is:

`OutputMediator -> HostRouter -> policy/effective OutputRequest ->
ObjectManagerHost.dispatch -> validate_output_request -> exact effective content`.

Extend the current validator derivation through the actual recursive
`walk/compound/record/fields` bodies and public wrappers. Derive depth/node/byte
bounds, cycle handling, exact record inventories, nested-label joins, exception
normalization and digest construction. Primitive and scalar-prefix proofs are
building blocks; they must not exempt the unproved suffix. Compose only when all
reachable behavior is modeled or the runtime refuses it.

Then discharge the host-output checker's validator obligation from that
source-bound derivation. Keep initialization, imports/builtin/class bindings,
payload stability and provenance as explicit separate premises until checked.

### 3. Make the admitted surface finite and enforce it

Apply the user's restriction policy to framework entry paths as well as tool
syntax. Inventory the supported entry points and output channels, identify their
trusted boundary primitives, and make unsupported graph/tool/callback/adapter
combinations fail admission before effects. Derive placement over that actual
admitted surface. Do not equate “present in the source inventory” with “proved,”
and do not shrink the evaluation denominator silently.

Keep the language-sandbox route and native-process routes as separate proof
contracts. One route's restriction or successful test does not discharge another
route's channel, activation, filesystem or lifetime obligation.

### 4. Refresh the acceptance evidence after code is stable

Generate new strict/regression/permutation reports under new filenames. Update
the campaign narrative and acceptance JSON with the new result while preserving
the previous failures. Archive the source bytes actually used by the new report
and verify inventory digests against that archive. Only then refresh
`current-sources.json`. The existing `raw/composition-proof/final-v2` captures 229
inventory Python files plus selected tests/docs (250 total), but is not current
for the latest work and is not a complete dependency/environment archive.

Do not spend effort rerunning already-passing application cohorts unless a change
affects them. Do not try to reconstruct missing historical evidence or engineering
hours; those remain acceptance dispositions. Notebook's server integration is a
separate implementation project, not a proof gap to waive.

## Commands and evidence navigation

Use the repository's `uv` environments. From `libs/prebuilt`:

```sh
make format
make lint
uv run pytest tests/security/test_verification*.py
uv run pytest tests/security/test_language_verification.py tests/security/test_language_sandbox.py tests/security/test_manifest_admission.py
uv run pytest tests/security/test_output_data*.py tests/security/test_output_verification.py tests/security/test_layered_verification.py tests/security/test_developer_verification.py
uv run pytest tests/security/test_typed_mediators.py tests/security/test_resource_binding.py tests/security/test_resource_mediator.py tests/security/test_resource_boundary.py tests/security/test_object_resources.py
make test
```

`make test` starts PostgreSQL/Redis Docker test services and cleans them up. The
last complete run took about 8.5 minutes on this shared host; the API inventory
test can be quiet for several minutes. Do not restart a live run merely because
it is quiet. Per repository instructions, run each modified library's format,
lint and tests before a PR; core/evaluation changes need their appropriate checks.

Choose unused report/log names; do not overwrite saved observations. For example,
after confirming that these names do not already exist:

```sh
make security-verify SECURITY_REPORT=/data/langgraph/eval/campaigns/remediation-v2/raw/checks/student-security-v1.json
make security-verify-regressions SECURITY_REPORT=/data/langgraph/eval/campaigns/remediation-v2/raw/checks/student-regressions-v1.json
make security-verify-permutations SECURITY_PERMUTATION_REPORT=/data/langgraph/eval/campaigns/remediation-v2/raw/checks/student-permutations-v1.json
```

Keep stdout/stderr and exit status as well as JSON. The strict command currently
is expected to fail until the proofs above are implemented. Passing regression
or permutation commands does not override it.

Useful evidence directories under `campaigns/remediation-v2/raw/`:

- `output-data-admission/before-v2` and `after-v2`: real before/after nested labels,
  hostile mapping and changed-approval probes with selected source bytes.
- `composition-proof/capture-v1`: earlier guarded-copy and pre-validator output
  branch proofs, explicitly for that snapshot.
- `composition-proof/final-v2`: last full inventory source archive.
- `language-metaclass`: bounded replay of the foreign-metaclass check issue.
- `output-data-proof`: primitive/scalar checker development logs.
- `checks/decision-proof-*`: real Decision derivation development, including
  failed pilots and the successful 2,417-test run.
- `checks/handoff-*-20261027-v1.log`: the final focused check of this handoff.

Some logs are ignored by Git. Use `rg --files --hidden --no-ignore` when locating
them. Raw rows in older cohorts sometimes require plan/configuration joins for
identity; do not imply a universal self-contained trial schema was achieved.

## 2026-10-27 08:31:17 EDT: Lean worker-route implementation started

User approved the Lean pivot and requested timestamped progress here. The selected first target is the Pandas C Linux worker route lifecycle: identity-bound authorization/activation, release to execute, cancellation, and confirmed cleanup before success. Existing SLP/Cedar Lean proofs remain separate authorization-model evidence.

Plan: (1) implement an executable Lean lifecycle/decision core with kernel-checked safety and useful-path theorems; (2) connect the Python route to that core through a narrow, fail-closed bridge, explicitly recording compiler/serialization/kernel/policy premises; (3) fix the ambient-exception cleanup defect and capability-bearing output refusal errors with regression tests; (4) add CI proof/axiom checks and source-bound evidence. No handwritten Python source-pattern check will be promoted to a Lean proof. SGV901–903 remain open until the actual supported-route composition is established.

Corridor analyzePlan is unavailable in this session. File ownership is split between Lean core, Linux cleanup, and output-refusal repairs; this parent owns bridge/CI/reporting and this log. Preserve all prior observations and use new lean-* log names. The previous goal UI remains paused; this explicit new implementation request authorizes the work, without changing that UI status through a tool.

## 2026-10-27 08:50:23 EDT: Lean core and runtime boundary repairs

The worker-route Lean core now compiles with 29 theorems, including exact successful-trace characterization, matching authorization/activation before GO, identity preservation, and permanent refusal after cancellation/unknown cleanup. The core uses no sorry, custom security axioms or native_decide. Main.lean supplies a bounded typed JSON bridge and the executable builds successfully; decoder/compiler/runtime correspondence remains explicit, not inferred from the theorem.

Linux cleanup now captures only the current invocation's escaping exception. Real-pipe controlled-worker tests reproduce the two old failures and pass after repair (50 focused cleanup/review checks); host_verification stays a review-pattern report with all proof flags false. Output receiver/principal/Runtime missing-slot refusals now discard attached exception objects; output and runtime focused runs pass 257 and 193 checks respectively.

The runtime bridge now selects an operator-pinned Lean binary, captures its bytes, executes a sealed memfd with no Python decision fallback, checks a bound trace before GO and checks successful completion after cleanup. Initial selection is synchronous only; selected async routes refuse. Existing unselected Linux routes and old Pandas cohorts gain no Lean proof claim retroactively. Build/bridge/kernel-axiom audits and integration regressions are in progress.

## 2026-10-27 08:59:18 EDT: Compiled guard integration and proof CI

The compiled bridge now passes 82 focused bridge/cleanup checks; the final real-pipe integration run passes 68 checks. The first bridge pilot failed because this Python build omits the memfd wrapper despite kernel support. The repair calls the fixed Linux libc primitive, installs and verifies all immutable-file seals, and keeps unavailable execution fail-closed. Both pilot failures and corrected observations are retained under raw/checks/lean-*.

A review found that a checker refusal after worker completion could be classified as a pre-execution denial. That is repaired: it now reports an indeterminate execution outcome with termination confirmed and withholds the result. Async selection, missing checker execution, changed identity and uncertain cleanup all refuse. Controlled pipe tests assert call placement but do not prove confinement.

The isolated Lean audit pilot passes 17 typed semantic obligations, standard-axiom closure checks and Lean kernel replay against the 29-theorem model. Kernel replay is the same Lean kernel implementation, not an independent checker. A pinned-toolchain CI job and security-verify-lean component target are being added; SGV901–903 and all runtime/source/compiler/decoder/OS refinement flags remain open.

## 2026-10-27 09:19:23 EDT: Whole-library validation and decoder counterexamples

The first complete current prebuilt run finished: 4,857 passed, five failed in lean-prebuilt-full-v1.log (586.29 seconds). Three failures require the deliberate new LeanLifecycleChecker public API export to be added to the API snapshot/reference; two retain stale proof-status expectations after the host checker correctly withdrew its structural proof claims. No runtime conformance failures were reported in that run. The export/reference repairs pass all six API/documentation checks; the two status assertions are being reconciled against the actual unproved report.

Fresh lean-security-v1.json keeps complete=false, acceptance_passed=false, zero implementation tasks and all SGV901–903 proof gaps. The strict make target exits 2. The regression target exits 0; the permutation target exits 0 with 2,444 runtime denial cases and 28,800 finite source-binding cases. Those gates do not close the strict gate. No observation was replaced.

Decoder review found actual counterexamples: duplicate JSON keys can overwrite cancellation, trailing documents were ignored, and the standard parser normalizes invalid surrogate escapes to U+FFFD, collapsing distinct Python identity strings. A regression capture retains 16 failures on the earlier executable. A strict bounded UTF-8/JSON reader is being implemented, with duplicate-key and invalid-surrogate refusal plus full-input framing. The previously passing raw/checks/lean-worker-formal-v1 audit remains pre-decoder-repair evidence. These repairs will be rebuilt and recaptured in a new directory.

## 2026-10-27 09:28:56 EDT: Final formal capture, runtime evidence and open system gate

The final retained formal run is raw/checks/lean-worker-formal-v3/report.json: passed, stable sources, 29 model theorems, 17 fixed typed obligations plus complete identity-field witness, 15 audit-driver tests and required Lean kernel replay. The copied executable SHA-256 is 9bf0fdf240d38ea9b8cab9626c8b29b03f26b017ceda35bc07cbc2258cb17233. This is the same Lean kernel replay, not an independent implementation. The v1 pre-decoder audit and v2 source-hygiene failure are preserved. The driver now understands Lean character literals without hiding following proof-bypass tokens.

The final compiled-binary integration run passes 155 tests, zero skips (lean-worker-final-runtime-v1.log/.xml). The repaired Python encoder rejects all surrogate codepoints before serialization, closing the additional paired-surrogate/scalar identity collision; ordinary scalar Unicode remains useful. The separate 88-test protocol run and before-repair failures are retained.

Actual native tests pass 3/3 against the final captured binary (lean-worker-native-v5.json/.log): useful allowed read, undeclared-file denial and fork denial, with ENFORCED activation receipts and confirmed cleanup. The outer same-host Docker harness explicitly relaxes AppArmor/seccomp/systempaths; real worker confinement and cleanup are exercised without mocks. Earlier UID/nested-mount setup refusals and the earlier executable cohort remain saved. This is finite native evidence, not a new production Pandas cohort or native refinement theorem.

Clarification of the first full-suite failures: two expected proof-status assertions were stale because Linux implementation changes invalidated the older source-review digest in _mediation_catalog. The full API runtime matrix had all 15,744 cases passing, but source_evidence_ready=false and aggregate complete=false. The digest is deliberately not refreshed merely to make that gate green. Tests now check this distinction, with 45 focused mediation/aggregation tests passing. The second full-library run is underway with the corrected snapshots/assertions and repaired decoder.

Fresh strict/regression v2 reports retain complete=false and SGV901–903. A new 443-file selected source capture matches all 199 declared source identities in those reports; the prior current-sources index is archived before refresh. The capture explicitly began after broad-suite startup and is not a complete dependency/OS archive. The public API, Makefile component target and pinned-toolchain CI are wired; acceptance.json records the bounded component result and keeps system completeness false.

## 2026-10-27 09:34:30 EDT: Lean implementation validated; system proof remains open

Final prebuilt make test exits 0: 4,886 passed, three skipped, 16 snapshots passed in 570.47 seconds (lean-prebuilt-full-v2.log). The three skips are the explicit native Lean opt-in cases; all three separately pass against the final formal-v3 executable in native-v5. Required compiled-checker integration passes 155 tests with zero skips. API/docs checks pass six tests; make format and make lint (including ty) pass. Compose test services were cleaned up; the unrelated existing notebook service was left running.

All 443 captured source/config/test bytes still match at the end of validation. raw/lean-integration-v1/final-checks.json records command outcomes, proof/runtime evidence, the source-capture timing limitation and the fact that GitHub Actions has not run remotely. acceptance.json and campaign README now include this bounded Lean component and full-library validation. Failed observations remain retained; four early Lean development logs were also copied into the raw source-capture directory without removing their originals.

Delivered: executable Lean lifecycle model with 29 theorems, strict protocol reader, identity-preserving Python encoding, sealed-binary bridge, synchronous Linux pre-GO/post-cleanup integration, cleanup/slot-refusal fixes, deliberate public API, pinned-toolchain CI, source-bound artifacts and regression/native tests. The selected async route and unsupported/malformed traces refuse. Unselected routes and old cohorts receive no retroactive proof claim.

Not complete: SGV901–903 still block strict system acceptance. Whole-route Python placement, authoritative observation provenance, adapter/publication composition and compiler/decoder/OS refinement are not established by the Lean model, passing tests or safe setup refusals. The old Linux source-review digest remains stale instead of being refreshed merely to make an aggregate gate green. No historical evidence, independent VM, performance isolation or retrospective labor claim is invented.

## 2026-10-27 09:54:23 EDT: Full evaluation goal resumed; concrete composition work

The goal is active again. The preceding turn was progress: executable Lean model/guard, runtime repairs and verified artifacts changed authoritative state; it did not close system acceptance. Current strict reports still have SGV901–903. The supported-surface files remain a draft inventory; their claim that the verifier consumes route check IDs is currently not implemented. No scope reduction or pass-flag substitution is authorized by this continuation. Corridor analyzePlan remains unavailable.

Next work: derive the actual output wrapper/digest contracts from source, keeping constructor and digest semantics explicit; reproduce and gate imported descriptor substitution before output traversal; repair exact activated-adapter evidence coverage in EnforcementCoordinator.validate_receipt, which currently accepts empty and duplicate evidence in a bounded reproduction; inspect and remove numeric-PID signal races in native cleanup. The receipt reproduction is an incomplete validation contract, not a demonstrated native sandbox escape. Code ownership is split among these tasks, with parent-owned integration/status.

## 2026-10-27 10:11:26 EDT: Activation coverage, descriptor admission and native lifetime repairs

Receipt validation now requires exact unique planned-adapter coverage, verifies every signed item, derives the activated obligation union from those items and rejects inconsistent ownership/mode/expiry/context. Before probes accepted complete/empty/truncated/duplicate evidence; after probes accept only complete evidence. 86 focused enforcement/broker tests pass, including useful multi-adapter, tightened support and explicitly degraded negotiation. This repairs runtime receipt composition, not the separate proof of lowering correctness.

A before-import Send.timeout property substitution executed during output validation. The new capture helper reads native class storage directly and accepts only exact native member/getset descriptors with matching owner and name; foreign getters never run. All captured output descriptor tables now use it. 55 focused runtime tests pass. Mutable module-table rebinding, general initialization/runtime binding and concurrent payload mutation remain explicit premises.

Linux cleanup previously read a PID start time and then sent SIGKILL through the numeric PID, leaving a reuse interval. The saved controlled race records that interval without claiming actual kernel PID reuse. Cleanup now opens a pidfd before rechecking start identity, signals only that handle and requires readable process-exit evidence; missing handles/signals or poll uncertainty remain unconfirmed with no numeric fallback. Process identity parsing now handles spaces/newlines/parentheses in comm. Also, a real temporary-path witness redirected a canonical checked resource through a replaced ancestor symlink. Descriptor opening now uses the existing openat2 helper with no-symlinks across every component. Focused lifetime checks pass 46; combined Linux/resource/Lean integration checks pass 90. Kernel handle semantics remain a documented premise (man7 pidfd_open/pidfd_send_signal and proc_pid_stat), not a Lean proof of Linux.

The source checker now derives actual output wrappers and the required SecurityLabels construction, plus native descriptor capture, with 281 focused proof/counterexample tests passing so far. Its digest result is only the exact hashing operation over the derived tagged projection; digest equality does not prove request equality, representation injectivity or mutation sealing. A separate coordinator-node witness remains open: local Python functions are still classified as legacy operator code without language-sandbox admission, so inner-tool mediation alone does not prove outer graph model/input/publication effects. The surface draft is being corrected to state that it is not an executable admission contract.

## 2026-10-27 10:17:43 EDT: Composition review and final validation preparation

The final output-wrapper source derivation passes 336 focused checks and is captured with eight selected sources in raw/checks/output-wrappers-proof-v1. Native descriptor capture, SecurityLabels construction, validation wrappers and the exact digest operation are derived; initialization/runtime binding, digest injectivity, mutation sealing and whole-route composition remain unproved. An independent review is in progress.

Current strict composition-security-v1.json still has zero implementation tasks, complete=false and SGV901–903. Regression checks pass. Linux/deployment integration passes 132 tests in composition-native-integration-v1.log; whole-package format/lint pass on that snapshot. The receipt repair also invalidates the old enforcement-receipt review digest, as expected. A focused mediation run retained one failed old expectation (41 passed); the assertion now requires both enforcement-receipt and linux-grant-activation to remain unresolved. No review digest was refreshed. An earlier command used a nonexistent test filename and exited 4 before collection; its log is retained.

Read-only review confirmed an additional setup leak: when a later resource open correctly fails with real openat2 ELOOP after a forced ancestor replacement, _worker_command leaves the earlier resource descriptor, artifact descriptor and private artifact allocated. The probe cleaned them afterward and no worker started. Exception-safe setup ownership is being implemented before the final suite. The pidfd and symlink repairs retain their observation/procfs/content/namespace premises; they are not promoted to complete host-adapter proofs.

## 2026-10-27 10:31:52 EDT: Frozen source, setup cleanup and whole-library run

Setup now retains ownership until a complete command is returned: acquired artifact/resource/status descriptors are released once on failure, used handles transfer on success, and unused artifact handles close. The same first 12 tests retained 11 before-repair failures and one pass; final 20 tests pass, including helper failure and cleanup-error cases. Failed removal can leave a private artifact, which the tests explicitly observe; no universal deletion or interruption guarantee is claimed. Evidence is raw/checks/composition-setup-cleanup-v1.

Independent output review corrected an evidence-text overclaim: a fresh refusal outside a local handler can still inherit the caller's active exception context and retain traceback frames. Runtime behavior was unchanged; the report and comments now state this, with a reproducing regression. Final source-derived wrapper/constructor/descriptor checks pass 337 tests in raw/checks/output-wrappers-proof-v2, preserving v1. Initialization/runtime binding and exception sanitization remain unproved. Mediation passes 42 checks while both changed source-review digests remain unresolved.

Whole prebuilt make format and make lint pass. A fresh 451-file selected source snapshot was captured before full-suite startup at raw/composition-activation-v1/source-capture.json, preserving previous current-sources, acceptance and README records. Full make test is running with the captured formal-v3 Lean executable required; fresh strict/regression/permutation and actual native checks are also running. Shared-host concurrency is explicit; these validation timings are not isolated performance measurements.

The next production-wired formal target is specified in docs/security/lean-receipt-composition-plan.md: extend the compiled protocol to consume actual assignment/native-plan/evidence coverage, captured once across GO and cleanup. It is explicitly proposed and unimplemented, not acceptance evidence. The current lifecycle model receives activation booleans; another unused model would not close that correspondence gap. SGV901–903 remain open.

## 2026-10-27 10:39:08 EDT: Native checks and source identities confirmed

The new native-selected run passes 3/3 actual production Linux worker cases against the formal-v3 executable: useful granted read, undeclared-file denial and fork denial, with real activation and confirmed cleanup. raw/composition-activation-v1/native-environment.json records the same-host Docker harness, explicit outer AppArmor/seccomp/systempath relaxation, image ID and executable hash; native-selected.json/log retain exact command and times. These new executions follow the receipt/pidfd/path/setup repairs and do not replace historical cohorts.

Fresh strict gate exits 2 with SGV901–903, zero implementation tasks, 3,078 declared obligations, router 21/21 and publication 9/60 (51 unresolved). Regression and permutation gates exit 0; permutations retain 2,444 runtime denial cases and 28,800 finite source-binding cases. All 451 captured files remain unchanged, and all 233 declared inventory source identities in each fresh strict/regression report match the before-suite capture. Formal source/driver/toolchain identities and executable SHA256 still match the earlier retained kernel audit; this identity check is not a new replay or refinement proof.

Full make test collected 5,056 cases and is still running with no failures reported so far. Final outcome remains pending. Independent cleanup review acknowledged the exact frozen Linux hash and found no further ownership/deduplication/masking issue within the scoped repair; deletion failure and arbitrary interruption remain explicit limits.

## 2026-10-27 10:41:18 EDT: Composition repairs validated; strict proof gate still open

Final prebuilt make test exits 0: 5,053 passed, three skipped, 16 snapshots passed in 535.62 seconds. All three skips are native Lean opt-in cases, separately passed 3/3 on the final sources. make format and make lint exit 0. raw/composition-activation-v1/final-checks.json links exact commands, logs, results and limitations. Test Postgres/Redis services were cleaned up by make; no unrelated service was targeted.

All 451 selected source/config/test bytes match the before-suite snapshot at completion. All 233 declared source identities in each strict/regression report match that capture. Prior current-sources, acceptance and README records were retained before refresh; acceptance.json now includes this distinct prospective remediation checkpoint while complete=false and goal_status=active remain. The earlier formal-v3 model audit remains the last kernel replay; source/binary identity was rechecked, not promoted to a new proof. No GitHub Actions run was dispatched.

Implemented and tested this continuation: exact receipt evidence/obligation composition, native descriptor admission, source-derived output wrapper/constructor/digest contracts, pidfd-only cleanup signaling with robust proc identity parsing, full-component symlink refusal, and best-effort exception-safe setup ownership. Recorded before failures and all failed pilots remain. A proof-report wording error about inherited exception context was corrected with a runtime regression.

Remaining: strict security-verify exits 2 for SGV901–903; regression and permutation gates exit 0 without overriding it. Publication remains 9/60 with 51 unresolved. Outer coordinator Python still lacks the required language admission boundary, and actual receipt rows are not yet consumed by the Lean lifecycle core. The next concrete implementation is the production-wired receipt-coverage projection/protocol in docs/security/lean-receipt-composition-plan.md, followed by the remaining placement/provenance/publication obligations. That document is a plan, not completed proof. Goal remains active; no acceptance flag or historical disposition was relabeled.

## 2026-10-27 10:45:06 EDT: Production-wired Lean receipt composition started

Previous goal turn classified as progress: validated runtime fixes, new source-bound observations and corrected evidence claims changed authoritative state. Rechecked current source and final records: system acceptance is still false with SGV901–903. Goal remains active; no external blocker. Corridor analyzePlan is unavailable.

Implementing the previously proposed receipt-composition plan now. Ownership: one agent builds executable Lean finite-coverage predicates and typed theorems; one extends the strict v2 CLI/typed audit; one implements native-shape certificate capture and immutable session reuse; parent integrates the real Linux plan/receipt before GO and after cleanup, maintains records and runs full validation. Protocol v2 requires actual assignment/native-plan/evidence rows, full identity bindings including deployment/runtime, and exact mode/waiver/removed-wants correspondence. Old executables must refuse, never downgrade to activation booleans.

Bounds: at most 256 general-array elements, 32 events, 16 object fields, depth 12, 4,096-character strings and one MiB encoded input; no truncation. Existing exact decoding, Unicode identity and duplicate-key refusal remain required. Signature/freshness checks, RuleEnforcement correspondence and grant-obligation generation stay separate runtime obligations; proving coverage of assigned obligations cannot establish complete grant lowering. Actual useful paths and existing degraded semantics must remain tested. All prior observations will be preserved.

## 2026-10-27 11:00:34 EDT: Receipt model and runtime integration pilots

ReceiptCoverage.lean now typechecks executable finite coverage/binding predicates and constructive multi-adapter theorems. The model derives exact assignment ownership, native-plan/evidence matching, no missing/extra obligations, waiver/mode/removed-wants correspondence, and certificate-bound pre-GO/full lifecycle conditions. Binding includes deployment/runtime. Final typed audit and kernel replay are still pending; root .lake development binaries are pilot artifacts only.

The strict v2 CLI and Python bridge are implemented. Session state is captured as immutable encoded data and fresh containers are supplied to each checker invocation, avoiding reuse of mutable call-site aliases. The native-record helper projects actual plan/receipt rows through captured native slots. Linux now supplies those rows before GO and reuses the captured certificate after cleanup. Initial bridge suite passes 164 tests; controlled real-child/pipe integration passes 49 tests, including contradictions deliberately accepted by a fixture coordinator but rejected before GO by the compiled checker. These are integration observations, not confinement proofs.

Pandas integration and the existing full-workflow harness now support explicit pinned v2 checker selection for C. Cohort setup copies exact selected executable bytes into the new cohort; unselected A/B behavior and the frozen ten-task utility oracle are unchanged. 21 selection/oracle checks pass. Plan is a new prospective full five-repetition ABC cohort once final audited sources/binary are frozen; no old observation is relabeled and no failure is removed. Model service is reachable. Imported class-layout admission, inherited exception context and aggregate capture budgets are being independently reviewed before source freeze.

## 2026-10-27 11:01:24 EDT: Immediate model-service status correction

Correction to the preceding entry: the contemporaneous localhost:11434/api/tags probe returned ConnectionRefusedError. The statement that the model service was reachable was an erroneous optimistic log entry written before inspecting the probe result. The application cohort has not started. Existing service executable/configuration is being inspected; no fresh workflow success or model availability is claimed. Formal/bridge work continues independently.

## 2026-10-27 11:34:09 EDT: Formatter evidence incident and recovery underway

At 15:10:36 UTC, parent ran eval make format without first ensuring campaign snapshots were excluded. Ruff reported 1,334 reformatted Python files, largely historical source copies. This was an evidence-preservation error. Application cohorts had not started and were paused. Raw JSON reports, recorded expected hashes and compiled binaries were not rewritten. Formatted bytes were quarantined before recovery. No original hash is being refreshed to match the formatting change.

Recovery uses independently recorded source hashes, unaffected content-addressed framework blobs, retained tar archives, original live bytes only when hashes match, and candidate reverse formatting accepted only on exact original-hash match. A small set of scripts without prior file hashes is reconstructed from exact preincident source-writing journal literals, with that limitation explicit and their reformatted bytes checked against quarantined incident copies. Other-thread/personal data was not used. Most files are restored; complete count/audit remains pending in raw/formatter-incident-v1.

The formatter configuration now excludes campaigns and enforces exclusions for explicit paths. Actual Ruff file discovery selects 192 live eval files and no campaign evidence paths; live implementation/tests remain checked. Whole eval lint now passes after splitting an overlong SQL test literal without changing its value. Recovery is still pending for a few historical source copies, so no overall preservation-complete claim is made yet.

Separately, the first native run selected the old v1 artifact because a generated harness used silent string replacements against a script whose quote formatting had changed. All three v2 invocations correctly refused that old executable. Those failures are retained. A fresh explicitly pinned v2 direct run passes 3/3; a separately recorded observer run also passes and captures actual sealed-checker exchanges. This was a harness selection error, not a repaired runtime vulnerability. Evidence: raw/receipt-native-diagnostic-v1. Final Lean audit and its restored source snapshots match recorded identities; full library and application validation remain pending.

Correction to the preceding tooling sentence: the saved Ruff discovery result contains 156 live files, not 192. It contains zero campaign paths. The JSON record is authoritative.

## 2026-10-27T15:44:48+00:00: Receipt audit and formatter recovery verified

Parent aggregate recovery verifies all 1,335 timestamp candidates: 1,334 changed files restored, including 1,323 against independently recorded preincident hashes and 11 from exact recorded source writes without prior file hashes; one copied helper was unchanged. Zero unresolved paths. Current restored bytes and every preserved incident copy match their recovery inventories. This restores evidence bytes without creating missing historical provenance. Records: raw/formatter-incident-v1/final-verification.json. Protected eval make format exits 0 and leaves all 4,228 existing archived Python files unchanged; campaigns are now excluded with force-exclude.

Final receipt-formal-v1 audit passes 54 model theorems, 37 fixed typed obligations, 18 driver tests, negative typechecking controls and fresh same-kernel replay. Exact executable SHA256 is 2cadadaee2faffa92ba7988c8f3f1abfdc13d6964538d2218cdb1aa2f22a29c5. Native-shape bridge tests pass 180; explicitly pinned native v2 worker cases pass 3/3. These establish the finite model and observed integration, not compiler/Python/OS refinement or full grant generation. Historical proof flags remain false.

The local pinned model service is verified available. Resuming a new prospective pilot and unchanged full ABC Pandas workflow cohort with explicit C receipt-v2 selection. Full library/eval verification follows source freeze. Shared-host concurrency remains explicit; no previous observation is replaced. SGV901–903 and the overall goal remain open.

## 2026-10-27T15:50:18+00:00: Final receipt-v2 validation started on frozen sources

A 457-file selected source/config/test snapshot is retained in raw/receipt-integration-v1/source-capture.json before full prebuilt make test startup. The final v2 binary is required. Strict, regression and finite-permutation checks are also running; outcomes are pending. The unchanged eval suite already passed 143 tests with two skips; selected Linux/enforcement/docs/cleanup integration passed 118 tests. Format/lint pass, and the final Lean audit source and binary identities were rechecked against the captured replay.

The fresh Pandas pilot passed all three A/B/C rows, with zero validation issues and actual ENFORCED C receipt using the pinned selected checker. The full original 150-row cohort started at 15:47:45 UTC and remains running. The cohort freezes framework and harness sources independently. No performance claim is drawn from shared-host durations.

Independent incident audit corroborates parent recovery and freshly rechecks unchanged original manifests: remaining-v1 3,993/3,993; completed-v2 package 157/157; completed-v2 files 103/103. Documentation now describes the implemented receipt-v2 contract and keeps full grant-generation, Python placement, publication and refinement gaps explicit. The earlier proposed-plan entries are historical checkpoints, not current implementation status.

## 2026-10-27T15:56:45+00:00: Fresh gates and next formal boundary

Strict/regression/permutation exits are 2/0/0. Strict retains SGV901–903, zero implementation tasks, 3,091 declared obligations, router 21/21 and publication 9/60 (51 unresolved). All 457 selected sources remain unchanged and all 233 inventory source identities in both strict/regression reports match the before-suite capture. Full prebuilt tests are running. The fresh Pandas cohort has 46/150 recorded trials, all passing so far; this is an interim count, not final acceptance.

Read-only next-contract evidence is retained in raw/checks/receipt-next-grant-v1. Removing one obligation consistently from assignment, plan, evidence and activation rows remains accepted by the v2 finite checker, as its documented contract permits. This is not a demonstrated Linux escape: the production route constructs compile_obligations(grant) itself. The next formal component must capture the grant independently, derive its rule obligations and all nine fixed domain complements, and compare actual semantic fields plus assigned/waived coverage. A self-declared required-ID list or opaque digest would leave the same gap. Additional broker-specific obligations require a separate derived profile.

Outer-graph admission also remains concrete work: ordinary Python nodes and wrappers around discovered ToolNodes can execute without the requested closed language/effect boundary. A mandatory finite admission inventory needs usable explicit node/model/input/publication mediators; blanket relabeling would only refuse the current useful outer workflow. No frozen production source was changed during this read-only investigation.

## 2026-10-27T16:00:16+00:00: Full library validation passed

Final prebuilt make test exits 0: 5,162 passed, three skipped, 16 snapshots passed in 565.98 seconds. The three native Lean opt-in skips were separately passed 3/3 against the same audited v2 executable. Docker test Postgres/Redis services were removed by make; no unrelated service was targeted. Prebuilt format/lint and eval format/lint/test pass; eval has 143 passed and two skips. All 457 selected files remain unchanged after the library run; strict/regression inventory identities still match. Validation durations reflect a shared host with concurrent application evaluation.

The full Pandas cohort remains active and is the remaining validation run for this checkpoint. Read-only next placement report is saved in raw/checks/receipt-next-placement-v1/report.json, with 21 stable selected-source identities and every implementation/SGV-closure flag false. It specifies closed node admission and actual mediated model/compute/dataset/publication operations while preserving the useful upstream workflow and denominator. No new frozen-source edits were made.

## 2026-10-27T16:04:48+00:00: Three full application repetitions complete

The unchanged full Pandas receipt-v2 cohort has 91/150 recorded trials, all passing so far, including three complete ten-task ABC repetitions. Source identities remain unchanged in recorded rows. The same runner continues; no new per-row retries, removed tasks or replacement observations. Final matrix/oracle/selected-checker/receipt validation remains pending.

## 2026-10-27T16:16:38+00:00: Receipt-v2 checkpoint complete; system proof remains open

Fresh full Pandas cohort passes 150/150: A/B/C each 50/50, under the original ten-task, five-repetition utility oracle. Original cohort verifier and independent identity/selection/receipt validator both exit 0 with zero issues. All 50 C rows select the exact audited v2 executable; 63 nonempty ENFORCED activation receipts are retained. All 233 frozen framework sources/blobs and every per-trial before/after source identity match. Model and binary identities remain stable. The pilot remains separate, and no old observation or failed row was replaced. Controller elapsed wall time was 26m25s on a shared host, not labor time or an idle-host benchmark.

Final accounting is raw/receipt-integration-v1/final-checks.json. Prebuilt: 5,162 passed, three native opt-in skips separately passed 3/3, 16 snapshots passed; eval: 143 passed, two skips. Format/lint pass. Lean audit: 54 model theorems, 37 fixed typed obligations, 18 driver tests, two negative controls and fresh same-kernel replay. Bridge180 and selected integration118 pass. All 457 selected source files remain unchanged; both strict/regression inventories match all 233 recorded source identities. Recovered archive candidates also remain unchanged.

Previous acceptance/current-source/README indexes were preserved before refresh. acceptance.json now records the distinct receipt_v2_composition checkpoint while complete=false and goal_status=active remain. Strict still exits 2 with SGV901–903, zero implementation tasks and publication 9/60; regression/permutation gates exit 0. GitHub Actions was not dispatched. The formatter incident, 11 no-prior-hash reconstruction limits, failed old-binary native harness selection, failed formal pilots and historical failures remain visible.

The owned local Ollama session was interrupted after validation and exited 0. No unrelated service was targeted. Next formal work is the independently captured grant-derived obligation inventory and semantic equality, with raw native data admission before generic mapping/digest helpers. Next placement work is a mandatory closed node/effect admission boundary with actual useful model/compute/input/publication operations. Both retained designs are unimplemented proposals; neither closes SGV901–903. Goal remains active.

## 2026-10-27T16:26:19+00:00: Grant-derived Lean composition started

Previous goal turn classified as progress: receipt-v2 production wiring, a fresh kernel audit, full library checks and a complete new 150/150 utility cohort changed authoritative state. Current checkpoint was re-read; strict SGV901–903 remain open. Goal remains active, with no external blocker. Corridor analyzePlan is unavailable.

Implementing the next contract from raw/checks/receipt-next-grant-v1. Protocol v3 will require an independently captured native Grant and actual generated obligation rows, derive rule semantics plus all nine fixed complements in Lean, require exact record/assignment coverage, and bind captured grant identities to lifecycle data. The selected Linux route remains enforced and waiver-free. A preflight decision precedes attestation/negotiation/lowering; the full decision reuses immutable snapshots before GO and after cleanup. Old protocol binaries must refuse.

Before any generic condition conversion or digest helper on the filter result, admit exact native filter/grant/rule/ledger storage, copy bounded data and reconstruct detached native objects for subsequent processing. Candidate protocols, unsupported floats/sets/opaque values and over-budget inputs refuse. Supported typed condition data covers null, boolean, signed64 integer, text, tuple sequence and native maps. This is the existing Linux generator profile, not the separate broker-extension generator. Earlier profile compilation/filtering, hash preimages, native lowering, Python source placement and publication remain explicit obligations.

Ownership: principal agent implements the GrantCoverage model; proof agent extends strict decoding and typed audit; host-contract agent implements native admission and bridge tests; parent integrates the Linux call sites and actual-worker tests. Previous campaign indexes and selected pre-change sources are retained under raw/grant-integration-v1. No historical observation or expected digest is replaced.

## 2026-10-27T17:25:41+00:00: Closed node/branch admission gate implemented (opt-in)

New libs/prebuilt/langgraph/prebuilt/security/admission.py admits graph bodies by exact type identity and captured native storage: AdmittedKind (LANGUAGE_PROGRAM, TOOL_NODE, NATIVE_DEPLOYMENT, FRAMEWORK_BRANCH), frozen AdmittedDescriptor(kind, name, identity, implementation, source_sha256), admit_node, admit_branch, recheck and describe. Only an exact ToolNode whose dispatch path is the configured host executor (Cedar ObjectPolicyHostExecutor with the language-sandbox, Docker or broker dispatcher, or a direct LinuxSandboxExecutor) with no pre/post wrappers and no injected arguments, and an exact RunnableCallable branch pinned to the framework tools_condition function, are admitted. Ordinary callables, Runnable subclasses, wrappers containing a ToolNode, metadata promotion and async-only bodies refuse with the registered admission: codes before any candidate protocol runs in config.py. Identity digests cover lowered program bodies, signatures, closed terminal IDs, contracts and source digests, or pinned artifact digests, or loaded framework code plus the routing map.

SecurityConfig(closed_admission=True) builds the full inventory before _find_tool_nodes/resolve_placement, places admitted bodies without module-name heuristics, verifies every mediated wrapper against its descriptor and attaches the immutable tuple as builder._security_admission. Default remains byte-for-byte unchanged. Runtime MAC now registers admitted descriptor inventories: closed graphs use the pre-protocol inventory; the legacy ToolNode-only shape is admitted post hoc (bound to source/deployment identity and rechecked at every check); secured graphs with other shapes and no closed admission refuse with admission:closed_admission_required; unknown bodies stay mac:unconfined_graph_body. The strict form (closed admission required for every secured graph under MAC) was not applied because it would break two existing positive MAC tests that compile default cedar_security graphs; recorded as an open item.

Tests: tests/security/test_admission.py 15 passed, 1 skipped (direct Linux native deployment skips: bubblewrap isolation unavailable on this host). Focused suites admission/config/runtime_mac/placement/static_flow_admission/checkpoint_placement/manifest_admission/isolated_cedar/docs_and_api/package: 160 passed, 1 skipped. ruff format/check and ty check pass. Graph construction effects before compile (add_node naming, type hints, signatures, schema inference) remain outside config.py control; placement.py binding of MediatedNode/MediatedBranch to captured descriptors is the next step. SGV901-903 remain open.

## 2026-10-27T17:31:57+00:00: Admission gate documented in the supported-surface inventory

New docs/security/admission.md describes the opt-in closed admission gate: the predicate, the admitted kinds (language_program, tool_node, native_deployment for nodes; framework_branch for the pinned tools_condition branch) with the exact dispatch path, program/deployment and identity requirements each needs, the five admission: refusal codes with the conditions that raise them, the SecurityConfig(closed_admission=True) opt-in and why the default stays unchanged, and the explicit non-claims (imports, builder initialization, reducer/cache/retry callbacks, checkpointers, stream callbacks, module mutation, output publication, compiler/decoder/OS enforcement, placement.py dispatch binding, uncovered entry points without RuntimeMAC). It states that the gate does not close SGV901 by itself.

docs/security/supported-surface.json gains a route-independent admission section (status opt-in, admitted kinds, refusal entries with gate_code/enforced_at/condition, not_proved list, sgv901/902/903_closed false). No existing null gate_code was replaced: none of the recorded routes compiles with closed admission (the Pandas outer vendor graphs carry no SecurityConfig), and the capability entries bundle behavior the gate does not refuse (admitted ToolNode ainvoke, Send dispatch, actual model mediation). Three unsupported_capabilities entries and the pandas route carry an admission_note instead. supported-surface.md mirrors this with an Admission section and keeps every existing disclaimer; the verifier still does not consume route check IDs. python3 -m json.tool validates the JSON; tests/security/test_docs_and_api.py passes 5/5. No code was changed. SGV901-903 remain open.

## 2026-10-27T17:38:30+00:00: Descriptor-bound dispatch for admitted nodes and branches (opt-in)

MediatedNode and MediatedBranch in libs/prebuilt/langgraph/prebuilt/security/placement.py now accept an optional captured AdmittedDescriptor; config.py passes it only on the two closed-admission construction sites, so SecurityConfig() default graphs carry descriptor=None and behave as before. With a descriptor the wrapper dispatches only the captured plan, in this order and before any router or candidate call: override kwargs refused; exact descriptor whose captured node/path is the wrapper's runnable and whose placement is TRUSTED/STANDARD; admission.recheck; ToolNode instance dictionary shadows no class-level function; input is an exact dict with str keys or an exact list and a shallow copy is passed; principal only from the native config; exact framework Runtime read from configurable. Then the existing router.dispatch mediation runs and the pinned class function ToolNode._func/_afunc is called with the captured node as receiver, the bounded copy, a narrowed config (configurable copy, metadata, tags, concurrency limits; callbacks, run_name and run_id dropped) and the Runtime; self.runnable.invoke/ainvoke, the mutable func/afunc attributes and dynamically returned Runnables are never used; results pass through the existing state-write mediation. Branches call the pinned tools_condition function with the bounded copy only (no config, callbacks, router or Runtime), require an exact str destination, and run the same sync function inline on ainvoke (the run_in_executor shim is never started). Node async dispatch requires the captured executor and dispatcher to define their own coroutine ainvoke in their exact class, otherwise admission:unsupported_async is raised before starting. All plan deviations (foreign containers, override dictionaries, missing Runtime, replaced links) raise admission:descriptor_changed; no new refusal literal was added.

Tests: tests/security/test_admission_dispatch.py 10 passed: the marker witness is retained for plain function, metadata-promoted foreign node and wrapper containing a valid ToolNode (legacy default still records coordinator-effect; closed admission refuses admission:unsupported_node_body with no marker and no mediation effect); admitted ToolNode plus language-sandbox tool and tools_condition branch do useful work end to end under closed_admission=True, sync and async; post-admission replacement of the wrapper runnable, descriptor, wrap_tool_call, func/afunc aliases, an instance-shadowed helper, the tool program, the branch runnable/ends/func/afunc shim all refuse before any dispatch transfer or state write and the restored graph works again; override kwargs, foreign dict subclass/non-str keys/tuple inputs, smuggled state principal, foreign config principal and missing Runtime refuse before effects; narrowed config verified; async without a native adapter route refuses admission:unsupported_async before any effect. Related suites (admission, placement, output host/router/data-descriptor binding, state/callback publication, config, runtime MAC, static flow, checkpoint placement, manifest admission, docs/api, package, mediation, tool node security): 320 passed, 1 skipped (direct Linux native deployment; bubblewrap unavailable). ruff format/check and ty check pass.

Open: the exact framework ToolNode still receives the configurable copy (principal, call counter, Runtime and framework channels) because the host executor binds calls to them; candidate tool bodies run only in the admitted host with validated arguments. BaseModel graph states are refused under descriptor-bound dispatch (exact dict/list only). _verify_admitted_graph and the MAC boundary do not yet check wrapper.descriptor identity (config.py/mac.py lines outside this step). Docker and direct-Linux positive dispatch remain untested here. SGV901-903 remain open.

## 2026-10-27T17:50:05+00:00: Source-derived admission-surface evidence wired as a non-gating component

New libs/prebuilt/langgraph/prebuilt/security/admission_verification.py (verify_admission_surface(admission_source, config_source, placement_source, mac_source)) parses the four admission modules with ast and symtable, never importing or executing them, and derives four obligations with per-obligation proved flags. Every statement of each analyzed function must be consumed by an accepted form (constant expressions, admitted calls, plain/tuple/subscript assignments, exact-type and membership guards that refuse with a registered code, try/except AttributeError native reads, native-lock with blocks in mac.py); unknown constructs, unknown call targets, protocol spellings (isinstance, getattr, hasattr, __module__, get_name, signature, .invoke/.ainvoke, bound/steps, unpacked arguments) and locally shadowed helper names leave the obligation unproved with the line recorded. (a) exact_type_selection: admit_node/admit_branch refuse on type(runnable) is not ToolNode / type(branch) is not BranchSpec before any other read of the candidate, which then flows once into the capture helper whose candidate reads are AttributeError-guarded native lookups. (b) closed_compile_refusal: configure_graph builds the closed inventory before any read of the builder; _closed_admission_inventory guards type(graph) is StateGraph, admits every node/branch via admit_node/admit_branch after exact container checks and uses metadata only for the exact-dict check; the placement loops' closed branch refuses admission:descriptor_changed for undescribed entries and builds MediatedNode/MediatedBranch around the admitted body with descriptor=admitted[...] and the fixed TRUSTED placement, then continue; the wrapped graph is verified afterwards. (c) descriptor_dispatch: the four invoke/ainvoke entries switch to the admitted route first; each admitted route starts with the kwargs/descriptor/recheck helper, uses input only through _bounded_input and config only through _principal, runs router mediation before calling the pinned ToolNode._func/_afunc with the captured node (or the pinned branch function with the bounded data), with no self.runnable, .invoke or unpacked kwargs anywhere. (d) runtime_mac_closed_admission: register_mac_boundary selects _closed_boundary when closed_admission is true, otherwise _legacy_boundary, which returns the closed-admission marker for any graph with branches and None for anything but an exact MediatedNode wrapping an exact admit_node-admitted ToolNode; RuntimeMAC.check refuses None and the marker (admission:closed_admission_required) in order before the boundary walk, which binds each wrapper to its captured implementation and rechecks. The report carries scope, six premises (initialization, runtime binding, recheck correctness, async adapters, framework primitives, pre-compile construction), issues, source_sha256 for the four modules, checker_sha256, system_complete False and sgv901_closed False; the legacy post-hoc shape is recorded as an explicit exception.

layered_verification.verify_layers now carries the result as evidence key admission_surface only; complete, path_cover_proved and every SGV diagnostic are unchanged. developer_report summary gains admission_surface_proved. On the actual repository the component proves all four obligations while developer_report still fails with SGV901, SGV902 and SGV903 and complete=false.

Tests: tests/security/test_admission_verification.py 27 passed (positive on actual sources; 22 mutation cases, including a self.runnable fallback sync/async/branch, isinstance on the candidate, a __module__ check, a getattr probe, a get_name call, metadata promotion in the closed loop and in the inventory, a dropped descriptor binding, a skipped branch admission, _find_tool_nodes before the inventory, missing recheck in the node and branch helpers and in the MAC boundary walk, forwarded kwargs, raw input, a moved descriptor switch, a removed closed-admission refusal, removed branch marker and an isinstance boundary selection, each leaving exactly that obligation unproved; unknown statement forms, local helper shadowing, empty/unparsable sources and comment-only binding changes). test_layered_verification.py 15 passed and test_developer_verification.py 14 passed including the real-evidence gate assertion. Combined: 56 passed. ruff format/check on the six files and ty check langgraph pass. Corridor analyzePlan unavailable; a five-line plan was written instead. Not done: no other verifier consumes admission_surface; the component does not prove recheck's identity recomputation, async adapter transport, module initialization or pre-compile construction effects; the direct LinuxSandboxExecutor route and Docker positive dispatch remain untested; SGV901-903 remain open.
## 2026-10-27T17:11:00-04:00: Route-scoped handoff and grant-v3 audit triage

The advisor replaced the former whole-system target with the route-scoped acceptance contract in `docs/security/evidence-standard.md`; no new proof work outside declared routes will be added. I inspected Claude's append-only log and preserved its four 17:25–17:50 UTC entries as Claude-authored reports. No Corridor `analyzePlan` tool is available in this session (tool inventory check returned no match), so this entry records the plan before edits: repair or park grant-v3, bind fresh Linux runtime evidence to current sources, promote only after the checks pass, apply the record corrections without rewriting history, run the required library checks, and commit the shared-tree checkpoint.

The saved `claude-lean-audit-v1` failure is localized: the current Lean project builds and all 72 fixed theorem/axiom checks were reached, while generated `KernelAudit.lean` has three malformed record literals (lines 352, 361, 371) and one proposition for which `decide` cannot synthesize `Decidable` (line 664). Grant-v3 is therefore being finished rather than replaced by receipt-v2. The failed capture remains immutable evidence.

## 2026-10-27T17:16:00-04:00: Step 1 complete, grant-v3 Lean audit passes

Repaired only the generated audit contract in `proofs/worker-route/check.py`: arbitrary `Rule`, `Grant`, and `Obligation` field-projection examples now use their constructors, avoiding the ambiguous record parser form, and the concrete useful-grant witness explicitly unfolds the finite well-formedness definitions before `decide`. The checker's 20 unit tests pass. The first new audit directory, `raw/checks/codex-grant-lean-audit-v1`, records a real environment failure because `lake` was absent from this shell's `PATH`; it is retained. With `/home/faculty/abk6349/.elan/bin` selected, `make security-verify-lean` passes in `raw/checks/codex-grant-lean-audit-v2`: 72 fixed theorem/axiom obligations, five negative controls, 20 driver tests, successful fresh kernel replay, stable source-before/source-after identities, `passed=true`, `model_proved=true`, and no issues. This is the finite route model only and does not expand the declared route scope.

## 2026-10-27T17:18:32-04:00: Grant-v3 native evidence and record corrections

The exact audited v3 executable (`6097be9...cb08`) passes the three opt-in real native cases: useful granted file read, undeclared-file denial and fork denial, each with an ENFORCED receipt and confirmed cleanup. The retained rerun and a source-bound record are under `raw/grant-integration-v1/grant-native-v1.*` and `native-runtime-evidence.json`; the latter binds eight current route/test sources. A fresh A/B/C Pandas pilot also passes 3/3 and the new 150-trial cohort is running from a frozen current framework snapshot. Its verifier now emits the seven Linux worker route source hashes it independently validates in that snapshot.

The runtime-evidence verifier previously accepted a record with zero matching source identities. That contradicted the evidence standard and the advisor's explicit promotion condition, so the check now fails closed when no recorded identity matches the current tree; both missing-hash and nonexistent-path regressions were added. All 61 route-verifier tests pass.

Applied the agreed record corrections without changing historical evidence: the SQL RM1 A/B/C and canary results are now described in `APPLICATIONS.md`, the SQL intake and the pilot report while retaining the production-unsupported distinction; Pandas v11 is corrected from 26/30 to 24/30 (8/10 each); and `apps.csv` retains historical single-run pointers while adding a separate cohort-evidence column and current next actions.

## 2026-10-27T17:28:26-04:00: Shared-tree checkpoint and pre-promotion validation

Created branch `codex/route-acceptance-grant-v3` and committed the accumulated shared-tree work as `01aed327` (`Checkpoint route-scoped security remediation`), excluding only the actively written Pandas grant-v3 cohort. A stray Vim swap file discovered in that checkpoint is staged for deletion in the final commit; no source file was removed with it.

Against the exact audited grant-v3 binary, the final focused suite passes 349/349. Prebuilt `make format` and `make lint` pass. Eval `make format`, `make lint`, and `make test` pass (144 passed, 2 skipped). A fresh full route gate before R3 promotion passes for the existing R2/R4 supported set with current-source Lean replay (`raw/checks/codex-prepromotion-security-v1.json` and `codex-prepromotion-lean-v1`). Whole-system completeness remains explicitly not established. The proof/runtime documentation now describes grant-v3, 89 public model theorems, the 72 fixed audit obligations, five negative controls, 20 driver tests, the strict v3 envelopes, and the current source-bound native observations; receipt-v2 remains historical evidence.

## 2026-10-27T17:44:24-04:00: R3 promoted and route-scoped gate passes

The fresh `raw/pandas-grant-v3-full-v1` cohort passes independent verification: 150/150 trials, 50/50 in A/B/C, no failures or issues, unchanged frozen utility oracle, exact audited v3 binary, and twelve route/application source identities matching the current tree. The owned Ollama server was stopped after the cohort. Runtime evidence now fails closed when zero current identities match, so the old receipt-v2 records cannot satisfy the promoted route accidentally.

`linux-worker-compute` is now supported in the manifest. SGV903 names the current source-bound 3/3 native record and Pandas grant-v3 cohort plus the fresh Lean audit and structural host guard. The five stale null-code entries that contradicted R3's generated-computation-only scope were not converted into fake gates: outer graph/checkpointer/human-review/UI behavior remains explicitly outside R3; writable worker-private `/tmp` remains an intentional baseline with no secrecy claim; network enforcement remains an OS/seccomp premise with the missing application probe disclosed. Actual in-scope exclusions still require registered refusal codes.

`make security-verify` passes on the final records in `raw/checks/codex-r3-final-security-v2.json` with fresh Lean evidence `codex-r3-final-lean-v2`: R2, R3 and R4 discharge every applicable route obligation. Whole-system completeness remains NOT ESTABLISHED. The earlier v1 final-gate run also passed before the final manifest prose corrections and is retained separately. Regression-clean verification and permutations pass; the latter covers 28,800 source-binding and 2,444 runtime-denial cases. The full prebuilt suite is still running at the time of this entry; its terminal result will be recorded separately before the final commit.

## 2026-10-27T17:56:08-04:00: Final library validation

The required prebuilt library commands are green on the final implementation: `make format`, `make lint`, and `make test`. The full test result is 5,511 passed, 3 skipped, 16 snapshots passed in 584.46 seconds; Docker Postgres/Redis services were removed after the run. Eval `make format`, `make lint`, and `make test` also pass (144 passed, 2 skipped). The route gate, regression-clean gate, permutation gate, 349 grant-v3 focused tests, three direct native tests, and the 150/150 Pandas cohort all pass. Final commit preparation is the only remaining action.

## 2026-10-28T06:45:13Z: Evaluation closeout under the revised scope

At the user's request, reconciled the campaign README, acceptance record,
supported-surface summary, operation catalog documentation and threat model
with Claude's D5–D11 implementation. Six routes are supported; application
nodes and branches are explicitly trusted subject to the deployment rule.
Whole-system completeness remains not established. Historical component
reports and Claude's status entries are preserved unchanged.

The closed pandas cohort is reported as 45/50 utility successes, five retained
monthly_mean nonfinite-output refusals, and no evidence-integrity issues.
Its verifier's false outcome is preserved. The v21 json-null-v1 transformation
is disclosed as a separate adapter configuration. Six unretained development
runs and the copied-cohort absolute-path pin limitation are disclosed.

Claude's full implementation test record remains 5,621 passed, 8 skipped and
58 host-environment failures; the affected files passed 63/63 in the container.
This is not described as a passing host suite. Today's closeout lint passes;
the eval suite passes 152 tests with 2 skips. A fresh six-route gate with both
Lean audits is running before commit. No implementation or manifest semantics
were changed during this documentation closeout. Corridor analyzePlan is not
available in this session.

## 2026-10-28T06:48:51Z: Closeout verified, ready to commit

Fresh `make security-verify` exits 0: all six supported routes accepted, both
Lean audits pass, and whole-system completeness remains false. Every recorded
check source identity matches the current tree. Evidence is
`raw/checks/codex-eval-closeout-v1.json` and `codex-eval-closeout-lean-v1`.
Lint passes and eval tests pass 152/152 with two additional skips. Final
implementation and cohort process logs are explicitly included in the commit;
raw whitespace is preserved for evidence integrity. The agreed evaluation is
closed with the five disclosed utility failures. No further proof work or
experiments are required by this scope.

## 2026-10-28T07:10:44Z: Publish source without generated evidence

The user requested pushing to slanggraph/wip, then explicitly excluded generated
evidence from Git. GitHub had refused the first push because retained binaries
and an archive exceeded its file limit; the remote was unchanged. The original
unpublished commits are preserved locally on backup/eval-evidence-20261028.
Generated cohorts, source snapshots, databases, intake logs, handoff archives and
report data are removed from the publication index only and remain on disk.
Ignore rules prevent recommitting them; source, configurations, input fixtures,
proofs, narrative reports and acceptance dispositions remain published.

The evaluation README explains reproduction prerequisites and that artifact
links refer to locally retained observations. Security acceptance still fails
closed without its required runtime evidence. Saved-artifact tests skip when
that evidence is absent; the unsupported-configuration unit test uses synthetic
host metadata instead of a historical capture. Format and lint pass. A clean
source-only export passes 141 tests with 13 skips (11 missing-evidence checks
and the two existing skips). No runtime security implementation or gate changed.
The source-only publication commit is based directly on the remote wip tip,
so publishing it requires no remote history rewrite.
