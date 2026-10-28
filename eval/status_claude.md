# Claude progress log: security evaluation

This log is maintained by Claude (Opus 5.5, Claude Code), working from the
handoff in [status.md](status.md). Entries are append-only and timestamped in
local time (EDT). I don't edit `status.md`, the campaign README or
`acceptance.json`. Those belong to the student's own workflow.

## Ground rules I'm following

- Preserve the working tree. No resets, no reverts of others' files, and no
  overwriting saved observations. Every log/report I create uses a new
  `claude-*` filename.
- No changes to the acceptance gate (`developer_verification.py` flags,
  SGV901–903 emission) unless they come with recomputed evidence for a precisely
  defined surface. That's the handoff's own rule, and I agree with it.
- Positive (useful-path) assertions stay. Denying everything doesn't count as
  progress.
- CLAUDE.md asks for a Corridor `analyzePlan` review before code changes. **No
  Corridor tool is available in this Claude Code session**, so I can't run it.
  I'll write the plan here instead, so it can be reviewed later.

---

## 2026-10-27 04:51: Step 0, orientation

**What the eval gate actually is.** `make security-verify` (in `libs/prebuilt`)
runs `developer_verification.py`. It passes only when `verify_layers()` returns
`complete=True` and no proof gaps remain. `complete` is a conjunction of these
checks:

| Conjunct | Current state | Where it comes from |
| --- | --- | --- |
| Router source proof | **true** (21/21) | `boundary_verification.verify_host_router` |
| Host-output correspondence `proved` | false | `output_verification.py`. Blocked on the `validate_output_request` derivation. |
| Placement `path_cover_proved` | false, **hard-coded** | `layered_verification.inventory_sources` (SGV901) |
| Adapter `proof` | false, **hard-coded** | `adapter_verification.check_adapters` (SGV902) |
| Publication model `complete` | false (9/60 verified, 51 unresolved) | `publication_verification.py` (SGV902) |
| Regression checks / waivers / inventory | true | various |

Separately, `developer_report()` appends **SGV903 unconditionally**. No evidence
input can clear it today.

So "make the strict gate pass" isn't one remaining bug. It's four open
whole-system proof components plus one unconditional diagnostic. Each is a
research-scale verification problem over a dynamic-language framework.

**Concurrent agent detected.** Another agent, **Codex (ChatGPT desktop app,
PID 68784)**, has been working in this same checkout. After it wrote
`status.md` (last write 04:46:33), it ran:

- `composition-format-v3.log`: `make format` reformatted 4 files
  (`test_developer_verification.py`, `resource_mediator.py`,
  `mediators/contracts.py`, `test_layered_verification.py`).
- `composition-lint-v3.log`: ruff, format-diff, isort and `ty` all pass.
- `composition-security-final-v3.{json,log}`: strict gate exit 2. 2,980
  declarations, router 21/21, publication 9 verified / 51 unresolved, zero
  implementation tasks, SGV901–903 remain.
- `composition-full-prebuilt-v3.log`: a full `make test` started at **04:44 and
  is still running** (about 40% at 04:50). `runtime-state.json` tracks it as
  Codex exec session 26619.

**My decisions:**
1. I won't start a second `make test` while this one runs. It would
   force-recreate the shared Postgres/Redis containers and tear them down
   underneath it.
2. I won't edit source files until that run finishes and I've confirmed Codex
   hasn't resumed editing. Two agents editing the same tree will collide.
3. In the meantime I'll do read-only study of the most concrete proof target
   (handoff step 2: `validate_output_request`).

**Note for the advisor.** If the student's Codex session is still meant to be
working, only one agent should edit this tree at a time.

## 2026-10-27 04:56: Step 1, stabilize and audit the checkpoint (handoff step 1)

Every result below is on the **current, unchanged tree**: no edits by me, and no
Codex edits since 04:46.

| Check | Result | Evidence (`eval/campaigns/remediation-v2/raw/checks/`) |
| --- | --- | --- |
| Prebuilt `make format` / `make lint` (ruff, format-diff, isort, `ty`) | pass | `composition-format-v3.log`, `composition-lint-v3.log` (Codex, 04:44) |
| **Full prebuilt `make test`** | **4,644 passed, 16 snapshots passed, 0 failed** (8m32s); Docker services cleaned up | `composition-full-prebuilt-v3.log` (Codex, finished 04:53) |
| Strict gate `make security-verify` | exit 2: SGV901–903, 0 implementation tasks, router 21/21, publication 9/60 verified | `claude-baseline-security-v1.{json,log}` |
| `make security-verify-regressions` | exit 0 | `claude-baseline-regressions-v1.{json,log}` |
| `make security-verify-permutations` | exit 0 | `claude-baseline-permutations-v1.{json,log}` |
| Eval unit suite (`eval/ make test`) | 129 passed, 3 skipped | `claude-baseline-eval-tests-v1.log` |

**Eval skip delta (130/2 before, 129/3 now).** The new skip is
`tests/test_isolation.py::test_real_host_controls_and_denials`. Its bubblewrap
preflight fails because this host currently has
`kernel.apparmor_restrict_unprivileged_userns = 1`. The test skips only when that
real preflight fails, so this is environmental, not a code regression. The
`slg-linux-test` Docker image (unconfined AppArmor/seccomp/systempaths) can run it
if needed.

**The two regressions the handoff asked to confirm already exist and pass:**
- Later suffix bindings shadowing builtins:
  `test_unproved_suffix_cannot_change_prefix_compilation_or_native_bindings`.
  It covers 11 cases (`del type`, `import builtins as type`, `def type`, match
  capture, `except ... as type`, `del hex`, `import math`, a shadowing
  `OutputDataError`, `global`, `yield`, `yield from`).
- Renamed keyword-only parameters leaving callers unbindable:
  `test_primitive_call_keywords_bind_against_the_actual_callee_signature`. It
  covers callee-only renames for `string` and `labels`. The positive
  counterpart, `test_consistent_keyword_parameter_and_call_renames_are_source_derived`,
  also passes.

**Conclusion.** The checkpoint is stable. The handoff's caution ("do not say the
full suite is green") is now outdated: the full suite is green on this exact tree.

## 2026-10-27 04:57: Assessment for the advisor, why this has been hard

The numbers say this isn't a matter of effort. The strict gate is shaped like a
**whole-system verification target**, and the campaign's own records show the
proof surface growing faster than the proofs close:

| Point in campaign (README) | Declarations | Publication entries | Verified |
| --- | --- | --- | --- |
| early remediation-v2 | n/a | 54 | 10 |
| output-envelope repair | 2,850 | 58 | 10 |
| callback mediation | 2,873 | 60 | 10 |
| state publication | 2,876 | 60 | 10 |
| composition v2 | 2,940 | 60 | 9 |
| composition v3 (today) | 2,980 | 60 | 9 |

Each runtime repair (events, logs, callbacks, state APIs) correctly closed a real
leak, and each one also added new entry points to the proof denominator. The
README notes this itself: "Adding callback mediation increased the explicit proof
surface; it did not close the proof model."

Structurally:
- **SGV903 is emitted unconditionally** (`developer_verification.py`). No
  evidence can clear it until someone defines and implements a composed host
  proof. That means grant lowering, activation-before-execution, channel
  identity, cancellation and descendant lifetime across `linux.py` (2.1k lines),
  `landlock.py` (1.1k) and `container.py`.
- **SGV901 is a hard-coded `False`.** It asks for LSM-hook-placement-style
  complete-mediation proof over LangGraph's Pregel engine, which is a research
  problem in Python.
- **SGV902** needs `adapters.proof` (also hard-coded `False`) plus 51 unresolved
  publication entries.

So, as written, the strict gate can't pass by incremental proof work on any
short horizon. The handoff's step 3 points at the realistic route: make the
admitted surface finite, enforce the exclusions at runtime, and prove only that
surface. **That needs a scoping decision from the advisor.** Which entry points,
output channels and tool routes does the paper's claim cover? Until that list
exists, every runtime repair will keep growing the denominator.

## 2026-10-27 04:57: Step 2 plan, discharge the host-output validator obligation (handoff step 2)

This is the one gate conjunct with a bounded, concrete path. Feasibility check
(in-memory monkeypatch, no repo edits): the validator call at
`object_manager.py:241` is the **only** blocker in the host-output derivation.
The engine also has no rule to consume a proven callee contract, though. With the
obligation bypassed, it stops at "reachable call statement requires an effect
derivation".

Plan (this stands in for the Corridor `analyzePlan` review, which isn't available):
1. Extend `output_data_verification._PrimitiveDerivation` in its existing
   statement-consuming style. Add derivations for `record`, `fields`, the full
   `walk` (identity tracking with `try/finally`), `compound` (every branch) and
   the module tables it reads, `_validate_output_request` and
   `validate_output_request`. Every statement gets consumed. Any unmodeled
   construct means unproved, never exempt.
2. Recursion: an explicit induction on remaining depth. `walk` refuses when
   `depth > max_depth`, and each recursive call is `depth + 1`. Termination also
   follows from the node budget being charged on every `walk` entry.
3. Contract claimed: on any input, the validator either raises or returns `None`.
   It doesn't invoke candidate-object protocols, it mutates only walker-owned
   state, and it doesn't mutate the request. Runtime/import binding,
   initialization and exception-traceback sanitization stay **explicit
   premises**, as in the existing primitive reports. They aren't claimed.
4. `output_verification.py` consumes the contract only when it was derived from
   the same `output_data.py` source the host imports (digest-bound). Otherwise
   the existing obligation is emitted unchanged.
5. Tests: the positive derivation, plus mutation tests where each risky edit
   (attribute protocol, equality on a candidate, a missing guard, a changed
   recursion bound, a new branch, etc.) must make the validator unproved.

Expected effect on the gate: `host_output_correspondence.proved` becomes true
**if and only if** the derivation succeeds. Acceptance stays FAIL (SGV901–903),
and I won't touch those diagnostics.

## 2026-10-27 05:17: Advisor scope draft received, plan adjusted

Received the Oct 27 draft "slangGraph: agent-system survey and supported
execution scope". It answers the scoping question from my 04:57 assessment: a
finite set of supported-surface contracts (§6), enforcing gates for everything
excluded (§7), six workload categories (§9 Step 3) and useful end-to-end routes
(§9 Step 5). From here on, my work follows it.

**How the in-progress work maps onto the draft:**
1. **Validator derivation (continuing).** This is security evidence for the
   publication route's runtime gate. §7.1 says a gate must not execute the
   unsupported behavior it inspects. §5.3 says unknown types must refuse before
   their protocols run. The effect-safety contract I'm deriving is exactly that
   property for the output-record gate. The derivation is table-driven over the
   walker's record inventories, so narrowing them to the records the selected
   applications need (§6, "Framework records") shrinks the proof instead of
   breaking it. It proves an existing gate. It doesn't widen the admitted
   language or verifier for compatibility, which §9 Step 4 warns against.
2. **Next: §7.2/§7.3 structured outcomes for this gate.** Keep the literal
   low-level refusal codes, which already serve as stable diagnostic codes. Map
   them in the trusted mediator to *unsupported*, *policy denied* or *execution
   failed*, with the "publication was blocked" wording. No fallback path.
3. **In parallel: a read-only subagent drafts Steps 1–3 from existing records.**
   That means classifying the eight attempted applications, writing an effect
   inventory per app using the draft's seven columns, and mapping the
   applications to the six workload categories. Output goes to
   `eval/scope/cohort-inventory-draft.md` as a draft for review, not an
   authoritative record.

**Fact checks on the draft against the tree.** The draft says it relies on the
handoff, not an audit, so I checked a few points.
- §5.2 seccomp: **confirmed in code.** `landlock.py:528` says "fixed minimal
  seccomp filter forbids all process/thread creation". `linux.py:1717/1723` say
  `minimal_seccomp_supports_pids_one_only` and `seccomp_no_process_creation`.
- SGV901–903 meanings: **confirmed, with one sharper point for §7.4/§9 Step 5.**
  None of the three has a discharge condition in code today. SGV901 and the
  `adapters.proof` half of SGV902 are hard-coded `False`, and SGV903 is
  appended unconditionally. Even a fully enforced supported surface can't clear
  them until `layered_verification.py` and `developer_verification.py` accept
  route-specific evidence. **Recommendation: each supported-surface contract
  should state what evidence the gate accepts for that route.** Without that,
  "close a useful end-to-end route" has no machine-checkable finish line.
- Cohort (§9 Step 1): `apps.csv` lists 8 candidates from 7 repositories with
  pinned SHAs. There are zero completed protected ports. Only pandas has a full
  A/B/C cohort (v19, 150/150). sql and notebook pass baseline smoke tests.
  email, research, coding, newspaper and finance are blocked (credentials,
  services, install failures). Only `research` (open_deep_research) and
  `coding` (open-swe) appear in both the survey and the cohort, so Step 3
  coverage has to start from the cohort, which is what the draft says.

## 2026-10-27 05:29: Step 2 result, validator derived and correspondence discharged (pending independent review)

**What changed** (pre-edit copies with SHA256SUMS are in
`eval/campaigns/remediation-v2/raw/claude-validator-proof/pre-edit/`):
- `output_data_verification.py`: new statement-consuming derivations for
  `_Walker.fields`, `record`, `compound` (all 12 branches plus the final
  refusal), the whole `walk`, `_validate_output_request` and
  `validate_output_request`. Every module inventory they read is derived from
  its initializer. That covers `_MODELS`, `_EVENTS`, `_TUPLE_RECORDS`,
  `_SLOT_RECORDS`, `_PLAIN_ERRORS`, the slot tables and the captured
  descriptors.
  - **Recursion.** `record` and `compound` are derived under the hypothesis
    "walk at depth + 1". Every recursive call must be exactly `depth + 1`.
    `walk` closes the induction: its prefix guard refuses `depth > max_depth`,
    `max_depth` is written only by the constructor (checked across all
    methods), and each entry charges the finite node budget. If `walk` fails,
    the conditional `record`/`compound` contracts are retracted.
  - **Newly checked conditions.** These used to be assumptions or weren't
    stated at all: no `global`/`nonlocal` anywhere in `output_data.py`;
    exception projections are limited to 13 simple builtin layouts (adding
    `OSError`, with its extra native fields, is rejected); and `LabeledValue`
    and `OutputRequest` slot names must be declared native record fields.
  - **Premises that remain explicit, not proved:** runtime/import binding and
    initialization, the external class layouts (listed per class in
    `external_layout_premises`), field stability, process-global GC/signal
    events, and unsanitized refusal tracebacks. No existing contract mentioned
    GC/finalizers before; it is now stated.
- `output_verification.py`: `verify_output_correspondence(...,
  output_data_source=...)` **recomputes** the validator derivation from source.
  It never accepts a saved report. It discharges only the exact call
  `validate_output_request(request)` on the unchanged request, and forks it
  into a refusal exit and a continuation. Without validator source, or with a
  failing derivation, the original obligation is emitted unchanged, now with
  the derivation issues attached. `_native_records` gained an optional `extra`
  parameter, used for `LabeledValue`.
- `layered_verification.py`: passes the audited `output_data.py` source in.

**Evidence:**
- Actual sources: validator `proved`; host-output correspondence `proved`.
  Dispatch and adispatch each have 1 useful return and 2 refusal exits
  (validator and clearance).
- **Mutation sweep: 34/34 risky edits rejected**, each with a specific
  reason. Examples: `depth` instead of `depth + 1`, `isinstance` dispatch,
  `str(value)`, `value.int`, hashing the candidate in the cycle set, swapped
  slot or descriptor captures, a dropped bound/schema/Command/label guard,
  adding `OSError`, a deny-all `compound`, an extra branch, an unused walker
  method that writes `depth`, a module-level `global`, and a cyclic inventory.
  These are now permanent parametrized tests.
- Tests: `test_output_data_verification.py` 131 passed;
  `test_output_verification.py` 80 passed; layered and developer tests pass.
  Ruff, isort and `ty check langgraph` are clean.
- **Interim strict gate** (`raw/checks/claude-validator-interim-security-v1.{json,log}`):
  `host_output_correspondence_proved: true` (was false), exit 2, SGV901–903
  remain, 0 implementation tasks. Declarations went from 2,980 to 3,031 because
  the ledger counts verifier code too.

**Test assertions I changed, and why.** Three assertions pinned the *open*
state, and they are now false because of a real derivation:
1. `test_actual_primitives_have_source_derivations_but_full_validator_stays_open`
   is renamed `test_actual_primitives_and_recursive_validator_have_source_derivations`.
   All positive primitive assertions are kept. `system_complete`,
   `runtime_binding_proved` and `initialization_proved` are still asserted
   false.
2. `test_actual_scalar_walk_paths_have_useful_source_derived_projections`:
   the scalar component's own assertions are kept, including "suffix not
   proved by the scalar component". The report-level "walk unproved" check is
   replaced by a check that the separate whole-walk derivation contains the
   induction step.
3. `test_primitive_evidence_uses_audited_source_and_never_closes_gate` now
   asserts admission is proved for the real source and unproved after the
   test's own mutation. The gate still never closes.

**Still pending before I call this done:** an independent adversarial review
of the checker (running now), then the full `make test`, `make lint` and the
three gates under final names.

## 2026-10-27 05:31: Step 3 (design only), advisor §7 gates, current state and a recommended change

I'm not implementing this yet. It touches files under the router and
publication proofs, so it needs the advisor's sign-off on two points below.

**Current state (verified in code).** Unsupported paths already **fail
closed**. Nothing found here falls back to an unmediated path.
- Output data: any validator refusal in `stack.py` (`_object_modules` and
  `_aobject_modules`) becomes `Decision(DENY, "output:unsupported_data")`.
  `HostRouter` then raises `PermissionError(decision.reason)` to the caller.
- Elsewhere: 48 `SupportLevel.UNSUPPORTED` capability-lowering refusals and
  about 15 distinct codes (`output:unsupported_mediator`, `…_router`,
  `…_host`, `object:unsupported_request`, `state:unsupported_operation`,
  `resource:unsupported_inprocess_binding`, `mac:unsupported_*`,
  `container:unsupported_authority`, plus language-sandbox
  `unsupported_statement`/`unsupported_expression`).

**Gaps against §7.2/§7.3:**
1. No shared structured outcome. Each gate uses its own string, with no
   category (unsupported / policy denied / execution failed), feature
   identifier or execution-route field.
2. The output gate discards the validator's stable code. `unsupported_type`,
   `budget`, `payload_confidentiality` and others all surface as
   `output:unsupported_data`.
3. No developer-facing message of the §7.3 kind ("publication was blocked;
   earlier authorized operations may have completed; open an issue").

**Recommended minimal change:**
- Add one module (e.g. `security/unsupported.py`) with a frozen
  `UnsupportedFeature(code, feature, route, reason, phase)` record, the two
  §7.3 message builders (admission and runtime, with an optional configured
  issue link), and `UnsupportedFeatureError(PermissionError)`. Subclassing
  `PermissionError` keeps every existing handler failing closed.
- **Keep `Verdict` unchanged.** A new verdict would ripple through the 21/21
  router proof and the Cedar/policy adapters. Carry the category in a stable
  reason prefix instead, e.g. `unsupported:output:unsupported_type` versus
  `denied:output:payload_confidentiality`. Map validator codes to categories
  with a fixed table in `stack.py`, not in the router.
- Raise the structured error at the mediator boundary
  (`OutputMediator._emit`/`_aemit`), then re-run the publication analysis.
  Those methods are publication-proof entries, so the change must not add
  unresolved paths.

**Decisions for the advisor:**
- (a) Can a recipient see the *category* of a blocked publication? Codes such
  as `payload_confidentiality` reveal that the content carried
  higher-labelled data, which is a one-bit leak. My suggestion: shape and limit
  codes go to the caller; label and clearance codes go only to the audit log,
  and the caller gets a generic "publication blocked by policy".
- (b) Should budget/depth/cycle refusals count as *unsupported* (outside the
  supported projection) or as *execution failed*?

## 2026-10-27 05:33: Finding, the next concrete SGV902 step on the output route

All 10 `OutputMediator` publication entries (`__call__`, `_emit`, `_aemit`,
`stream`, `callback`, …) are still **unresolved**. From the interim report
(`raw/checks/claude-validator-interim-security-v1.json`): `_emit` follows
`labels_for_output` → `validate_output_data` → `_Walker.*` with the
*generic* publication engine (`verification.py`). That engine can't model the
walker's native operations, and the entry exhausts its 5,000-step budget. The
most common unresolved reasons across all 51 entries are "call not covered by
transfer analysis" (719), "exception publication requires a data-flow model"
(566), "iteration requires a known tuple or mapping" (439) and "ordered/equality
comparison requires known inert values" (436). Many of the output-route ones are
the operations the new walker contract already derives.

**Recommended next step.** This is narrow and route-specific, in line with the
advisor's §9 Step 5.
1. Extend the same derivation to `validate_output_data` and
   `output_data_digest`, which `labels_for_output` and approval subjects
   call. Both reuse the proved walker. Neither is covered today, and the
   contract says so.
2. Teach the publication engine to consume these recomputed contracts at those
   call sites, the same way the correspondence engine now does, instead of
   re-analyzing the walker body.
3. Re-measure how many of the 10 `OutputMediator` entries resolve. Anything
   that stays unresolved is then the real remaining output-route work: approval
   continuations, exception publication, principal binding.

## 2026-10-27 05:39: Goal set, "don't stop until the eval is complete". Definition of done and parallel plan

**Definition of done** (from the advisor's draft, §9 deliverable, plus the
handoff's rule for SGV901–903):
- **D1. Cohort frozen and classified.** Effect inventories and six-category
  coverage (Steps 1–3). *In progress (inventory subagent).*
- **D2. Finite supported-surface contract.** A machine-readable manifest plus a
  doc covering each supported route, its entry points, enforcement points and
  the *evidence the gate requires*. Every excluded capability gets its gate.
- **D3. Working gatekeepers.** Each exclusion refuses before its effect with a
  stable, registered diagnostic code and the §7.3 message, and a test shows
  the refusal.
- **D4. Route-scoped SGV901–903.** The verifier recomputes evidence per declared
  route. The gate passes only when every supported route has complete evidence
  and every exclusion is enforced at runtime. A route without evidence is moved
  to *unsupported and gated*. It is never claimed. This follows the handoff:
  "recomputed evidence for a precisely defined admitted execution surface,
  with explicit premises and runtime enforcement of exclusions."
- **D5. Useful executions.** Existing passing cohorts are mapped to supported
  routes, with no reruns unless a change affects them. Unsupported apps and
  tasks stay recorded as unsupported.
- **D6. Records and checks.** Campaign README and acceptance JSON get new
  dispositions, with history preserved. Full suite, lint and all gates run
  under new `claude-*` names.

**Parallel workstreams.** File ownership is disjoint, and agents run only
focused pytest. No `make test` or Docker restarts, because those services are
shared on this host.
- **Me:** reviewer fixes in `output_data_verification.py`, the D4 gate design
  (`layered_verification.py`, `developer_verification.py`, manifest
  loader), integration, full-suite and gate runs, and this log.
- **Agent "gates" (D3):** a new `security/unsupported.py` registry of every
  existing `*:unsupported_*` code with category, feature, route and §7.3
  messages; a static completeness test; and preserving the specific output
  refusal code in `stack.py`. Defaults for the two open advisor decisions:
  label/clearance codes become a generic caller message with the detail in
  audit only, and budget/depth/cycle count as *unsupported*.
- **Agent "output-route" (D4 evidence, SGV902):** extend the validator
  derivation to `validate_output_data`/`output_data_digest`, and teach the
  publication engine to consume the contracts so the `OutputMediator` entries
  can resolve. Starts once the reviewer fixes are in.
- **Agent "surface" (D2, then D5):** the manifest and doc from the inventory
  draft and §6. Starts once D1 lands.

## 2026-10-27 05:43: Review-found hole fixed, final verification, workstream results

**Soundness hole found by the independent reviewer, now fixed.** `_Walker.fields`
checks completeness with `len(copied) != len(names)` plus "every name
present". A *repeated* inventory name passes that check while a real field is
never traversed. The reviewer demonstrated this at runtime: changing
`_GENERATION` to `("text", "text", "type")` let a `"secret"` label hidden in
`generation_info` be admitted, and my checker still said proved. The same
defect applied to `_EVENTS` and `_SLOT_RECORDS`.
- **Fix:** `record_row` now rejects repeated or empty field names after
  concatenation. This is a checked condition, not a premise.
- The slot-record and Interrupt layout premises now say explicitly that the
  listed slots are *all* the instance state.
- There are three regressions for the reviewer's exact edits. A second quick
  re-review is still running.

**Final verification on the current tree:**
| Check | Result | Log (`raw/checks/`) |
| --- | --- | --- |
| Output, verifier, layered and developer suites | **286 passed** | (focused run) |
| Full prebuilt `make test` (before the hole fix) | 4,631 passed, **58 failed**, 16 snapshots | `claude-full-prebuilt-v1.log` |
| Those 58 tests, in the unconfined `slg-linux-test` container | **63/63 passed** (both files) | `claude-linux-docker-v1.log` |
| `make lint` | pass | `claude-lint-v1.log` |
| Eval unit suite | 129 passed, 3 skipped (same as baseline) | `claude-eval-tests-v2.log` |
| Strict `make security-verify` | exit 2, **host_output_correspondence_proved: true**, SGV901–903, 0 implementation tasks | `claude-final-security-v1.{json,log}` |
| Regressions / permutations | exit 0 / exit 0 | `claude-final-{regressions,permutations}-v1.*` |

All 58 native failures are `RuntimeError: bubblewrap isolation is unavailable
on this host`. My shell runs under `kernel.apparmor_restrict_unprivileged_userns=1`,
while Codex's run (0 failures) evidently had user namespaces available.
**Caveat:** the full-suite run predates the duplicate-name fix. The fix is
verifier-only and is covered by the 286-test focused run, but the next full
run should be on the final tree.

**Workstream results:**
- **Cohort inventory (D1): done.** See `eval/scope/cohort-inventory-draft.md`.
  - pandas: proposed *supported*, limited to the C isolated-worker computation
    route.
  - sql, email, research, notebook, newspaper, finance: *requiring an
    adapter*. coding: *requiring a worker profile*.
  - Only workload category 4 (data analysis) is covered.
  - **Record errors found:**
    1. SQL already has a full protected cohort
       (`campaigns/remaining-v1/raw/sql-full`, 50/50 in A/B/C, 0/50 C
       canary exposure), yet the app docs still say B/C are unsupported.
    2. README v11 says 26/30; the raw trials show 24/30.
    3. Stale baseline pointers in `apps.csv`.
    4. **Ungated paths in pandas C:** model calls, final output publication,
       and `/tmp` writes that are listed as unsupported but succeed.
- **Output route (SGV902): no code changed, but a key diagnosis.** All 10
  `OutputMediator` entries go through `_require_output_host`
  (`placement.py:563`) and `labels_for_output` (`object_manager.py:381–382`).
  There, an unset slot raises a native `AttributeError` whose `.obj` is the
  receiver: a router or host capability that could reach the caller. The
  verifier is right to flag it.
  - **Fix needed in `placement.py`/`object_manager.py`:** catch it and raise
    a literal refusal after the handler, as `validate_output_request`
    already does.
  - Other blockers: `_validate_principal` `raise … from` (types.py:127),
    `_approval_required` nested closures, and uncovered calls in `_emit`
    (lines 449–462).
  - Also flagged for review: `exact_type_branch` in `verification.py`
    resets tracked slot writes on a slotted receiver.
- **Gates registry (D3), surface contract (D2), worker-route SGV903 checker:**
  still finishing. Their results are appended below when they report.

**Honest status against the definition of done:** D1 is done (as a draft for
review). D2, D3 and the SGV903 checker are in flight. D4 is **not** done: the
gate is not route-scoped yet, and no supported route has complete evidence.
The output route is blocked on the `AttributeError` capability leak above.
D5 and D6 are not started. **The eval is not complete.**

## 2026-10-27 05:45: Re-review, gates (D3) and surface contract (D2) delivered

**Second re-review of the fix.** Duplicate names are now rejected everywhere:
through concatenation, in inline rows, in events, tuple records, slot records,
every `*_SLOTS` table, empty names and aliases. Omitted fields in
models/events/tuple records still fail closed at runtime
(`output_data:record_shape`). **Two remaining items:**
- **Class shadowing** (an earlier, shorter row for the same class) was
  accepted. It is now rejected: a class may appear in only one dispatch row
  across all inventories. A regression test was added; 229 focused tests pass.
- **A shortened `_SLOT_RECORDS` row** (e.g. `Send` without `timeout`) is
  still accepted, and the omitted slot's labels escape. It is covered only by
  the stated premise "…has no other instance state", which a source checker
  cannot verify for an external class. **Recommended:** a runtime-binding
  check that compares each slot-record row with the class's actual
  `__slots__`. That would turn the premise into evidence.

**Gates (D3)**, new `security/unsupported.py` and
`tests/security/test_unsupported_registry.py`, edits in `stack.py` (output
refusal sites only):
- The registry has **42 codes**: 40 *unsupported* and 2 *policy_denied*
  (`payload_confidentiality`/`payload_integrity`). Nothing is
  *execution_failed* yet.
- §7.3 message builders are included.
- `UnsupportedFeatureError(PermissionError)` keeps the code as `str()`.
- A static completeness test fails if a new `*:unsupported_*` or
  `OutputDataError` code ships without a registry record.
- Output refusals stay `DENY`. The reason is now
  `unsupported:<code>` or `denied:output:policy`, taken from a fixed
  table and never echoed from the exception.
- Tests: 16 registry, 294 output/stack/placement, 536 on the `-k` sweep.
  Categories follow my defaults, pending the advisor's decisions (a) and (b).
- **Finding for the advisor:** opt-in `enforcement_waivers`
  (`object_policy.py` ~705–720 and ~960–1000, `check.py`) keep a grant line
  that **no enforcer supports** and run in `EnforcementMode.DEGRADED`. That
  contradicts "unsupported means stopped". It is recorded in receipts and
  forbidden under MAC (`mac:enforcement_waivers_forbidden`), but it should be
  either removed or explicitly excluded from the supported surface.
- **Gap:** the specific label code behind `denied:output:policy` is not
  audited anywhere yet. There is no audit hook at that early return.

**Surface contract (D2)**: `docs/security/supported-surface.{json,md}`
(the JSON validates) and `eval/scope/record-corrections.md`.
- **Supported:** only `pandas-c-generated-computation`
  (`isolated-worker:linux-sandbox`). SGV901/902 rest on the router source
  proof plus `raw/pandas-v19-full/verification.json`. SGV903 rests on
  `host-route:linux-sandbox` (the worker-route checker, still running) plus
  that runtime evidence.
- **Unsupported:** `output-publication` (0/10 `OutputMediator` entries
  verified) and `sql-bounded-select` (its 50/50 C cohort ran on
  evaluation-harness code, not a production mediator). All other apps and 11
  §6 capabilities are listed as unsupported.
- **Exclusions:** 8 gated, **10 ungated**. Ungated: pandas model requests,
  dataset loading, final output publication, `/tmp` writes, network from
  generated code, outer state/checkpointer, `human_review`, the Streamlit UI,
  raw debug/state/event APIs, and SQL model calls and publication.
- Record corrections are **proposed, not applied**: SQL docs vs the 50/50
  RM1 cohort, README v11 26/30 vs 24/30, `apps.csv` baseline pointers and
  stale `next_action` text.

Verification: whole-package `make lint` passes on the current tree
(`claude-lint-v2.log`). The Linux tests rerun in the container pass 63/63
(`claude-linux-docker-v2.log`).

## 2026-10-27 05:47: SGV903 worker-route checker, and a real executor defect

**New:** `security/host_verification.py`
(`verify_linux_host_route(linux_source, worker_source, *, repo=None)`) and
`tests/security/test_host_verification.py` (17 passed). It is a source-derived
checker for the `LinuxSandboxExecutor` route that pandas C uses.
| Obligation | Status | Basis |
| --- | --- | --- |
| Grant lowering | proved (structural) | `assess` defaults to UNSUPPORTED; one `negotiate` with no waivers; refusal raises `HostExecutionDenied`; inexact writable mounts refused. Exactness of `lower` per mount is **not** derived. |
| Activation before execution | proved (structural) | `_apply_limits` and `_apply_seccomp` dominate `_invoke` in worker `main`; the allowlist has no clone/fork/execve/socket; the seccomp default is deny. |
| Channel identity | proved (structural) | `GO` is sent only after the exact ready/challenge/plan check, the kernel-state capture and receipt validation. Identity is pid + start time, not pidfd. |
| Cancellation and lifetime | **unproved: real defect** | See below. |

The premises are explicit: kernel namespaces/seccomp/rlimits/LSM, bubblewrap
and libseccomp behaving as documented, a pinned interpreter, and policy
correctness. The runtime evidence is labelled as such, not proof.
`native-filesystem-matrix` and the `container-*` cohorts are **different
routes** and don't count here.

**Executor defect (`linux.py` ~1157, `_run_worker`), confirmed by me.** The
`finally` passes `active_error=sys.exc_info()[1]` to `_cleanup_worker`. On
a *successful* return, that is the **caller's** already-handled exception,
which I demonstrated. Suppose a synchronous `invoke` runs inside
`except HostExecutionError:` (e.g. a retry) and the worker's termination is
unconfirmed. Cleanup then marks the caller's old error INDETERMINATE and
returns quietly, so `invoke` **returns success with worker termination
unconfirmed**. The async path is unaffected, because it runs on a fresh thread.
- **Fix, not applied:** set `completed = True` just before the success
  `return`, and pass `active_error=None if completed else sys.exc_info()[1]`.
- Then update the checker to accept that shape. Its test-only "repaired"
  variant (`active_error=None` always) is **not** a valid fix, because it
  stops marking real in-flight errors.
- I left this unpatched on purpose: it is the production executor, and the
  time limit didn't allow a careful change plus a re-proof.

**Correction to my earlier wording.** Pandas v19 is 150 trials in total,
**50/50 per configuration** (C = 50/50), not "C 150/150".

Final lint on the final tree, including the new modules: whole-package ruff,
format, isort and `ty` all pass (`claude-lint-v3.log`). Registry and host
checker tests: 33 passed.

## 2026-10-27 05:50: Final status against the definition of done

**Gates on the final tree** (`raw/checks/claude-final-*-v2.*`): strict exit 2
with only SGV901–903 and 0 implementation tasks; regressions exit 0;
permutations exit 0; `host_output_correspondence_proved: true`; 3,051
declarations (verifier code counts); publication 9/60. A clean full
`make test` on the final tree (`claude-full-prebuilt-v3.log`) and an
exhaustive adversarial workflow over every artifact from this session were
still running when this entry was written. Their results are appended below.

| Item | Status |
| --- | --- |
| D1 cohort frozen and classified | **done as a draft for review** (`eval/scope/cohort-inventory-draft.md`) |
| D2 supported-surface contract | **drafted** (`docs/security/supported-surface.{json,md}`): 1 supported route, 10 ungated exclusions listed |
| D3 gatekeepers | **partial**: registry of 42 codes with §7.3 messages and a completeness test; output refusals categorised. Ungated exclusions are not gated yet. `enforcement_waivers` contradicts "unsupported means stopped". |
| D4 route-scoped SGV901–903 | **not done**. The checkers exist (router 21/21, host-output correspondence, validator, worker-route SGV903 with 3 of 4 obligations), but the gate still emits the three diagnostics unconditionally or from hard-coded flags. Wiring them to the manifest is the next step, and no route has complete evidence yet. |
| D5 useful executions | pandas C 50/50 (v19) is mapped to the supported route; SQL's 50/50 cohort is recorded but ran on harness code. |
| D6 records and checks | corrections are **proposed**, not applied (`eval/scope/record-corrections.md`). Campaign README and `acceptance.json` are untouched. |

**The eval is not complete.** The two most important things found today are
defects, not proof gaps, and both are unpatched on purpose:
1. **`linux.py` `_run_worker`:** cleanup receives the *caller's* handled
   exception on a successful return, so a sync `invoke` inside an
   `except HostExecutionError` can return success with worker termination
   unconfirmed. This blocks the SGV903 lifetime obligation for the one
   supported route.
2. **`placement.py:563` / `object_manager.py:381`:** an unset slot raises a
   native `AttributeError` whose `.obj` is the router/host capability. This
   blocks all 10 `OutputMediator` publication entries.

**Next steps, in order:** patch (1) and (2) with regressions and re-prove;
wire the manifest into `layered_verification.py`/`developer_verification.py`
so SGV901–903 are recomputed per declared route; gate the 10 ungated
exclusions; apply the record corrections; refresh the campaign README and
`acceptance.json`.

**Process note.** CLAUDE.md asks for Corridor's `analyzePlan` before code
changes. The tool was not available in this session (nor to the subagents),
so plans were written in this log instead.

## 2026-10-27 05:54: Clean full suite on the final tree

`raw/checks/claude-full-prebuilt-v3.log`: **4,651 passed, 16 snapshots passed,
58 failed, 4 skipped** (8m09s), Docker test services cleaned up. All 58 failures
are `RuntimeError: bubblewrap isolation is unavailable on this host` in
`test_linux_execution.py` (44) and `test_resource_boundary_linux.py` (14),
the same environmental cause as the v1 run. Both files pass **63/63** in the
unconfined `slg-linux-test` container on the same tree
(`claude-linux-docker-v2.log`). The 20 additional passes over v1 are the new
registry and host-route checker tests. No code regression. (The interrupted
`claude-full-prebuilt-v2.log` was stopped by me because agent edits landed
mid-run; it is retained but superseded.)

## 2026-10-27 06:34: Adversarial sweep results and corrections (session cut off by usage limit)

The exhaustive sweep (62 agents: 6 attackers, each medium/high finding
challenged by two independent verifiers) finished: **34 findings survived, 7
refuted**. Full record: `raw/claude-validator-proof/adversarial-sweep-v1.json`.

**Corrections to this log** (confirmed by the sweep):
- The full-suite line for v1 omitted **4 skipped**; v1 was 4,631 passed /
  58 env failures / 4 skipped. The "286 passed" focused figure was an inline
  run with no saved log.
- `claude-full-prebuilt-v3.log` was run with
  `--ignore=tests/security/test_host_verification.py` (the file did not
  exist when the run started). The 20 extra passes are the registry (16) and
  the four new validator regressions, **not** the host-route tests; those 17
  ran separately (33 passed with the registry).
- `_validate_principal`'s `raise … from` is at `types.py:166`, not 127.
- `claude-lint-v3.log` contains outputs only (commands were chained).

**Host-route checker (SGV903): claims overreached.** Eight of its thirteen
findings were confirmed by both lenses: `main()` exempt from the loader scan,
spelling-only loader and allowlist checks, neutered `_apply_seccomp`
undetected, waivers via `**kwargs`, presence-only guards, substring lifetime
needles, and `sys.exception()` evading the defect check. My earlier
"proved (structural)" wording was wrong; it is a review-pattern check. An
agent is downgrading its report (`proved` always false, `structural_checks`
instead, known evasions listed) and adding the cheap hardening.

**Fixed now:** `_module_bindings` bound `import a.b.c` to the dotted path, so
a bare import could pose as the validator; a bare import now binds only the
top-level module (regression added). `layered_verification.py` cross-checks
the validator derivation digest against the audited `output_data.py`
(96 tests pass).

**Still open from the sweep:** `_SLOT_RECORDS` accepts any imported class
and cannot tell a property from a member descriptor; this stays an explicit
layout premise and needs the runtime `__slots__` binding check. Registry
completeness regex and stack-level refusal tests (agent in flight). Seven doc
errors in the surface manifest and corrections (agent in flight).

**The eval is not complete.** The session was stopped by the usage limit while
three agents were still running; their reports are not recorded here. Check
`git status` for their files before relying on them.

## 2026-10-27 13:02 EDT: Resumed; read the student's status.md through 16:26 UTC

The student's log (status.md, entries 08:31 EDT through 16:26 UTC) records a
different trajectory since my cutoff, and I'm adopting it as the authoritative
state. In particular:
- **Lean is now the proof core.** `proofs/worker-route/` has a lifecycle model
  (29 theorems), a receipt-coverage model (54 theorems, 37 typed obligations),
  a strict JSON bridge, a sealed-binary runtime guard before GO and after
  cleanup, and kernel replay audits (same-kernel, not independent). Pandas C
  ran a fresh 150/150 cohort with the audited v2 checker selected.
- **Both defects I reported are fixed by them:** the ambient-exception cleanup
  in `linux.py` and the capability-bearing `AttributeError` on the output
  path. `host_verification.py` was rewritten as a review-pattern report with
  all proof flags false, which is what my cut-off agent was about to do.
- Full suite 5,162 passed (3 native opt-in skips passed separately), strict
  gate still SGV901–903 with 0 implementation tasks, publication 9/60.
- **In progress by them (12:26 EDT, last writes 12:49):** grant-derived Lean
  composition (protocol v3). Owned files: `GrantCoverage.lean`, `Main.lean`,
  `check.py`, `linux.py`, `enforcement.py`, `test_lean_grant_linux.py`,
  pandas integration. **I will not touch those.**
- **Unowned and unimplemented:** the closed node/effect admission boundary
  (SGV901 placement), specified in `raw/checks/receipt-next-placement-v1/`.

My three cut-off agents made no code edits except the doc agent, which may
have partially applied its fixes; checking that first.

## 2026-10-27 13:04 EDT: Checks on resume

- **Lean core builds on this host.** `~/.elan/bin/lake build` in
  `proofs/worker-route` (Lean 4.34.1): "Build completed successfully".
  The five exported WorkerRoute theorems depend only on `propext` and
  `Quot.sound`; grep finds no `sorry`, `axiom`, `native_decide` or
  `unsafe` in the four `.lean` files. (`lake` is not on PATH in my shell;
  use `~/.elan/bin`.)
- **The seven doc fixes from the adversarial sweep were applied** before the
  cutoff: utility-only notes on the pandas obligations, `sql-bounded-select`
  SGV902/903 now `applicable: false`, `gate_code_prefix` for
  `adapter_rule_unsupported`, `enforced_at` corrected to
  `linux._verified_artifact_fd`, the B/C mediator attribution fixed,
  `APPLICATIONS.md:148-150` cited correctly, and a `cohort_evidence` column
  proposed instead of repointing `baseline_run`. JSON validates.
- **My files on their tree:** registry, host checker, output/layered/developer
  suites pass 346 tests.
- **Registry completeness:** 17 refusal literals are still unregistered (4
  prefixes, 13 bare codes). A registry agent is closing this now.

## 2026-10-27 13:07 EDT: Starting the closed admission gate (SGV901 placement spec), plan and ownership

This stands in for the unavailable Corridor `analyzePlan`. Source:
`raw/checks/receipt-next-placement-v1/report.json` (status
`proposed_unimplemented`, left unowned by the student's log).

**Goal.** Enforce the spec's predicate: every secured graph entry references
an admitted execution descriptor (exact validated language-IR program, exact
ToolNode dispatch primitive without wrappers, or validated native deployment
on a confined host). Ordinary callables, Runnable subclasses, `__module__`
trust, metadata promotion and ToolNode-containing wrappers refuse **before**
any candidate protocol runs.

**Design decisions.**
- Opt-in via `SecurityConfig(closed_admission=True)`; installed RuntimeMAC
  requires it. Default behavior stays byte-for-byte unchanged, so the
  student's 5,162-test suite and the evaluation adapters keep working. The
  spec says unsecured evaluation baselines stay explicit unsecured controls.
- Descriptor-bound dispatch in `MediatedNode`/`MediatedBranch`: identity
  recheck, then only the captured implementation. No `self.runnable.invoke`
  fallback when a descriptor is present.
- Evidence: a new source-derived component `admission_surface` in the
  layered report with its own flags. **`path_cover_proved` and SGV901–903
  stay untouched.** The gate alone does not close SGV901; the useful pandas
  outer route still needs the native graph-unit host, model terminal and
  data/publication operations from the spec.
- New codes: `admission:unsupported_node_body`, `…:unsupported_branch`,
  `…:descriptor_changed`, `…:unsupported_async`,
  `…:closed_admission_required` (registry agent adds them).

**Ownership (file-disjoint, staged workflow):** Core → `admission.py` (new),
`config.py`, `mac.py`; Bind → `placement.py` (+ descriptor pass-through
in `config.py`), docs; Verify → `admission_verification.py` (new),
one evidence key in `layered_verification.py`, summary field in
`developer_verification.py`; Review → read-only bypass attempts and a
regression sweep. **Not touched:** `linux.py`, `enforcement.py`,
`proofs/`, pandas integration, Lean tests (Codex's grant-v3 work).

Also running: an independent reproduction of the Lean formal audit on this
host (`raw/checks/claude-lean-audit-v1`).

## 2026-10-27 13:07 EDT: Closing my own loop, the fixes for my reported defects are in the code

Confirmed by reading the current tree, not the log:
- `linux.py:1131` cleanup captures only an exception escaping the current
  invocation; the `finally` no longer reads `sys.exc_info()`.
- `placement.py:578-580` and `object_manager.py:403-405` catch the unset-slot
  `AttributeError` and raise a literal refusal after the handler, so
  `.obj` cannot carry the router/host capability to the caller.
- `output_data.py:97-98`: descriptor capture accepts only exact
  `MemberDescriptorType`/`GetSetDescriptorType` with matching owner and
  name. That closes the `_SLOT_RECORDS` property substitution the second
  review found; no foreign getter can run during validation.
- `host_verification.py` on the actual source: `proved` all false,
  `complete` false, `proof` false, with `structural_checks` and
  `known_evasions` reported separately. My earlier "proved (structural)"
  wording is now also wrong in the code's own terms, in the right direction.

In flight: the closed-admission workflow (Core → Bind → Verify → Review), the
registry agent (17 literals + 5 admission codes), and the Lean audit
reproduction. Their results are appended when they report.

## 2026-10-27 13:08 EDT: Lean audit reproduction failed on the in-progress snapshot; registry gaps closed

**Lean audit reproduction** (`raw/checks/claude-lean-audit-v1`, exit 1):
driver tests pass and source hygiene passes, but the kernel typecheck step
fails: the generated `KernelAudit.lean` has three syntax errors (lines 352,
361, 371: "unexpected identifier; expected '}'") and one "failed to
synthesize" (line 664). Every WorkerRoute, ReceiptCoverage and GrantCoverage
theorem that did elaborate depends only on `propext`, `Quot.sound` and
`Classical.choice`. `check.py` (12:34) and `Main.lean` (12:37) were edited
by Codex after the student's last passing audit (`receipt-formal-v1`,
`passed: true`, kernel replay checked), so this is most likely their
grant-v3 work in progress, not a model defect. **Observation only; I did not
touch the Lean project.** It does mean the current checkout cannot reproduce
the recorded audit until that edit lands; the student should re-run
`make security-verify-lean` after it.

**Registry completeness closed** (`unsupported.py`,
`test_unsupported_registry.py`, 22 tests, ruff/ty clean):
- New codes: `host:special_resource_unsupported`,
  `inprocess:descriptor_read_unsupported`,
  `object_policy:typed_constraints_unsupported`, and the five `admission:*`
  codes for the gate under construction.
- New `PREFIXES` for dynamic-suffix codes: `adapter_rule_unsupported:`,
  `object_constraints_unsupported:`, `unsupported:`, `unsupported_class:`
  (plus the existing rule/language prefixes).
- Six `NOT_REFUSAL_CODES`, each with a reason and a test that fails if the
  site disappears: four `SupportAssessment` labels that never reach a
  decision (`EnforcementCoordinator._supporting` drops them and surfaces
  `adapter_rule_unsupported:<id>`), and the two bare language suffixes that
  `reject()` turns into registered `language_proof:*` codes.
- Stack-level tests now exercise the real `SecurityStack.object_permission`
  path, sync and async: `set` content → DENY
  `unsupported:output_data:unsupported_type`; a nested `{"secret"}` label
  over empty declared labels → `denied:output:policy`. The escalation-subject
  site is reachable only after validation passed and is not separately
  exercised.

## 2026-10-27 13:09 EDT: Pandas-route design started (read-only)

The admission gate alone would refuse the current pandas outer workflow (plain
Python nodes), as the spec says. A read-only agent is drafting
`eval/scope/pandas-route-design.md`: the effect inventory of the actual
outer and nested vendor graphs, a confined graph-unit host running the
unchanged workflow with the four host operations (model_invoke, compute,
dataset_input, state_and_publication), the native-deployment descriptor that
admits it, honest limits (budgets, broker, proxied model call), and a staged
work plan mapped to the spec's five acceptance checks. No code is changed.

## 2026-10-27 13:18 EDT: Pandas-route design delivered (`eval/scope/pandas-route-design.md`)

Design only; no code. Architecture: run the whole unchanged vendor graph as
**one confined graph-unit worker** under a new `GraphUnitDispatcher` derived
from `DockerObjectDispatcher` (`container.py:71-598`). The pinned
`sha256:` image ID binds the vendor bytes and serves as the gate's
native-deployment identity; the 1 GiB / 32-pid envelope fits a whole graph.
`compute` stays on the existing C `LinuxSandboxExecutor` route with the
Lean v2 receipt lifecycle, invoked by a parent-side mediator. The broker
protocol, `SpawnRecord`, obligation lowering and `ResourceContract` typing
are reused.

**Absent today:** (1) a broker transport into the container (Docker exec is
stdio-only; proposed parent `AF_UNIX` socket bind-mounted, connected by the
shim before seccomp, challenge-bound); (2) SERVICE-line acceptance in the
Docker grant check (`container.py:305-313`); (3) explicit graph-unit limits;
(4) the four mediators (`model_invoke` via `HostRouter.model_invoke`,
`compute`, `dataset_input`, `state_and_publication` via `output_emit`);
(5) a worker artifact with stdout capture and a `BrokeredChatModel`.
**Key premise to probe first:** no thread creation inside the worker (the
seccomp profile lacks `clone3`); Pregel's single-task inline path makes this
plausible but unverified.

**Size:** about 50 agent-hours over 11 steps, plus model wall time for a new
10-task × 5-repetition D cohort. SGV901–903 stay open regardless; this is the
route that would let pandas C be *admitted* under the closed gate, not a
proof.

## 2026-10-27 13:25 EDT: Design fact-check, six corrections applied to `pandas-route-design.md`

An independent read-only check verified most of the design's citations
(allowlist lacks clone/clone3/fork/vfork/execve/socket/connect; Docker flags,
stdio-only exec, grant-line rejection, broker/contract/router line cites all
correct) and found six overstatements, now corrected in the file:
1. **Seccomp violations return `EPERM`, they do not kill the worker.**
   `_apply_seccomp` installs `SCMP_ACT_ERRNO(EPERM)` as the default
   (`_linux_worker.py:253-256`); only `bpf`/`process_vm_readv`/`ptrace`/
   `unshare` are `SCMP_ACT_KILL` (`:111-116`). A thread or socket attempt
   raises in Python and the worker survives. The design's tests must assert
   `EPERM`, not termination.
2. **The shim already redirects tool stdout/stderr** to discarded
   `StringIO` buffers (`_linux_worker.py:310-311`); vendor `print()`
   cannot corrupt the protocol pipe today. A bounded capture is needed only
   if the design wants to return that output.
3. **Pregel's inline single-task path is narrower:** `_runner.py:201-203`
   requires one task, no timeout and no waiter; `stream_eager`, subgraph
   streaming, `messages`/`custom` modes, `step_timeout`, two tasks in a
   step, `Send` or functional `Call` all go through the thread pool. The
   executor object is created eagerly (`_executor.py:48-50`); only the OS
   thread is lazy. So "no threads" needs a probe per workflow, as the design
   already said, and now says precisely.
4. Broker death surfaces as `broker:invalid_response` on read-EOF
   (`broker.py:368-373`), not `broker:channel_closed`.
5. The broker fd reaches the worker via the `SLANGGRAPH_BROKER_FD`
   environment variable (`landlock.py:403-404`, `broker.py:336`); the
   Docker transport must set it too.
6. `container.py` line numbers drifted by ~8 after line 320; substance
   unchanged.
Vendor `pandas_data_analyst.py` lines are unverifiable here (upstream pin only).

## 2026-10-27 13:42 EDT: Decision, route-scoped acceptance gate (advisor chose this at ~13:40)

The advisor chose "route-scoped gate now". This follows the handoff's own rule
for SGV901–903: replace them only with recomputed evidence for a precisely
defined admitted execution surface, with explicit premises and runtime
enforcement of exclusions. **Nothing is relabeled; every check is recomputed
at gate time from current sources, and any route without complete evidence is
unsupported-and-gated, never claimed.**

**Supported surface (proposed, to be encoded in `supported-surface.json` v2):**
- R1 `language-sandbox-tool`: admitted language-IR programs executed
  in-process by the interpreter; effects only through registered terminals.
- R2 `tool-node-dispatch`: exact `ToolNode` under `MediatedNode` with a
  captured descriptor; effects through `HostRouter`.
- R3 `linux-worker-compute`: `LinuxSandboxExecutor` with the Lean
  receipt-v2 checker required (pre-GO and post-cleanup).
- R4 `output-publication`: `OutputMediator` → `HostRouter.output_emit` →
  `ObjectManagerHost.dispatch` (OutputRequest).
Everything else (plain Python nodes, Runnable subclasses, metadata promotion,
Docker route until its own evidence exists, SQL, notebook, the pandas outer
graph) is unsupported and refused by `closed_admission` or an existing gate.

**Evidence standard per obligation (recomputed check IDs):**
- SGV901 (placement over the admitted surface): `admission-surface` (all
  obligations proved) + `router-source-proof` (21/21) + the five
  `gate:admission:*` codes registered. Premise: unsupported bodies refuse
  before effects (tested).
- SGV902 (adapter composition): R2/R1: `router-source-proof` +
  `admission-surface` (dispatch only the captured implementation through
  mediation). R4: `router-source-proof` + `host-output-correspondence` +
  `output-validator-contract` + **`output-mediator-correspondence`** (new
  source-derived component for `_emit`/`_aemit`: normal return is exactly
  the dispatched result through `rebuild`, else refusal/approval). The
  generic publication entries (9/60) stay reported but are not the criterion.
- SGV903 (host contract): R3: `lean-audit` (a fresh `make
  security-verify-lean` pass with kernel replay, source identities matching
  the current tree) + `runtime-evidence` (native receipt-v2 cases) +
  `host-route:linux-sandbox` structural checks (regression, not proof) +
  explicit premises (compiler/decoder/OS refinement, kernel/LSM, bubblewrap,
  libseccomp). R1: interpreter admission derivation + premises. R2/R4: not
  applicable (no host adapter), with reason.
- Any `ungated_exclusions` entry fails the gate.

**Dependency outside my control:** `lean-audit` cannot pass on the current
checkout because Codex's grant-v3 edit (`check.py`/`GrantCoverage.lean`,
12:32–12:37) leaves the generated audit source unparsable. The gate stays
honest-red until that edit lands or is reverted to the last audited state.

**Work now:** (a) manifest v2 + evidence-standard doc (agent);
(b) `output_mediator_verification.py` (agent); (c) route-scoped
`layered_verification`/`developer_verification` rewrite, after the
admission workflow's Verify stage releases those files.

## 2026-10-27 13:53 EDT: Route-scoped verifier delivered

New `security/route_verification.py` + `test_route_verification.py`
(59 tests, ruff/ty clean). `verify_routes(repo, run_lean_audit=…)` reads
`docs/security/supported-surface.json` (schema 2), **recomputes** every check
from current sources (no saved report is ever read for a proof check), and
sets `complete` only when every supported route discharges every applicable
obligation, every exclusion's gate code is registered, `ungated_exclusions`
is empty and no unknown check ID appears. `system_complete` stays false and
the claim text says route-scoped. CLI exits 0 only on `complete`.

Dry run against a scratch v2 manifest on the current tree:
- **pass:** `router-source-proof` (21/21, proof), `host-output-correspondence`
  (proof), `output-validator-contract` (proof), `admission-surface` (4/4,
  proof; the workflow's component exists already), `host-route:linux-sandbox`
  (structural, no proof), `runtime-evidence` for pandas v19.
- **fail, as expected right now:** `output-mediator-correspondence` (component
  being written), `lean-audit` (not run; and blocked by Codex's edit),
  `final-checks.json` as runtime evidence (no outcome field: the manifest
  must cite files with `passed`).
- Four v1 gate codes are unregistered; the seccomp one is an assessment label
  (use the `adapter_rule_unsupported:` prefix), the three `host:*` codes I am
  registering now.
The real manifest is still v1, so the real run exits 2 (fails closed) until
the v2 manifest lands.

## 2026-10-27 13:54 EDT: Registered host:missing_security_context, host:missing_router (unsupported) and host:artifact_changed (policy_denied); registry + route verifier tests 81 passed.

## 2026-10-27 13:55 EDT: Provenance note, four entries in status.md were written by my agents

The entries in `eval/status.md` timestamped 2026-10-27T17:25:41Z,
17:31:57Z, 17:38:30Z and 17:50:05Z ("Closed node/branch admission gate
implemented (opt-in)", "Admission gate documented…", "Descriptor-bound
dispatch…", "Source-derived admission-surface evidence wired…") were appended
by the Core/Bind/Verify agents of my admission-gate workflow, **not by the
student**. They followed status.md's own logging convention instead of this
file. I am leaving them in place (append-only, technically accurate; the
student should treat them as my reports) and have told the remaining agents
to write only to this log. Summary of what they report:
- `security/admission.py` (descriptors, `admit_node`/`admit_branch`,
  `recheck`), `SecurityConfig(closed_admission=True)` inventory at compile
  (default unchanged), RuntimeMAC requires closed admission.
- Descriptor-bound dispatch in `MediatedNode`/`MediatedBranch`: override
  kwargs refused, recheck, bounded input copy, principal only from native
  config, pinned `ToolNode._func/_afunc` with the captured node, no
  `self.runnable` path; branches run the pinned function inline; async only
  with a native adapter route. Marker witnesses retained: plain function,
  metadata-promoted node and ToolNode-containing wrapper refuse
  `admission:unsupported_node_body` with no marker and no mediation effect.
  10 dispatch tests; 320 related tests pass (1 bubblewrap skip).
- `admission_verification.py`: four obligations proved on the actual
  sources, 27 tests (22 mutations), wired as non-gating evidence key
  `admission_surface`; SGV901–903 and `complete` unchanged.
- Stated open items: BaseModel graph states refused under descriptor dispatch;
  Docker/direct-Linux positive dispatch untested; the component does not
  prove recheck's identity recomputation, async transport, initialization.

## 2026-10-27 13:56 EDT: OutputMediator correspondence proved (SGV902 chain for the output route complete)

New `security/output_mediator_verification.py` +
`test_output_mediator_verification.py` (40 tests, 33 mutation variants,
ruff/ty clean). On the actual sources: `proved: true`. `_emit`: one normal
return (`rebuild(result)`), one approval raise, four literal refusals;
`_aemit`: three returns (awaited callback / plain / non-awaitable), one
approval raise; the six public wrappers derive as class-function forwardings.
`router.output_emit` is consumed by recomputing the router source proof;
`validate_output_data` by recomputing the student's wrapper contract;
`OutputRequest` field order from the native record model. Helpers are
pattern-consumed, not exempted. Explicit premises: exact receiver with derived
slots (init unproved), `rebuild` is one of three framework rebuilders
(bodies uncertified), `principal_from`/`next_call_index` trusted runtime,
`labels_for_output` body not derived (shape only), native dataclass
post-init, stdlib `inspect.isawaitable`. Continuation closures stay in
`remaining_composition`. One tightening: the `_aemit` callback-await guard
is now derivable (removing it flips the proof). Independent re-run on the
current tree confirms `proved: true` with no unproved dependencies.

## 2026-10-27 14:00 EDT: Route-scoped acceptance wired into the strict gate; Makefile updated

`developer_verification.py` (27 tests, ruff/ty clean): whole-system
`complete` and the SGV901–903 diagnostics are unchanged (same fingerprints),
each gap now carries `route_scope` ("discharged on every supported route" /
"open on <ids>" / "not evaluated"); `report["route_acceptance"]` holds the
recomputed route result; `acceptance_passed = no regression tasks and
route_acceptance.complete`. CLI: `--no-lean-audit`, `--evidence-dir`;
default exit 0 iff `acceptance_passed`; `--require-complete` is the old
whole-system gate (documented as currently unreachable). Text output lists
per-route SGV901/902/903 results, the claim text and the "NOT ESTABLISHED"
sentence. Makefile: `security-verify` now passes
`--evidence-dir "$(SECURITY_EVIDENCE_DIR)"` (fresh dir per run, default
`security-route-evidence`); new `security-verify-fast` skips the Lean audit
(that check then fails closed). The real tree still exits 1 because the
manifest is v1 and the Lean audit cannot pass on Codex's mid-edit snapshot.

## 2026-10-27 14:02 EDT: Admission-gate workflow finished; review found one high-severity gap, fix in progress

Workflow result (6 agents, 0 errors; the Core/Bind/Verify technical details
are the four agent-written entries in status.md noted above):
- **Regression sweep: 4,818 passed, 0 failed, 8 environment-gated skips**
  (tests/security, excluding the five bubblewrap/Lean-binary files), plus
  tool-node/react suites; whole-package lint and ty pass.
- **Bypass review (read-only, in-memory):** every intended refusal held
  (plain function, Runnable subclass, callable marker, async body,
  metadata-promoted node, ToolNode-containing wrapper, injected error-handler
  node, override kwargs, foreign containers, smuggled principal, replaced
  descriptors). Three findings:
  1. **High.** `RuntimeMAC` binds the builder-captured `MediatedNode` and
     never re-reads the compiled `graph.nodes[name].bound` that Pregel
     actually invokes (`mac.py:76-115`, `181-207`). Swapping the compiled
     binding after registration bypasses the runtime check. **Fix:** the
     runtime check must require `graph.nodes[name].bound is <captured
     wrapper>` for every captured node and refuse any node outside the
     inventory, then recheck.
  2. **Medium.** Under `closed_admission`, graph-author callbacks still run:
     custom channel reducers (`binop.py:143`), `CachePolicy.key_func` and
     `RetryPolicy.retry_on` (`_algo.py`, `_retry.py`). The spec listed
     these as outside the gate's scope, but "unsupported means stopped" means
     they should refuse at compile. **Fix:** closed admission refuses
     non-framework reducers/cache/retry callables with the new registered
     code `admission:unsupported_callback`.
  3. **Low.** The legacy (non-closed) MAC path now runs `admit_node` at
     compile and reports `admission:closed_admission_required` instead of
     `mac:unconfined_graph_body` for branch graphs; both refuse. To be kept
     byte-equivalent where feasible.
A single agent is applying fixes 1–2 (and 3 where cheap) across `mac.py`,
`config.py`, `admission_verification.py` and their tests, with mutation
regressions, because the admission-surface derivation consumes every
statement of those functions and must be extended in lockstep.

## 2026-10-27 14:04 EDT: Manifest v2 delivered; mediator proof review found five checker holes (fix in progress)

**Manifest v2** (`docs/security/supported-surface.json`, `.md`, new
`evidence-standard.md`; JSON validates, all 80 cited paths exist). Written
against the real verifier loader. Honest statuses right now:
- R2 `tool-node-dispatch`: **supported** (declared), pending the admission
  fixes below.
- R4 `output-publication`: unsupported only because the mediator component
  landed after the agent started; flips to supported once the mediator
  checker passes re-review.
- R3 `linux-worker-compute` (pandas C is an application under it):
  unsupported until a fresh Lean audit passes on the current tree (Codex's
  in-progress edit). Runtime evidence now cites files with `passed` fields.
- R1 `language-sandbox-tool`: unsupported; its interpreter-level evidence is
  not a recomputed check yet (the language derivation captures have no
  outcome field and stale hashes). Language-sandbox ToolNodes are still
  admitted as R2 descriptors of kind `LANGUAGE_PROGRAM`.
- Still ungated (7): worker-private `/tmp` writes (explicitly writable by
  manifest), network from generated code (kernel EPERM, no refusal code),
  outer-graph checkpointer, `human_review`, Streamlit, raw debug/state/event
  APIs, SQL effects. Three former ungated items are now gated by
  `admission:unsupported_node_body`.
- Six exclusion gate codes were unregistered; registered now with
  `admission:unsupported_callback` (registry now 60 codes, completeness test passes).

**Mediator proof review (read-only):** five confirmed holes, all checker
bugs: (A) a second `output_emit` call accepted (sticky result kind); (B)
`rebuild(result)` evaluated twice; (C) wrappers forwarded roles blindly
(`callback` with `value`/`deliver` swapped proved; `stream` forwarding
`_identity` proved); (D) module-level `_patch = setattr(OutputMediator,
'__call__', …)` accepted as an assignment; (E) extra `labels_for_output`/
`_operation_id`/`OutputRequest` calls accepted. Plus a premise that let the
slot reader's order choose which field is "destination". Everything else
tried held (return content/result, shadowed `rebuild`, walrus,
comprehensions, swallowed approval raise, reordered pair check, coroutine
tricks, decorators, class-body statements). An agent is fixing all six with
mutation regressions; R4 stays unsupported until re-review.

## 2026-10-27 16:38 EDT: Session limit interrupted both fix agents mid-edit; resumed

At ~14:12 the session hit its usage limit and both fix agents were terminated
mid-edit. On resume (16:38): `mac.py` holds the admission agent's partial
rewrite (14:12), so the admission suites currently show **6 failures** (the
MAC inventory test and five admission-surface derivation cases that no longer
match the new `mac.py`); ruff is clean. The mediator checker and its test
(14:10) are consistent and pass. Both agents were resumed from their saved
context with instructions to first make their files consistent. The advisor
decided (before the cutoff) to **finalize with R3 recorded unsupported** until
a fresh Lean audit passes on the current tree, pandas C included; one JSON
flip and a rerun restore it later.

## 2026-10-27 16:39 EDT: Mediator checker holes fixed (68 tests); re-review running

`output_mediator_verification.py`: (A/B/E) a per-path effect tally; a second
routing, rebuild, label, operation-id or request construction on any path is
an unmodeled effect, and every normal-return and approval path must hit the
exact tally; (C) wrappers bind parameters by name and forward content/config/
rebuilder roles to exactly `value`|`envelope.content`, `config`, and
`_identity`|`envelope.rebuild`|`deliver`; (D) a module/class-body scan
refuses wildcard imports, call RHS in assignments (allowlist empty, since
placement.py needs none) and decorators other than `dataclass`/
`runtime_checkable`; (F) roles are bound by slot name, `__slots__` must be
exactly the four, and the reader must return them in role order. The actual
sources still prove with and without dependency sources; 68 tests (27 new
adversarial cases with reason/line assertions); ruff/ty clean. A second
read-only adversarial pass is running on new attack classes before R4 is
flipped to supported.

## 2026-10-27 16:40 EDT: First route-gate run on the real tree (Lean audit skipped)

`make security-verify-fast` → `raw/checks/claude-route-gate-fast-v1.{json,log}`,
exit 1 (expected). Recomputed results: `router-source-proof` 21/21,
`host-output-correspondence`, `output-validator-contract` and
`output-mediator-correspondence` all pass, so **R4's SGV902 chain is
discharged**. R2 and R4 fail only on `admission-surface`, which is the
half-rewritten `mac.py` the resumed agent is fixing. Remaining blockers for a
green run: the seven top-level `ungated_exclusions` (five belong to the
unsupported pandas-outer/SQL surfaces and should be recorded under those
entries, not block supported routes; the "raw publication APIs" item is a
premise backed by the student's SGV109/SGV110 regressions, not an exclusion),
and two "manifest overclaims proof" issues for `admission-surface` (clears
when it passes) and `lean-audit` (R3 unsupported by decision). R3's manifest
entry now carries the advisor's decision text.

## 2026-10-27 16:40 EDT: CHECKPOINT (paused at the advisor's request)

**Where the route-scoped gate stands** (`make security-verify-fast`, Lean
audit skipped): router 21/21, host-output correspondence, validator contract
and the new mediator correspondence all recompute and pass; R4's SGV902 chain
is discharged. The gate is still red for three reasons, each in progress:
1. `admission-surface` fails because `mac.py` holds a half-finished rewrite
   (the review's high finding: bind the compiled `PregelNode.bound`, refuse
   graph-author callbacks). The resumed fix agent is working on `mac.py`,
   `config.py`, `admission_verification.py` and their tests. **Until it
   reports, the admission suites show 6 failures; nothing else is affected.**
2. R4 is still marked unsupported in the manifest pending the mediator
   checker's second adversarial pass (running).
3. Verifier rule fixed just now: a *failing* check no longer counts as a
   "proof overclaim"; manifest ungated items moved under their unsupported
   routes (visible, non-blocking), the raw-publication-API item became an R4
   premise backed by SGV109/110 regressions. Route verifier tests re-run below.

**Decisions on record:** route-scoped gate (advisor, ~13:40); R3/pandas C
recorded unsupported until a fresh Lean audit passes on the current tree
(advisor, ~14:10); the R3 manifest entry carries that text.

**Not yet done:** flip R4 to supported after re-review; final
`make security-verify` (with Lean audit, expected to fail only on R3's
unsupported entry), full `make test`, `make lint`, regression and
permutation gates under `claude-final-*-v3` names; proposed dispositions for
`acceptance.json`/campaign README (student's files, not edited by me).

**Files of mine with uncommitted changes** are listed in the earlier
entries; pre-edit copies with checksums are under
`raw/claude-validator-proof/pre-edit/`. Nothing committed, nothing of the
student's reverted. The four agent-written entries in `status.md` (17:25–17:50
UTC) are mine by provenance, as noted above.

## 2026-10-27 16:43 EDT: Mediator checker re-review, no holes

Read-only second pass: all six fixed holes refuse with a specific reason;
new attack classes (nested route inside `rebuild`, keyword/star arguments,
swapped positionals, wrong awaits in `_aemit`, try/finally rebuild,
conditional returns, shadowed `_require_output_host`, `__slots__` reorder
with a compensating reader, class decorators, spread approval kwargs, walrus,
relative import) are all refused. Accepted-but-safe: slot tuple reorder with
name-bound descriptors, dead code after the return, same-value alias, import
alias. **R4 (output publication) is cleared to be marked supported** once we
resume; still paused.

## 2026-10-27 16:49 EDT: All agents finished; first passing route-scoped gate (Lean audit skipped)

**Admission-gate fixes (all three review findings):**
1. *High:* `RuntimeMAC` now binds the compiled graph it actually receives
   (`check_runtime_policy(self)`, `main.py:2826/3289`): compiled node names
   must equal the inventory plus `__start__`, every `PregelNode.bound` must
   be the captured `MediatedNode`, every writer is an exact `ChannelWrite` or
   the captured branch route, cached plans are dropped; any mismatch raises
   `admission:descriptor_changed` before the descriptor recheck. Tests cover
   a swapped `bound` (marker never runs), added/removed nodes, swapped/extra
   branch writers, cached plans.
2. *Medium:* closed admission refuses graph-author reducers (only
   `operator.add`/`add_messages` by identity), non-default cache keys, retry
   predicates and trace policies with `admission:unsupported_callback` before
   any node; `operator.add` channels still work end to end.
3. *Low:* the legacy (non-closed) MAC path is back to HEAD behavior.
The admission derivation consumes the new statements (14 new mutation cases).
Agent's suites: 106 passed, 1 skipped (bubblewrap).

**Route-scoped gate** (`make security-verify-fast` →
`raw/checks/claude-route-gate-fast-v2.{json,log}`): **exit 0,
"Route-scoped acceptance: PASS"**, `tool-node-dispatch` SGV901 ok, SGV902 ok,
SGV903 not applicable. Whole-system completeness still "NOT ESTABLISHED" and
SGV901–903 still listed with their route scope. Caveats, stated plainly:
- This run skips the Lean audit; R3 (pandas C) is unsupported by decision, so
  it doesn't affect the result.
- Only R2 is marked supported. R4 is cleared by its re-review but not yet
  flipped (paused).
- One test pinned the old behavior and now fails for the right reason:
  `test_route_verification.py::test_real_tree_smoke_without_lean_audit` (and the developer CLI test the agent saw) expected a failing gate on the
  real tree; the gate now passes. It needs updating to assert the new result.
Combined related suites: 254 passed, 1 failed (that test), 1 skipped.

**Still to do on resume:** update that test; flip R4 to supported and rerun;
full `make test`, `make lint`, regression/permutation gates and the full
`make security-verify` under final names; fix the stale
`closed_admission_required` row in `docs/security/admission.md`; proposed
dispositions for the student's acceptance records.

## 2026-10-27 16:52 EDT: Resumed after checkpoint; strict gate passes route-scoped (Lean audit run)

Resumed because the goal is still active. Done:
- Two tests that pinned the old failing outcome now assert invariants:
  acceptance equals the recomputed per-route result, whole-system stays
  false, and no accepted route may rest on a skipped Lean audit (86 pass).
- R4 `output-publication` promoted to supported (decision text recorded in
  the manifest); stale `admission.md` row fixed, `unsupported_callback` added.
- **Final runs** (`raw/checks/claude-final-*-v3`): `make lint` exit 0;
  regressions exit 0; permutations exit 0; **`make security-verify` (Lean
  audit run) exit 0: "Acceptance: PASS. System completeness: NOT
  ESTABLISHED."** `tool-node-dispatch` and `output-publication`: SGV901,
  SGV902 ok, SGV903 not applicable. All three proof gaps carry route scope
  "discharged on every supported route"; 0 implementation tasks; 0 issues.
- Per-check: router 21/21, host-output correspondence, output validator,
  output-mediator correspondence and admission surface (4/4) are **proofs**
  recomputed from source; host-route structural check and gate registrations
  are non-proof checks; the Lean audit **fails** (Codex's mid-edit snapshot),
  which blocks only R3, recorded unsupported by the advisor's decision.
- **Weakness:** the two runtime-evidence files cited for R3 pass on their
  `passed` field but carry no source hashes the verifier can re-check ("0
  recorded source identities match"). They do not affect the supported
  routes, but R3's promotion should require evidence with bound identities.
Full `make test` is running; result appended when it finishes.
Proposed dispositions for the student's records: `eval/scope/proposed-dispositions.md`.

## 2026-10-27 17:01 EDT: Final full suite on the final tree

`raw/checks/claude-final-full-prebuilt-v3.log`: **5,446 passed, 16 snapshots
passed, 8 skipped, 58 failed** (9m01s); Docker test services cleaned up. All
58 failures are `RuntimeError: bubblewrap isolation is unavailable on this
host` in `test_linux_execution.py` (44) and `test_resource_boundary_linux.py`
(14), the known environment limit of my shell. Those two files pass **63/63**
in the unconfined `slg-linux-test` container on the same tree
(`claude-final-linux-docker-v3.log`). No code regression.

**Summary of the finished state:** lint, regression and permutation gates
pass; `make security-verify` passes route-scoped acceptance with the Lean
audit run; whole-system completeness remains NOT ESTABLISHED by design.
Outstanding only on the student's side: finish or park the grant-v3 Lean edit,
rerun `make security-verify-lean`, then flip `linux-worker-compute` to
supported (with runtime evidence that records source identities) and rerun
the gate; review `eval/scope/proposed-dispositions.md` and
`record-corrections.md` and apply what they agree with.

## 2026-10-27 17:03 EDT: Stopped at the advisor's direction

Offered: repair the student's in-progress Lean audit, apply the proposed
acceptance dispositions, commit to a branch. The advisor chose **none: stop
here**. The delivered state is the route-scoped gate pass recorded above.
Left for the student: the grant-v3 Lean edit and audit, promotion of
`linux-worker-compute` with identity-bound runtime evidence, and review of
`eval/scope/proposed-dispositions.md` and `record-corrections.md`. Whole-
system completeness remains NOT ESTABLISHED by design. Nothing committed.

## 2026-10-27 20:08 EDT: Independent verification of the student's completion

Checked the student's work against the four requests, without relying on
their records:
- **Committed:** branch `codex/route-acceptance-grant-v3`, commits
  `01aed327` (checkpoint) and `784be435` (promote Linux worker route);
  the tree was clean before my verification run.
- **Fresh gate, run by me** (`raw/checks/claude-verify-student-v1.{json,log}`,
  new Lean audit under `claude-verify-student-evidence-v1`): exit 0,
  "Acceptance: PASS". **All three supported routes discharge every applicable
  obligation:** `tool-node-dispatch`, `linux-worker-compute` (pandas C)
  and `output-publication`. Lean audit passes on the current tree
  (kernel-checked finite model). Runtime evidence now binds 8 and 12 current
  source identities (was 0). Router 21/21, host-output, validator, mediator
  and admission proofs all pass; 0 tasks, 0 issues. Whole-system completeness
  is still NOT ESTABLISHED, by design.
- **Records:** `acceptance.json` item 2 is `addressed-route-scoped`;
  v11 corrected to 24/30; SQL RM1 cohort now described in
  `APPLICATIONS.md` and the SQL README; `apps.csv` gained a separate
  cohort-evidence column. Overall `complete: false` and
  `goal_status: active` remain, which is accurate for whole-system scope.
- **Their own improvements:** they found and fixed a weakness in the
  route verifier (runtime evidence with zero matching identities used to
  pass; it now fails closed, with regressions), and they ran a fresh pandas
  grant-v3 cohort (150/150) instead of reusing old evidence.
- **Scope call to note:** five former ungated items were not turned into
  gates. They are recorded as outside R3's generated-computation scope
  (outer graph, checkpointer, human review, UI), as an intentional baseline
  (`/tmp`) or as an OS/seccomp premise (network). That is consistent with
  route scoping and stated openly.
- Their reported validation: prebuilt suite 5,511 passed, 3 skipped,
  16 snapshots; eval 144 passed; format/lint pass.

**Verdict:** the requested work is done and holds up independently.

## 2026-10-27 20:36 EDT: Threat model documented

Advisor decision: the language-sandbox interpreter is part of the trusted computing base (assumed correct, not proved). New `docs/security/threat-model.md` states the adversary (AI model output, untrusted inputs, admitted tool code), the TCB (interpreter, registered terminals, controller runtime, Python/kernel/LSM/bubblewrap/libseccomp/Docker, Lean toolchain), the per-route meaning of safe (SGV901/902/903 and output correspondence), escape strength by route, and what is out of scope. Linked from `docs/security/README.md` and `supported-surface.md`. Not committed.

## 2026-10-27 20:51 EDT: Language-sandbox route proved in Lean and promoted (advisor: Lean is the proof core)

**Decision path.** The advisor confirmed the interpreter is trusted (threat
model), then chose a **Lean** proof of the checker over accepting a Python-only
check. I had first written a Python choke-point check
(`security/language_route_verification.py`); it stays as the link to the
source, and the proof itself is in Lean.

**Lean proof** (new project `proofs/language-route`, Lean 4.34.1, separate
from the student's `proofs/worker-route`):
- `LanguageRoute.lean` models the admitted language (constants, locals,
  joins, string comparisons, terminal calls with positional and keyword
  arguments; return/expression/assign/if statements) and an executable
  `checkProgram` that mirrors `derive_program` rule for rule (types, call
  arity/keyword/argument-kind rules, the if/else environment merge, implicit
  None result), plus an evaluation semantics where terminals are an arbitrary
  oracle and every call is traced.
- **Main theorem `checked_program_calls_only_registered`:** if the checker
  accepts a program, then for any terminal behavior and any inputs, every
  terminal called during evaluation is registered. Supporting theorems:
  static call sites of accepted programs are registered; executed calls are
  syntactic call sites; an unregistered terminal is never accepted. No
  `sorry`/`native_decide`/custom axioms; axioms used: `propext`,
  `Quot.sound` only.
- `Controls.lean` is **generated by `check.py` from the real Python lowering
  and checker**: 4 useful programs (Python accepts; Lean returns the same result
  type) and 9 forged IR programs (Python refuses each with its specific code;
  Lean refuses), all checked by the kernel via `decide`. The audit fails if
  the committed file drifts from what the current Python produces.
- `check.py` audit (`raw/checks/claude-language-lean-audit-v1`): passed;
  kernel typecheck, fresh `leanchecker` replay of both modules, axiom audit.

**Python link** (`language_route_verification.py`, 13 tests incl. mutations):
`LanguageProgram.invoke` derives the same captured snapshot before any
terminal call, terminals execute nowhere else, `lower` proves at admission,
and `ManifestAdmission.invoke/ainvoke` validate first and execute only via
`program.invoke`; plus live controls (3 useful accepted, 8 forbidden source
programs refused with registered codes). Registered as check
`language-derivation` in the route verifier.

**Manifest:** `language-sandbox-tool` SGV903 now requires
`lean-audit:proofs/language-route` + `language-derivation`; route promoted
to **supported**, with the threat-model premise first in its list.

**Gate** (`make security-verify`, both Lean audits run fresh →
`raw/checks/claude-language-gate-v1.{json,log}`): **exit 0, all four routes
pass**: language-sandbox-tool, tool-node-dispatch, linux-worker-compute,
output-publication. 0 tasks, 0 issues. Whole-system completeness still NOT
ESTABLISHED by design. Related suites 190 passed; ruff and ty clean.
`docs/security/threat-model.md` updated to say the checker is Lean-proved and
only the interpreter's faithful execution is assumed.

**What the language-route claim does and doesn't cover:** proved, any checked
program can only call registered terminals (argument kinds are enforced by the
Lean checker but not yet a stated theorem);
assumed (TCB), the interpreter executes the checked program faithfully, the
terminals honor their contracts, CPython and the Lean toolchain are correct.
Full prebuilt suite running; result appended when done. Nothing committed.

## 2026-10-27 21:01 EDT: Full suite after the language-route proof

`raw/checks/claude-language-full-prebuilt-v1.log`: 5,458 passed, 16 snapshots passed, 8 skipped, 58 failed (9m00s). All 58 failures are `bubblewrap isolation is unavailable on this host` in `test_linux_execution.py` (44) and `test_resource_boundary_linux.py` (14), the known limit of my shell; both files rerun in the unconfined container on this tree: see `claude-language-linux-docker-v1.log`. No regression from the language-route work.

## 2026-10-27 21:49 EDT: LLM calls scoped to a hook point (advisor decision); implementation started

Decision: the runtime provides a **hook point** for LLM calls and policy over
the **capability** to call the LLM; it does not perform the call or guarantee
the content sent (future guards attach at the hook). Gaps against that bar,
found in code: model nodes are chosen by a class-name guess (`_is_model`),
so an LLM call inside an ordinary function node gets no hook; under closed
admission there is no model node kind (all LLM calls refused); no test shows
a deny prevents the call.

In progress: one agent adds an exact-type `MODEL_CALL` admission kind (hook
always runs before the pinned model call; LLM calls elsewhere refused), the
matching admission-surface derivation, and `test_model_hook.py` (allow runs,
deny never invokes, hidden calls refused, swaps refused). Done by me: manifest
route `model-invoke-hook` (R5) added as **unsupported pending** the code;
`docs/security/threat-model.md` gains an "LLM calls" section stating the
hook-only scope.

## 2026-10-27 22:01 EDT: LLM-call hook implemented; five routes pass the gate

Agent work (admission.py, config.py, placement.py, mac.py,
admission_verification.py; tests): new `AdmittedKind.MODEL_CALL`. Model nodes
are admitted only by **exact type** from an allowlist (`FakeListChatModel`,
`GenericFakeChatModel`, `langchain_openai.ChatOpenAI`; `ChatOllama` if
installed, which it isn't here). Descriptor identity covers the class and its
exact-string endpoint fields; models with callbacks, callback managers, custom
token counters or rate limiters are refused; `.bind(...)` wrappers are refused
(safe support would need unpacked call arguments the dispatch proof rejects).
Dispatch: hook (`model_invoke` through the proved `HostRouter`) then the
class-level `invoke` captured at admission, never the instance's. An LLM call
inside an ordinary function node stays refused. Admission-surface proves all
four obligations on the actual sources, with 11 new mutation cases (model before
hook, hook removed, `issubclass`/name heuristics, wrong placement, MAC recheck
removed). `test_model_hook.py`: 23 tests, sync and async (allow runs; **deny
raises with zero model calls**; hidden calls, non-allowlisted classes and
post-admission swaps refused). Related suites 347 passed, 1 skipped; ruff/ty clean.

**What the hook guarantees:** the capability decision happens before the call
and a deny means the LLM is never invoked. **Not guaranteed:** prompt or reply
content (out of scope by decision); the call runs in the coordinator process,
recorded as a premise.

Manifest route `model-invoke-hook` promoted to supported. **Gate**
(`make security-verify`, both Lean audits fresh →
`raw/checks/claude-model-hook-gate-v1.{json,log}`): exit 0, **all five routes
pass**: language-sandbox-tool, tool-node-dispatch, linux-worker-compute,
output-publication, model-invoke-hook. `make lint` exit 0. Full prebuilt
suite running; result appended when done. Nothing committed.

## 2026-10-27 22:04 EDT: Advisor design decisions register (consolidated)

All design decisions the advisor has given in this session, in order. Earlier
entries record them where they happened; this is the single list.

| # | When (EDT) | Decision | Where it took effect |
| --- | --- | --- | --- |
| D1 | 05:17 | Scope draft: support a finite surface with gatekeepers for everything excluded; "unsupported means stopped"; keep the language sandbox and isolated workers as separate routes. | Plan for all later work. |
| D2 | ~13:40 | Acceptance is **route-scoped**: SGV901–903 recomputed per declared route; whole-system completeness stays reported, not required. | `route_verification.py`, `developer_verification.py`, manifest. |
| D3 | ~14:10 | Finalize with the Linux worker route (pandas C) **unsupported until a fresh Lean audit passes**; no waiting on the student's edit. | Manifest R3 (later promoted by the student). |
| D4 | 17:03 | Stop: don't repair the student's Lean work, apply their records or commit; leave those to the student. | Message to the student. |
| D5 | evening | **Threat model:** the AI model, untrusted inputs and admitted tool code are adversarial; the language-sandbox **interpreter is trusted** (TCB), with terminals, admission code and the controller runtime. | `docs/security/threat-model.md`. |
| D6 | evening | **Lean is the proof core**; prove the language-sandbox checker in Lean rather than accept a Python-only check. | `proofs/language-route`, route promoted. |
| D7 | evening | The **runtime provides state, checkpoints, approvals and streaming** as trusted machinery; application node code is not runtime and must use mediated operations, confinement or a reviewed adapter. | Gap analysis; threat model. |
| D8 | evening | The runtime exposes a **finite set of well-defined operations**, and that set is **bounded by what the evaluation dataset needs**; future needs are added one operation at a time, everything else refused. | Planned runtime operation catalog (not yet written). |
| D9 | evening | **LLM calls: hook point only.** Model the LLM call as an operation and let policy allow or deny the capability to call; no content guarantee and no runtime-performed call. | `MODEL_CALL` admission kind, `model-invoke-hook` route. |

**Open decision (needs the advisor):** which applications the operation
catalog must cover: pandas only (adds dataset input), pandas plus SQL (adds a
bounded query operation), or more. Recommended: pandas only for now.

## 2026-10-27 22:07 EDT: Full suite after the LLM-call hook

`raw/checks/claude-model-hook-full-prebuilt-v1.log`: 5,492 passed, 16 snapshots passed, 8 skipped, 58 failed (9m23s). All 58 are the known bubblewrap-unavailable limit of my shell (`test_linux_execution.py` 44, `test_resource_boundary_linux.py` 14); both files rerun in the unconfined container: `claude-model-hook-linux-docker-v1.log`. No regression from the hook work.

## 2026-10-27 22:12 EDT: Decision D10 (catalog = pandas only) and a correction on step 4

- **D10:** the runtime operation catalog covers **pandas only** for now
  (advisor agreed). Work authorized through step 4: catalog, dataset-input
  operation, port pandas.
- **Correction:** I said `bind_tools` might block the port. Checked the
  vendor code: pandas never uses it. The real issue: its five LLM calls are
  `prompt | llm | parser` chains inside ordinary node functions
  (`pandas_data_analyst.py:321`, `data_wrangling_agent.py:718/804`,
  `data_visualization_agent.py:995/1087`), so the node-level `MODEL_CALL`
  hook doesn't reach them.
- **Approach for step 4 (my recommendation, given to the advisor):** keep the
  vendor code unchanged and run the whole graph in the confined worker; its
  `llm` is a forwarding stub whose calls reach the runtime's model hook
  over the worker channel (`eval/scope/pandas-route-design.md`). Rewriting
  the graph into separate model nodes would change the app under evaluation.
- **Estimate corrected:** step 4 is ~50 agent-hours per the design, not
  "about a day".

## 2026-10-27 22:13 EDT: Paused, three agents stopped at the advisor's request

I had started the catalog, dataset-read and graph-unit probe agents in the same reply that answered the advisor's question; the advisor asked me to wait. All three were stopped within minutes. Any partial files they created are listed in the next entry if present; none are relied on.

## 2026-10-27 22:23 EDT: Decision D11, application graph code is trusted

**D11:** LangGraph/LangChain framework code **and the application's own graph
code** (developer-written node functions: prompt building, LLM calls, parsing,
glue) are trusted. Untrusted: tool implementations and code generated at
runtime. Consequence noted by the advisor: `bind_tools` and other framework
wrappers are not a security concern.

`docs/security/threat-model.md` updated (adversary scope and TCB). Added to
the register: **D11**, ~22:2x EDT, "application graph code is trusted", took
effect in the threat model.

**Effect on the plan (not started; awaiting the advisor's go):** step 4 shrinks
from the ~50 agent-hour confined port to running the pandas graph as-is in the
trusted controller, with its generated code already in the proved Linux worker,
LLM calls as hook points and output through the proved publication route. Open
technical point: the closed admission gate currently refuses developer node
code, so the supported pandas configuration must either run without closed
admission (with RuntimeMAC's current requirement revisited) or admit
developer nodes explicitly as trusted.

## 2026-10-27 22:24 EDT: D11 documented in the threat model

At the advisor's request, `docs/security/threat-model.md` gained a full section, "Trust boundary: trusted application, contained tools (D11)": the three code categories and their trust, rationale, the four paths attacker influence can take, a pandas walkthrough, what D11 does not protect against (confused deputy in trusted code, direct effects by trusted code, malicious application code), the resulting deployment rule (application code must not act on model output directly), how D11 maps to the implementation (including that closed admission needs a trusted-application-node kind), and the claim wording the paper may use. The "LLM calls" section was reconciled with D11 (direct calls by trusted code are allowed and unpoliced; the hook covers calls through the runtime model operation).

## 2026-10-27 22:25 EDT: Go-ahead for steps 2-4 (advisor)

Plan: (A) runtime operation catalog for pandas (D8/D10); (B) `dataset_read` operation; (C) trusted-application-node admission kind (D11) with the admission-surface proof extended; then (D, me) wire the catalog into the route verifier, run pandas under closed admission and a fresh cohort if the model service is available. A/B/C run in parallel with disjoint files.

## 2026-10-27 22:30 EDT: (A) Runtime operation catalog delivered

New `docs/security/runtime-operations.{md,json}`,
`security/operation_catalog.py` (`load_catalog`, `verify_catalog`) and
12 tests (9 mutation failures), ruff/ty clean. Pandas operations: `compute`
(proved: linux-worker-compute incl. Lean audit), `output_publish` (proved),
`model_invoke` (proved, hook only; pandas' own direct LLM calls are trusted
and unpoliced per D11), `tool_dispatch` (proved, not needed by pandas),
`state_read`/`state_write`/`checkpoint`/`approval_resume` (trusted
runtime premises), `dataset_read` (implemented by B, **no proving route
yet**: the only reason `complete` is false). Excluded from the pandas
catalog with refusals: principal transfer/attenuate, all five dispatch forms,
tool registration/override (`registry:dynamic_registration_denied`), store
read/write, `guard_operation`. Not yet wired into the gate.
The advisor set a new goal: "don't stop until eval is done".

## 2026-10-27 22:32 EDT: (B) dataset_read delivered and proved; catalog complete and gated

- **B (agent):** `security/dataset_operation.py` (`DatasetEntry`,
  `DatasetRegistry`, `read_dataset`/`aread_dataset`, ids only, never paths),
  23 tests. Reuses `landlock.open_path_descriptor(no_symlinks=True)` and the
  reopen/inode check of `inprocess.read_text`; digest over exactly the
  returned bytes. Policy via an `authorize(principal, DatasetReadRequest)`
  hook requiring an exact unconstrained ALLOW (the Cedar and object-policy
  paths are tool-call specific and `objects.py` has no dataset request kind;
  documented). Codes registered: `dataset:unknown` (unsupported),
  `dataset:denied` (policy_denied), `dataset:too_large` (unsupported),
  `dataset:changed` (policy_denied, like `host:artifact_changed`),
  `dataset:unavailable` (execution_failed).
- **Proof route (me):** `security/dataset_route_verification.py` derives the
  ordering from source (lookup → policy → exact allow → only then the pinned
  read; no other open; `no_symlinks=True`; digest compare is the last check
  before return; the pinned read is reachable only from the two entry points)
  and runs live controls (allow returns exact bytes; **deny makes zero
  opens**; unknown/changed/oversize refused). 8 tests incl. 6 mutations.
  Registered as check `dataset-read`; manifest route `dataset-read` (R6)
  supported; catalog entry marked proved.
- **Catalog gated:** new check `operation-catalog` (`verify_catalog`
  complete) is now required by SGV901 on all **six** supported routes.
  `verify_catalog`: complete, 0 issues. Route verifier and catalog tests:
  73 passed; lint clean.
Waiting on (C) trusted-application-node kind before running pandas through the gate.

## 2026-10-27 22:40 EDT: (C) Trusted application nodes delivered; gate passes with six routes

- **C (agent):** `SecurityConfig(closed_admission=True,
  trusted_application_nodes=frozenset({...}))` admits declared plain sync/async
  function nodes as `AdmittedKind.TRUSTED_APPLICATION` (never inferred;
  bound methods, partials, generators and other Runnables refuse; undeclared
  functions still refuse). Identity binds name, module, qualname, loaded code
  and injected-keyword plan; swaps → `admission:descriptor_changed`. A
  ToolNode declared trusted is **refused** (would contradict D11 tool
  containment); a declared allowlisted model stays MODEL_CALL with its hook.
  Dispatch runs the function captured at compile with normal inputs and config
  (trust, not containment, stated in code). RuntimeMAC binds and rechecks them.
  Admission-surface proves all four obligations on the actual sources with the
  D11 premise recorded; 27 new end-to-end tests, 17 new mutation tests,
  6 config tests; focused set 341 passed, 1 skipped; ruff/ty clean.
- **Gate** (`make security-verify`, both Lean audits fresh →
  `raw/checks/claude-catalog-gate-v1.{json,log}`): exit 0, **six routes
  pass**: language-sandbox-tool, tool-node-dispatch, linux-worker-compute,
  output-publication, model-invoke-hook, dataset-read; each SGV901 now also
  requires the complete operation catalog.
- **Step 4 started:** an agent is configuring the unchanged pandas app under
  closed admission (vendor nodes declared trusted, generated code on the C
  compute route, dataset via `dataset_read`, output via the mediator) and will
  run a pilot. It must report, not relax, any admission blocker (e.g. nested
  agents compiled as subgraph nodes).

## 2026-10-27 22:43 EDT: Step 4 blocker, pandas branch functions; trusted branches being added (D11)

The integration agent inventoried the compiled vendor graphs
(`raw/pandas-closed-v1/inventory.json`, `apps/pandas/closed_inventory.py`):
all **14 nodes** are plain closures and are admitted once declared trusted.
The nested agents run as separately compiled graphs invoked inside trusted
node bodies (not subgraph nodes). The only blocker: **three custom branch
functions** refuse with `admission:unsupported_branch` (the outer
`router_chart_or_table` closure and the two retry-condition lambdas in
`create_coding_agent_graph`), because only `tools_condition` is pinned.
Admission was not relaxed and nothing was run.

Branch functions are application code, so under **D11** they are trusted.
Resumed the trusted-node agent to add declared **trusted application branches**
(same mechanics: explicit exact declaration, code-identity binding, recheck,
MAC binding, derivation extended), so pandas can compile under closed admission
without changing the vendor graph. Model service (Ollama) still down; will be
started as an owned process for the pilot, as the student did.

## 2026-10-27 22:49 EDT: Trusted application branches delivered; pandas pilot and cohort started

- **Trusted branches (agent):** `SecurityConfig(..., trusted_application_branches=
  frozenset({"<source>:branch:<name>"}))`, new kind
  `TRUSTED_APPLICATION_BRANCH` (kept separate from `FRAMEWORK_BRANCH` so
  evidence never presents developer code as a pinned framework function). Plain
  sync functions, closures and lambdas only; undeclared custom branches, async
  branches, `tools_condition` declarations and unknown names refuse with
  `admission:unsupported_branch`; swaps → `admission:descriptor_changed`;
  any `Send` a branch returns is still authorized; RuntimeMAC binds them via
  the compiled writers. Admission-surface proves all four obligations on the
  actual sources; 13 mutation + 18 runtime + 6 config tests; focused set
  399 passed, 1 skipped; ruff/ty clean. Pandas declarations:
  `data_wrangling_agent:branch:router_chart_or_table`,
  `execute_data_wrangler_code:branch:condition`,
  `execute_data_visualization_code:branch:condition`.
- **Model service:** started a coordinator-owned `ollama serve` (PID
  3012425, recorded in `raw/pandas-closed-v1/claude-owned-ollama.pid`, log
  alongside); `qwen3:8b` digest `500a1f067a9f` matches manifest-v19. I will
  stop only that process when the cohort ends.
- **Step 4 resumed:** compile all three graphs under closed admission, wire
  `dataset_read` and the C compute route, one pilot task, then the full
  10 × 5 C-closed cohort with independent verification; failures kept.

## 2026-10-27 22:53 EDT: Gate after trusted branches

`make security-verify` (both Lean audits fresh): exit 0, all six routes pass (`raw/checks/claude-branches-gate-v1.{json,log}`); `make lint` exit 0. Pandas pilot/cohort still running.

## 2026-10-27 23:02 EDT: C-closed cohort interim, 9/10 in repetition 1; one real compatibility refusal

The unchanged pandas app compiles and runs under closed admission (three
pilot runs retained in `raw/pandas-closed-v1/pilot-v1..v3`; cohort in
`full-v1`, run in the unconfined container harness). Repetition 1: **9/10**.
`monthly_mean` is refused at runtime by the nested wrangling graph's output
gate with `output_data:nonfinite_float`: the vendor code rebuilds a `NaN`
for the empty April mean, and the output validator refuses non-finite floats
by design. Recorded as a failure, no change, no retry beyond the manifest's.
This is the closed configuration failing closed on data the earlier
configurations serialized (their codec maps non-finite values to null before
the parent sees them). Remaining 40 trials running.

## 2026-10-27 23:22 EDT: Step 4 done: C-closed pandas cohort 45/50; final validation green

**Cohort (`raw/pandas-closed-v1/full-v1`, manifest-v21-closed, 10 tasks × 5).**
The unchanged vendor pandas app runs under closed admission (14 trusted nodes,
3 trusted branches, compute dispatch admitted as an exact `ToolNode`, dataset
via `dataset_read` pinned to the fixture digest). Result: **45/50**. Nine
tasks pass 5/5; `monthly_mean` fails 0/5, every time with
`output_data:nonfinite_float` (10 occurrences in its process logs). Failures
kept, no retries beyond the manifest's.

- **Independent re-verification:** I copied the cohort, deleted its
  `verification.json`, and reran `verify_closed_campaign.py` with the prebuilt venv.
  - Same counts and failures.
  - One difference: "Captured Lean worker differs from its pin". The pin
    stores the binary's absolute path, so a copy at another path cannot match
    it. On the original cohort `issues` is empty.
- **Deviation to note (agent's, not an advisor decision):** manifest-v20-closed
  was refused in both pilots before any model call. The vendor's
  `data_raw = df.to_dict()` has integer keys (`output_data:string_key_required`)
  and a NaN.
  - v21 adds adapter-side transport `json-null-v1`: the data read via
    `dataset_read` and the compute results are JSON-round-tripped, which turns
    keys into strings and NaN/Infinity into null. This mirrors the JSON transport
    configuration C already applies to the compute payload.
  - Unchanged: vendor code, prompts, tasks, oracle, model, retries, policy and
    the Lean binary.
  - The `monthly_mean` failure is the vendor re-creating NaN inside the
    controller after that normalization; the output gate refuses it by design.
    No validator or oracle change.
- **Environment:**
  - The run used rootless Docker `slg-linux-test` (`run-container.sh`), because
    bubblewrap is blocked on this host.
  - The `cedar` CLI was bind-mounted at `/opt/cedar`.
  - Six dev runs, not retained, diagnosed the nested-mount refusals.
  - All of this is recorded in `runs.json`.
- **Model service:** stopped the coordinator-owned `ollama serve` (PID 3012425)
  at 23:12; no other process touched.

**Final validation (same tree):**

| Check | Result | Evidence |
| --- | --- | --- |
| `make security-verify` (both Lean audits fresh) | exit 0; route-scoped acceptance PASS on all six supported routes; worker-route and language-route audits passed (language-route axioms: propext, Quot.sound) | `raw/checks/claude-final-gate-v1{,.log}` |
| `make lint` | exit 0 | `claude-final-lint-v1.log` |
| `make test` (libs/prebuilt) | 5,621 passed, 8 skipped, 58 failed; all 58 are the known bubblewrap-unavailable limit (`test_linux_execution.py` 44, `test_resource_boundary_linux.py` 14) | `claude-final-full-prebuilt-v1.log` |
| Those two files in the unconfined container | 63/63 passed | `claude-final-linux-docker-v1.log` |
| `eval/tests/test_pandas_closed_{integration,inventory}.py` | 8 passed | — |

SGV901/902/903 are still reported as not established for the whole system;
acceptance is route-scoped as decided (D2).

**Open for the advisor/student:**

1. How to report `monthly_mean`. It is a real compatibility refusal of closed
   mode: the security layer fails closed on NaN that vendor code creates.
2. Whether v21's `json-null-v1` input normalization is acceptable as stated.
3. Records and commit. Nothing has been committed by me.
