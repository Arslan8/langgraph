# Verifier scope: non-bypassability

This records the agreed verification assignment. Use it when choosing work,
interpreting results, and deciding whether the verifier is complete. Changes to
this scope require an explicit agreement; do not expand it implicitly.

## Objective

Establish that every in-scope protected effect requires authorization for the
actual caller, resource, operation, and call context, through an enforcement
point that can refuse the effect. No applicable API or alternate path may avoid
that enforcement.

The assignment is **non-bypassability**, not general framework correctness or
functionality. Demonstrating that permitted operations work is not a completion
requirement for this assignment. A system that refuses everything may satisfy
the safety property; that alone does not demonstrate correct mediation of the
framework's other reachable paths.

## Trust boundary

- Assume host MAC/LSM correctness. Do not re-prove kernel enforcement or analyze
  arbitrary tool internals merely because they execute under host confinement.
- Verify the integration needed to rely on that assumption: protected host
  effects enter the required confinement, and untrusted code cannot acquire
  coordinator capabilities or avoid the boundary.
- Framework objects still require framework mediation. Cross-tool calls,
  state/store access, checkpoint operations, model access, and publication must
  use the applicable refusing boundary with authenticated identity and correctly
  bound authority. Host MAC does not automatically discharge those obligations.
- State all other trusted contracts explicitly. Do not silently promote an
  unverified adapter or helper into the trusted base to obtain a passing result.

## Verification strategy

1. **Deny-all effect testing.** Apply denial at every applicable policy decision,
   exercise discovered entry points, and observe concrete protected effects.
   No protected effect may occur. Include relevant sync/async, inherited,
   callback, nested-call, resume, and exceptional paths. A test that fails to
   reach its intended entry point, or whose effect observation fails, provides
   no passing evidence.
2. **Complete entry-to-effect analysis.** Independently inventory protected
   effects and entry points, then establish that every reachable in-scope path
   crosses the applicable refusing enforcement point before the effect. Follow
   helpers, aliases, and alternate paths. Unsupported or dynamically unresolved
   behavior remains unproved. A finite test matrix is not this proof.
3. **Exact authorization bindings.** Establish that the authorization used is
   for the actual principal, resource, operation, and call/approval context.
   Deny-all alone cannot distinguish a correct check from a check against the
   wrong identity or resource, because both deny. Value transformations belong
   in this analysis when needed to keep an effect within its authorization;
   general data-processing correctness does not.

Use source-only positive and negative fixtures to validate the verifier's
supported models. These test the verifier's reasoning, not whether the product
implements every desired feature. General allow-policy functionality tests may
provide supporting evidence but must not become a new acceptance obligation.

## Completion criteria

A non-bypassability claim requires all three strategy obligations to be
discharged for the claimed source/runtime configuration and stated trust model.
Record the evidence and its source/version binding. Claims must not exceed the
scope of that evidence.

None of the following establishes completion:

- Passing a deny-all test matrix without complete path coverage.
- Passing router checks without establishing that applicable effects reach it.
- Finding no currently recognized bad source patterns.
- Counting every discovered declaration, reporting a larger inventory, or
  treating a historical denominator as exhaustive coverage.
- Making the command fail on every unresolved case. Failing closed prevents
  false acceptance; it does not discharge the missing proof.
- Waiving unsupported analysis or treating test errors as successful denial.

## Ownership and working discipline

The verifier's missing models, incomplete coverage, and false acceptance are the
verifier maintainer's responsibility. Keep those separate from implementation
violations demonstrated by evidence. Do not ask implementation authors to fix
unspecified requirements merely because an earlier checker missed them.

Do not present the script as ready to establish this guarantee before these
criteria are met. Report progress by obligations actually discharged, remaining
proof gaps, and demonstrated violations—not by additional rules, passing test
counts, or additional unresolved entries alone. Keep the overall objective open
while required proof remains incomplete.

## Reproducible permutation tests

From `libs/prebuilt`, run:

```sh
make security-verify-permutations
```

This writes `security-permutation-report.json`. CI runs the same command and
uploads the report. `suite_passed` describes this finite test suite;
`system_complete` remains false. A passing matrix is supporting evidence for the
objective above, not a substitute for its outstanding placement/composition proof.
The [recorded matrix result](permutation-report.json) binds its results to checker,
transfer-engine and router source hashes; rerun the command after source changes.

The matrix exhausts these declared dimensions:

| Matrix | Dimensions | Cases |
| --- | --- | ---: |
| Source bindings and guards | 2 sync/async modes × 5 source forms × 5 guard forms × 24 authorization argument permutations × 24 effect argument permutations | 28,800 |
| Root denial | 5 root APIs × 4 non-ALLOW verdicts | 20 |
| Cross-tool denial | 2 APIs × every combination of the 5 verdicts at 4 authorization stages, excluding the all-ALLOW combination | 1,248 |
| Framework-object denial | 14 APIs × 21 request variants × 4 non-ALLOW verdicts | 1,176 |

Source forms cover direct calls, callable aliases, helper functions, inheritance,
and branches. Guard forms cover ALLOW-only enforcement, an absent guard, an
inverted guard, enforcement on only one branch, and rejection of DENY alone
while other non-ALLOW verdicts remain possible. These source candidates are
never executed. Negative cases must produce a diagnosed violation; an unresolved
analysis is a failed matrix case, not a successful rejection test.

The four binding positions represent principal, resource, operation, and call.
The original API arguments are fixed independently of their use in the candidate
body. Matching authorization/effect arguments is insufficient when both have
been changed from the original API arguments. The shared verifier now enforces
this through `VerificationSpec.entry_bindings`; the router uses that mechanism
as well as its additional protocol checks. New APIs without entry contracts and
stale contracts naming absent APIs prevent verification.

Runtime cases execute the admitted router against in-memory policy and terminal
effect observers. They check the reached authorization stages, original argument
identities, zero terminal effects, and the distinction between refusal and an
escalation result. An unexpected exception, missing stage, unclassified router
API, duplicate case ID, or failed admission cannot count as a pass. The observers
are tested separately to ensure that effects would be recorded.

The request variants cover every current state-operation and dispatch-kind enum
value, static/dynamic registration with and without override, two model names,
and user/callback output destinations. The test harness discovers enum values
and checks the actual router API inventory. These axes do not exhaust arbitrary
input values, generated Python behavior, concurrency schedules, or adapter/host
integration. Those remain governed by the completion criteria above.

## Native record transfer checks

The shared transfer engine also models native field-only `NamedTuple` records
used by store operations and checkpoint tuples. Run its source-only tests with:

```sh
uv run pytest tests/security/test_verification_named_tuple*.py
```

Run that command from `libs/prebuilt`. The binding matrix covers 2 sync/async
modes × 24 field-value permutations × 4 projections (attribute, index, mapping,
unpacking) × 4 selected field positions, for 768 cases. Additional tests cover
actual repository record
declarations, constructor arguments and defaults, replacement, nested aliases,
immutable writes, exception continuations and unsupported layouts. Candidate
source fixtures are never executed; a separate native-contract check uses only
benign data and no protected effects.
Publication cases require the exact authorized record and reject wrapped
capabilities. Explicit effect contracts remain authoritative even when the
method otherwise has a native data-operation model.

These checks establish transfer behavior for supported records. They do not
prove the complete store/checkpoint adapters, authorize backing reads, or supply
the missing router receiver/result and host-integration proofs.
See [validation evidence and remaining work](validation.md) for the recorded
commands, results and remaining proof obligations.

## Stable developer scope

Immediate synchronous generator expressions consumed by native `tuple` or
`list` are covered by `test_verification_generators.py`. The finite matrix has
2 entry modes × 2 consumers × 3 callable forms × 3 iterable shapes × 4 lengths
× 4 authorization patterns, for 576 combinations. Additional cases cover scope,
evaluation order, nested aliases, exceptions and unsupported consumers.

The checker distinguishes an entry with no reachable effects from evidence of
whole-spec coverage. Existing gate semantics remain unchanged: absent dispatch
obligations do not produce a complete effect-coverage report. No effect is
executed merely to satisfy that requirement.

This is a tested developer regression tool with explicit analysis limits. It
is not yet a complete security-assurance verifier. Stabilization should preserve
passing supported cases and actionable failures; further completeness work must
discharge the documented placement/composition obligations rather than substitute
larger test counts for those proofs.
