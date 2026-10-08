# Verification evidence and remaining work

This records the completed native-record and immediate-generator stabilization.
It is test evidence, not a non-bypassability certificate. The agreed acceptance
criteria remain in
[README.md](README.md).

## Current evidence

Run library commands from `libs/prebuilt`.

| Command/check | Result | Scope |
| --- | --- | --- |
| `uv run pytest tests/security/test_*verification*.py -q` | 2,409 passed | Transfer-engine, router, publication, report and finite-matrix regressions. |
| `uv run pytest tests/security/test_verification_named_tuple*.py -q` | 846 passed | New native-record tests; included in the verifier-suite count above. |
| `uv run pytest tests/security/test_verification_generators.py -q` | 624 passed | Immediate native consumers, ordering, per-iteration authority and explicitly unsupported deferred/async behavior; included above. |
| Generator, descriptor and normalizer focused tests | 652 passed | Includes the normalization regression and property tests. |
| `make security-verify-permutations` | 28,800 source cases and 2,444 runtime cases passed | Declared finite dimensions only; included as matrix tests in the verifier suite. |
| `make format` and `make lint` | Passed | Prebuilt formatting, lint and configured type checks. |
| Strict mypy on `verification.py`, `boundary_verification.py`, `permutation_verification.py` with `--explicit-package-bases --follow-imports=silent` | Passed | These three verifier modules only. |
| `make test` | 3,362 passed | Final full library run after stabilization, including benchmarks, snapshots and integration fixtures; 2,428 warnings, no failures. |
| `make security-verify` | Failed acceptance | Four implementation findings and three verifier-owned proof gaps remain. |

The saved [matrix report](permutation-report.json) includes checker, transfer
engine and router source hashes. The refreshed
[developer report](../../docs/security/developer-verification-report.json)
includes the source-bound findings and proof obligations. Regenerate reports
after changing the analyzed sources.

The previous full library test run exposed a failing existing
`tests/security/test_normalizers_fuzz.py::test_domain_fuzz` property: domain
normalization was not always idempotent. Stabilization now rejects host
whitespace both before and after IDNA conversion, canonicalizes Unicode label
separators, and accepts canonical IP-address results as inputs. Focused property
tests and explicit hostname/IDNA/IPv4/IPv6 regressions pass. This fix is separate
from the four remaining static implementation findings.

## What changed

The verifier follows native field-only `NamedTuple` construction, projections,
replacement, dictionary copies and publication. It preserves nested alias
dependencies and rejects publication of a different record under an earlier
record's grant. Explicit effect contracts take precedence over native data
models. Wrapping a capability in a record cannot make it inert data.

The field matrix exhausts 2 sync/async modes × 24 value permutations ×
4 projection forms × 4 field positions. Tests also use the six actual
checkpoint/store record declarations. Unsupported layouts and generated API
surfaces remain explicitly unproved. Candidate source is never executed.

The intermediate generator failures were test expectations that incorrectly
equated an entry with no reachable effects with whole-spec coverage. Those
expectations now match the existing report contract. The generator model is
limited to immediately consumed finite native `tuple`/`list` expressions; it
does not eagerly analyze arbitrary deferred generators as if their bodies ran
at creation time.

## Completion remains open

The router's 21 entry proofs still pass, but the adapter publication analysis
still has 38 unresolved entries out of 49 and an unclosed source model.
Locally verified entry results do not discharge that source closure or prove
adapter composition.

Remaining verifier obligations are complete enforcement placement, adapter
composition (including authenticated receiver and escalation-result handling),
and binding host confinement and worker-channel identity/lifetime to the exact
request. Host MAC correctness remains an assumption. These gaps belong to the
verifier maintainer; the system report continues to reject completeness.

## Maturity assessment

The supported analysis and finite regression matrices are usable by developers:
they have repeatable commands, source-bound reports, negative controls and
explicit limits. The stabilization point does not expand the supported scope
to make the system gate pass. It leaves the missing proofs visible.

For the original purpose of certifying complete non-bypassability, the verifier
is not yet mature. Closing the remaining placement, adapter and host-integration
proofs is the next substantive milestone. Additional permutation counts alone
would not change that assessment.
