# SLP-to-Cedar authorization model

## Current implementation: completeness is false

The production translator has a reproducible counterexample. Given this valid
SLP manifest and `permit(principal, action, resource);` in both owner and caller
partitions, with no MAC forbids, the `alice` principal gets the required grant
while the valid `josé` principal fails with `cedar:evaluation:owner-call`:

```slp
class record {
  operations read
  object item
  normalizer identity
  attrs owner
  enforced_by broker
}
tool lookup {
  runs broker
  record read public need
  returns normal
}
```

The failure is caused by `_cedar`, which uses
`json.dumps(value, ensure_ascii=True)[1:-1]`. It translates `josé` into
`jos\u00e9`. Cedar requires Unicode escapes with braces, such as `\u{e9}`, or
literal Unicode. `_call_request`, `_request`, and generated permits all reuse
this escaping function. The installed real Cedar CLI (4.13.0) rejects the emitted
request. Replaying it with only the principal literal changed to raw Unicode
returns `ALLOW`, using the identical policy and entity data.

This refutes completeness of the current implementation over accepted principal
identities. It does not refute soundness: this example fails closed. The Python
implementation has deliberately been left unchanged so the counterexample
remains reproducible.

From the repository root, with `lean` and `lake` on PATH:

```sh
(cd proofs/slp-cedar && lake build)
libs/prebuilt/.venv/bin/python proofs/slp-cedar/reproduce_translation_failure.py \
  --output /tmp/slp-cedar-counterexample
```

The script imports the repository's actual implementation, parses the SLP,
checks that `Principal` accepts the identity, invokes the actual authorizer and
Cedar executable, saves/replays the generated bundle, and captures the emitted
escape into a Lean theorem. An explicit `--lean /path/to/lean` is also supported.

`TranslationFailure.lean` proves that the offending string is not a Cedar string
body, even under a grammar that relaxes digit/control-character restrictions.
`ProductionCapture.lean` is a checked capture of the production output; the
reproducer regenerates and checks it from the live implementation. The saved
`counterexample-evidence.json` records the implementation's SHA-256, Cedar
version, outputs, and Lean result.

**Evidence boundary:** Lean proves the lexical rejection of the captured value.
The capture from Python, correspondence of the grammar to Cedar, and execution
of the real authorizer are reproducible external evidence, not a formalization
of Python or the Cedar executable. This is a concrete implementation
counterexample, not a claimed universal implementation proof.

The earlier model below makes operational success a prerequisite. That
prerequisite excludes this bug; its theorem therefore cannot establish
translation correctness.

## Earlier conditional authorization model

This project proves soundness and completeness of a **formal model of the v2
authorization boundary**, after successful SLP expansion. It does **not** yet
prove soundness and completeness of the executable Python-to-Cedar translation.
The older `CedarPolicyBackend` in `security/cedar.py` is outside this project.

Run with the pinned Lean 4 toolchain (no third-party Lean dependencies):

```sh
cd proofs/slp-cedar
lake build
```

`SlpCedar.lean` prints the axioms of its main theorems. Successful verification
must contain no `sorryAx`; standard Lean logical axioms are expected.

## Statement

`slp_to_cedar_sound_complete` proves, for every finite list of expanded lines,
every policy predicate, every call gate, and every support predicate:

```text
authorize(gates, translatedQueries, support, candidates) = some(output)
  if and only if
ValidGrant(gates, sourceAuthorization, support, candidates, output)
```

`ValidGrant` requires all of the following:

- Successful call gates and operational prerequisites.
- Every `need` line is authorized.
- Output is exactly the authorized subsequence of input, preserving order and
  duplicates. Denied `want` lines are omitted.
- A nonempty candidate list has a nonempty output.
- Every retained line has enforcement support or an accepted waiver.

The forward implication is soundness; the reverse implication is completeness
**relative to these prerequisites**. An unavailable Cedar executable cannot be
complete relative to a specification that only asks whether a policy permits.
`no_amplification` separately proves every returned line was requested and allowed.

The source line decision is owner permission AND (principal OR share permission)
AND no matching mandatory forbid. The target model evaluates the owner,
envelope, and ephemeral candidate-plus-MAC queries separately. It uses Cedar's
[default-deny and forbid-overrides rules](https://docs.cedarpolicy.com/auth/authorization.html).
It abstracts successful individual policy evaluation as Boolean predicates;
it does not implement Cedar expressions or import Cedar's formal semantics.

## Correspondence to the implementation

All Python references below are in
[`object_policy.py`](../../libs/prebuilt/langgraph/prebuilt/security/object_policy.py).

| Lean definition | Python boundary |
| --- | --- |
| Input `List Line` | Result of `SecurityManifest.expand` |
| `query` | `_request`, before string/JSON encoding |
| `candidatePermit` | `_candidate_permit` |
| `targetAllows` | Owner, envelope, and MAC checks in `CedarObjectAuthorizer.authorize` |
| `collect` | The per-line loop's retain/skip/raise behavior |
| `callGate` | Owner call, MAC call, and empty-manifest principal call checks |
| `authorize` | Collection, nonempty-access check, and support/waiver checks |

Resource-free calls use the principal call gate alone, not a principal/share
union, matching the implementation. `operational` abstracts successful policy
validation, executable availability, and error-free subprocess evaluation for
the queries actually executed. Diagnostics and failure reasons are not modeled.

## Remaining proof obligations

The table is a manual correspondence, not a verified refinement relation.
Before calling this an end-to-end proof, establish:

1. **SLP expansion:** parsing, operation selection, bindings, normalization,
   labels, and `need`/`want` classification faithfully implement the intended
   source language. User-defined normalizers and label providers are trusted
   today; this proof starts after they finish successfully.
2. **Request/entity encoding:** abstract natural-number identities preserve the
   equality of actual principal, tool, class, action, and resource identities.
   Prove string escaping, schema construction, attributes, entity lookup, and
   JSON decoding preserve those values. Python hashes resource identities with
   SHA-256; unconditional injectivity over arbitrary resources cannot be assumed
   as a mathematical theorem. An end-to-end statement needs an explicit
   collision-free condition on the concrete candidate set or a different encoding.
3. **Cedar evaluation:** connect the Boolean predicates to actual policy semantics,
   including errors, entity attributes, missing entities, and policy partition
   restrictions. The principal/share disjunction assumes permit-only partitions;
   the MAC predicate assumes a forbid-only partition.
4. **Python refinement:** prove that Python control flow implements `authorize`,
   including errors and short-circuit behavior. Differential tests could catch
   drift but would not discharge this universal obligation.
5. **Runtime enforcement:** separately verify that execution respects the issued
   grant. This authorization theorem says nothing about trusted tool behavior,
   OS enforcement, resource races, or dispatch.

## Why query scope matters

`_candidate_permit` constrains principal and action but leaves resource
unconstrained. The final Lean example proves that such a permit also matches a
different resource with the same principal and action. Consequently, equivalence
of the generated policy to the SLP manifest for **all arbitrary requests** is
false. The proved statement is restricted to generated per-line queries and the
grant collector, as used by the authorizer. Do not reuse those ephemeral permits
as a standalone resource ceiling.
