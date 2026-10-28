# Lean contribution on this campaign

The selected protocol is `worker-route-grant-v3`, pinned to Lean 4.34.1 and
runtime executable SHA-256
`6097be9b7b84639959c7a0b9de31c79f23486e9f01bf1b6de575dfab25c7cb08`.
The four model/bridge files contain 1,817 lines. The five central properties are:

| Theorem | Statement |
|---|---|
| `success_iff_exact_route` | `decideRoute binding events = true ↔ events = successfulEvents binding` |
| `useful_route_succeeds` | `decideRoute binding (successfulEvents binding) = true` |
| `go_requires_matching_authorized_activation` | `(step (run binding events) (.go observed)).phase = .running ↔ events = [.authorize binding true, .activate binding true true] ∧ observed = binding` |
| `cancellation_anywhere_refuses` | `decideRoute binding (before ++ .cancel :: after) = false` |
| `unknown_cleanup_anywhere_refuses` | `decideRoute binding (before ++ .cleanup false :: after) = false` |

They assume truthful and complete principal/session/call/tool, artifact, grant,
plan, nonce, host/context, process identity, authorization, activation, result,
cleanup, and event-order facts. They prove the captured finite decision model,
not Python/compiler/OS refinement. The implementation checks the grant before
native activation, at the worker boundary, and around the exact lifecycle
trace; integration tests and receipts provide the separate implementation
connection.

Reproduce with:

```sh
libs/prebuilt/.venv/bin/python proofs/worker-route/check.py \
  --output /absolute/new/worker-audit
```

On this campaign host, driver tests completed in 0.186 s and source hygiene
passed, but the proof build/replay could not start because `lake` was absent.
Accordingly `raw/lean-check/report.json` sets `passed`, `model_proved`, kernel
checking, and all refinement flags to false. Earlier matching retained evidence
measured 26.961 s for model build, 5.336 s for generated-kernel checking, and
83.468 s for fresh kernel replay; it is historical context, not pooled with this
failed reproduction.

No bug is credited to modeling alone because no prospective origin log exists.
Modeling made binding, activation, cancellation, cleanup, and evidence coverage
obligations explicit. Runtime tests found the callback-await regression,
Pandas routing/Period/serialization issues, container lifetime cases, and the
non-finite-output refusals.
