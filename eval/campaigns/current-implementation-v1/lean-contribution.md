# Lean contribution on the frozen revision

The current selected worker protocol is `worker-route-grant-v3`. The captured
audit uses Lean 4.34.1 and the exact executable SHA-256
`6097be9b7b84639959c7a0b9de31c79f23486e9f01bf1b6de575dfab25c7cb08`.
The four model files contain 1,817 lines: 346 lifecycle, 512 receipt coverage,
517 grant coverage, and 442 executable/JSON bridge lines. The audit selects 72
security-relevant results from 89 public theorems.

## Five central properties

| Theorem | Exact statement | What it contributes |
| --- | --- | --- |
| `success_iff_exact_route` | `decideRoute binding events = true ↔ events = successfulEvents binding` | Complete lifecycle characterization: success is not a deny-all result and no alternative event order succeeds. |
| `useful_route_succeeds` | `decideRoute binding (successfulEvents binding) = true` | Constructive useful path for every binding. |
| `go_requires_matching_authorized_activation` | `(step (run binding events) (.go observed)).phase = .running ↔ events = [.authorize binding true, .activate binding true true] ∧ observed = binding` | `GO` follows matching positive authorization and confirmed supported activation. |
| `cancellation_anywhere_refuses` | `decideRoute binding (before ++ .cancel :: after) = false` | Cancellation cannot be completed into success. |
| `unknown_cleanup_anywhere_refuses` | `decideRoute binding (before ++ .cleanup false :: after) = false` | Unconfirmed cleanup cannot be completed into success. |

All statements are universally quantified over the finite model's `Binding` and
event lists. The model assumes that the supplied principal/session/call/tool,
artifact, grant, plan, nonce, host/context and process identity strings are
truthful; that event order is complete; and that Boolean authorization,
activation, result, and cleanup facts mean what the Python/runtime bridge says
they mean. It does not prove those facts.

## Reproduction and checking cost

From revision `bdb0cb9d467e426354ad8beba20407374947ce51`:

```sh
python3 proofs/worker-route/check.py --output /absolute/new/worker-audit
```

The retained matching audit recorded:

- build of `WorkerRoute`, `ReceiptCoverage`, `GrantCoverage`, and `workerRoute`:
  26.960856 s;
- generated `KernelAudit.lean` checking: 5.336394 s;
- five deliberately malformed semantic controls: all rejected;
- fresh `leanchecker` replay: 83.467999 s.

The replay is Lean's own kernel, not an independent verifier implementation.
The audit report explicitly sets `runtime_refinement_proved`,
`source_refinement_proved`, `decoder_refinement_proved`,
`compiler_refinement_proved`, and `os_refinement_proved` to false, and therefore
sets `system_complete` to false. The proof establishes the decision core, while
native integration tests and retained runtime receipts establish separate
implementation evidence.

## Connection to implementation

The pinned executable consumes the generated complete grant/obligation/receipt
records plus the lifecycle trace. The selected Linux route checks the grant
before native attestation, checks it again at the worker boundary, and asks the
Lean executable to accept the exact pre-`GO` and post-cleanup traces. The
deployment connection is the pinned binary digest plus integration tests; it is
not a proved compiler or Python refinement.

## Modeling findings versus testing findings

No issue is labeled “found by modeling alone” because the project did not retain
a prospective issue-origin log that would support that attribution. Modeling
made the omitted cases explicit—full binding comparison, unsupported or
unconfirmed activation, cancellation, unconfirmed cleanup, unique obligation
ownership, and no-extra/no-missing evidence—and the negative type controls show
that malformed model variants are rejected. Runtime and application testing,
not the Lean model, exposed the concrete callback-await regression, Pandas
request-routing/Period/serialization failures, container lifetime cases, and
non-finite output refusals. This distinction avoids retroactively crediting the
proof for bugs first observed in tests.

Retained source: `proofs/worker-route/`. Retained matching audit:
`eval/campaigns/remediation-v2/raw/checks/codex-grant-lean-audit-v2/report.json`.
