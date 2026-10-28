# Lean receipt composition: implemented contract and remaining work

**Status: the v2 decision core and synchronous production integration are
implemented.** The captured model audit passed. This document records the
implemented portion of the earlier plan and the obligations still open; it is
not a complete SGV901–903 acceptance claim.

## Production connection

`EnforcementCoordinator` still performs its actual `_assigned_adapter_plans`,
`_validate_activation` and `validate_receipt` checks. After those checks, the
selected `LinuxSandboxExecutor` projects the negotiated plan and receipt into
native bounded data and asks the compiled Lean core to permit `GO`. The same
session asks it to permit success only after a valid result and confirmed
cleanup. A certificate is mandatory at both gates.

[ReceiptCoverage.lean](../../proofs/worker-route/ReceiptCoverage.lean) formalizes
finite coverage and identity predicates from that contract. It does not replace
signature verification, freshness/expiry, grant-obligation generation,
`RuleEnforcement`, policy authority or actual confinement activation. Those
remain Python checks or external premises whose correspondence is unproved.

## Captured contract

| Record | Fields checked by the finite model |
|---|---|
| Binding | Principal, session, call, tool, artifact, grant, plan, host, context, nonce, deployment, runtime and worker PID/start time/boot ID |
| Assignment | Obligation ID, adapter ID, `exact` or `tightened` support |
| Native plan | Adapter ID, digest, obligation IDs |
| Evidence | Adapter ID, native-plan digest, context, nonce, obligation IDs |
| Plan | Grant, host, digest, mode, assignments, native plans, waived IDs, ordered removed wants |
| Receipt | Grant, plan, host, context, nonce, artifact, deployment, runtime, mode, activated IDs, ordered removed wants, evidence |

`BoundTo` equates every plan/receipt identity above that has a corresponding
binding field. Each identity-bearing lifecycle event compares the complete
binding. `ValidCoverage` requires:

1. Nonempty assignments with unique nonempty obligation IDs and nonempty owners.
   The support type admits only exact or tightened assignments.
2. Nonempty native plans with unique adapter IDs, exactly the assignment owners.
   Each row has a nonempty digest and nonempty, unique obligation IDs exactly
   assigned to that adapter.
3. Exactly one evidence row per native-plan adapter, matching its digest and
   obligation IDs and the receipt's context and nonce. Evidence obligation lists
   are nonempty and unique.
4. Unique activated IDs equal both assigned IDs and the evidence union. Receipt
   mode and the ordered `removedWants` list equal the plan's.
5. Unique nonempty waived IDs disjoint from assignments. Mode is enforced exactly
   when waivers are empty, otherwise degraded.

Coverage comparisons use membership equality with separate uniqueness checks;
row order is immaterial. Removed-wants metadata uses exact list equality,
including order. No digest preimage, signature, fresh observation or waiver
permission is inferred from these strings.

This covers **assigned obligations**, not the completeness of the original grant
inventory. The latter still needs correspondence for obligation generation,
`_validate_obligations`, negotiation, authorized waivers and
`RequirementLedger.recheck`. A future formal inventory extension must bind that
original inventory and show its IDs equal assigned plus authorized waived IDs;
a receipt's declaration cannot supply the premise itself.

## Proved statements and useful paths

`coverageAccept_iff` and `certificateValid_iff` establish that the executable
checks decide `ValidCoverage` and `BoundTo ∧ ValidCoverage`. Ownership and
evidence theorems establish unique adapter ownership, unique evidence coverage,
and no extra or missing obligations. `runCertified` refuses an invalid
certificate for every trace. `runCertified_running_exact` and
`certifiedRoute_exact` characterize the exact authorized/activated/GO prefix and
full successful route by certificate validity and matching events.

`useful_partition_certificate` and `useful_partition_route` construct successful
certificates for arbitrary nonempty, disjoint multi-adapter partitions and
valid disjoint waiver lists; they do not assume acceptance. The abstract model
preserves degraded-mode semantics. The selected Linux route still requires
an enforced, waiver-free plan and receipt. Other routes gain no new waiver
authorization or proof status.

## Wire version and reuse across execution

The exact request protocol is `worker-route-receipt-v2`, with mandatory
`protocol`, `binding`, `certificate` and `events`; responses must match that
protocol and schema 2. Old binaries/responses, missing certificates and unknown
fields or enum values refuse. The strict decoder rejects duplicate decoded
keys, invalid UTF-8/surrogate identities and extra documents. Bounds are 1 MiB
input, depth 12, 256 entries per certificate array, 32 events and 4096 Unicode
scalar values per identity. Deployment/runtime may be empty optional metadata;
other wire identities must be nonempty. Excess data refuses rather than being
truncated. The decoder itself has no refinement proof.

The bridge captures the selected binary's bytes and digest and executes sealed
`memfd` storage. It reads admitted native record slots and stores one detached
binding, certificate and event history as immutable JSON bytes. Both gates use
fresh decoded arguments from that capture. The history is captured before the
checker call, so its argument aliases cannot replace the next check's history.
Regression tests cover mutation through caller aliases and an observing checker
callback; they do not prove immutable controller state, safe module/class
rebinding, or every concurrent mutation behavior. Reusing activation evidence
after cleanup does not establish a fresh activation observation at that time.

## Evidence and remaining work

The [v2 audit](../../eval/campaigns/remediation-v2/raw/checks/receipt-formal-v1/report.json)
passed 37 fixed typed obligations, full record and constructive witnesses, both
negative controls, 18 driver tests and fresh Lean kernel replay with stable
sources. There are 54 public model theorems: 30 lifecycle and 24 coverage.
This replay uses Lean's own kernel, not an independent verifier implementation.
The earlier [v1 audit](../../eval/campaigns/remediation-v2/raw/checks/lean-worker-formal-v3/report.json)
remains historical and its binary is incompatible with the v2 bridge.

Separate runtime observations record
[180 passing bridge tests](../../eval/campaigns/remediation-v2/raw/checks/receipt-bridge-v2/final-v1.json)
and [3/3 direct native cases](../../eval/campaigns/remediation-v2/raw/receipt-native-diagnostic-v1/report.json)
against the audited v2 executable; a separate observer-assisted native rerun
also passed 3/3. Selected sources and binary bytes were stable. The outer Docker
harness was unconfined; the inner worker used production activation and cleanup.
These observations are not model-to-runtime refinement or a full application
cohort result. See the [runtime guide](lean-worker-route.md) for commands and
historical failures retained alongside the new evidence.

The [cross-adapter scope probe](../../eval/campaigns/remediation-v2/raw/checks/receipt-cross-adapter-scope-v2/result.json)
used a separately identified development v2 executable. Crossed evidence refused,
but consistently changed assignment/native-plan/evidence rows with unchanged
opaque digest strings were accepted. This demonstrates the unproved digest
preimage and faithful-projection premise; it does not demonstrate a production
signature bypass.

Remaining work includes faithful Python projection and call placement, complete
grant inventory, `RuleEnforcement`, authorized waivers, signatures and time
checks, digest derivation, truthful native activation and lifetime observations,
controller binding stability, every outer-graph effect path, publication
mediation, and serialization/decoder/compiler/loader/OS correspondence. The audit
keeps all corresponding refinement flags and `system_complete` false. No current
Pandas full-cohort result is implied by the optional checker selector; future
runs must preserve the complete frozen denominator and failed observations.
