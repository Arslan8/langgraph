# Evidence standard for route-scoped acceptance

This note explains what each SGV obligation means per route in
`supported-surface.json` (schema 2), what counts as evidence for it, and what
is only a premise. The verifier (`langgraph.prebuilt.security.route_verification`)
recomputes every named check from the current sources; nothing here is
satisfied by a saved report. **This is a route-scoped claim, not whole-system
completeness: an accepted route says only that its listed obligations are
discharged under its listed premises; unsupported routes, ungated effects and
every premise remain open.**

Obligation definitions are the campaign's
(`eval/campaigns/remediation-v2/acceptance.json`):

- SGV901: all supported effect paths and publication placement.
- SGV902: adapter composition and authoritative data/label correspondence.
- SGV903: truthful request-bound activation/lifetime observations and native
  enforcement correspondence.

## What counts

| Check id | Counts as | Proof? | Recomputed? |
|---|---|---|---|
| `router-source-proof` | `boundary_verification.verify_host_router`: complete, verified == discovered (21/21), loaded `host_router.py` equals the audited source | yes (source derivation) | yes |
| `host-output-correspondence` | `output_verification.verify_output_correspondence` proved with the validator dependency recomputed from `output_data.py` | yes | yes |
| `output-validator-contract` | `output_data_verification.verify_output_data_primitives` proved | yes | yes |
| `output-mediator-correspondence` | new `output_mediator_verification`: `OutputMediator._emit/_aemit` normal return is exactly the dispatched result through the captured rebuilder | yes | yes (component not yet present) |
| `admission-surface` | `admission_verification.verify_admission_surface`: all four obligations proved | yes | yes |
| `host-route:linux-sandbox` | `host_verification.verify_linux_host_route` structural checks all true | **no** (regression guard; `proved` is all-False by construction) | yes |
| `lean-audit:proofs/worker-route` | a fresh `make security-verify-lean` passes with kernel replay and `source_after` identities equal to the current tree | finite model only (`model_proved`); never source/compiler/decoder/OS/runtime refinement | yes |
| `runtime-evidence:<path>` | a labelled JSON record with a top-level boolean outcome field true, no recorded failures/issues, and at least one recorded `source_sha256` entry matching the current tree (every recorded path that exists in the tree must still match) | **no** | no |
| `gate:<code>` | the code is in `unsupported.REGISTRY` or (prefix form) `unsupported.PREFIXES` | **no** (registration is not placement) | yes |

A check that is not a proof can discharge an obligation only in the
combination listed for that route; it never upgrades to a proof by being
listed.

## Per route

**R1 `language-sandbox-tool`** (in-process admitted language programs).
SGV901 = `admission-surface` + `router-source-proof` + the five `gate:admission:*`
codes: the only admitted node body is the exact `ToolNode` dispatched through
the exact `ObjectPolicyHostExecutor` and `_LanguageSandboxDispatcher`, and the
router's return protocol is source-derived. SGV902 = `router-source-proof` +
`admission-surface`: the adapter chain is the captured identity that `recheck`
re-reads. SGV903 is applicable but has no qualifying check today: the language
derivation captures under `eval/campaigns/remediation-v2/raw/proof-language/`
carry no outcome field and their recorded hashes are stale. Premises:
interpreter correctness, execution-language implementation correspondence,
terminal implementations and their flow contracts, no descendant supervision,
initialization/runtime binding, recheck correctness.

**R2 `tool-node-dispatch`** (the dispatch spine under closed admission).
SGV901 and SGV902 as for R1. SGV903 not applicable: no host adapter on this
route; the adapter is R1 or R3. Premises are the `admission_verification`
premises (initialization, runtime binding, recheck correctness, async adapter
lifecycles, trusted framework primitives, pre-compile graph construction).

**R3 `linux-worker-compute`** (`LinuxSandboxExecutor` with the Lean checker
selected). SGV901 as above. SGV902 = `router-source-proof` + `admission-surface`
+ `lean-audit:proofs/worker-route` (proposed; the receipt/grant coverage model
is the composition evidence). SGV903 = `lean-audit:proofs/worker-route` +
`runtime-evidence:` records (receipt-v2 model audit, pandas receipt-v2 cohort)
+ `host-route:linux-sandbox`. The audit proves the finite captured model only.
Premises are the audit's `unproved_obligations` (call placement, certificate
projection faithfulness, truthful observations, JSON codec, compiler/loader,
OS/namespace/seccomp/LSM) plus the structural checker's (kernel, bubblewrap,
libseccomp, pinned interpreter, prior policy evaluation) and the cleanup
observation premises (PID/start-time, stable procfs, `openat2` not freezing
contents).

**R4 `output-publication`** (`OutputMediator` to `ObjectManagerHost`).
SGV901 as above. SGV902 = `router-source-proof` + `host-output-correspondence`
+ `output-validator-contract` + `output-mediator-correspondence`: the host
returns identical content within clearance, the validator's primitives hold,
and the mediator returns exactly the rebuilt dispatched result. SGV903 not
applicable: no host adapter. Premises are the `entry_premises` of
`output_verification` (exact request/labels, native semantics and stable
bindings, exact receiver with native lock) and `_VALIDATOR_PREMISES` of
`output_data_verification` (CPython semantics, initialization/runtime binding,
field stability, process-global events, unsanitized tracebacks).

## What is premise, not evidence

Anything a check lists under `premises`, `entry_premises`,
`unproved_obligations` or `remaining_composition`: compiler, decoder and OS
refinement; kernel, LSM, bubblewrap and libseccomp behaviour; module
initialization and runtime binding; field stability across a call;
interpreter correctness; truthfulness of recorded observations. A `runtime-evidence`
record is a labelled run, never a premise discharge. A registered refusal code
is a name, not proof that it fires before the feature's effects.

## Exclusions

An exclusion is gated when its `gate_code` is registered (exact or declared
prefix). An ungated exclusion blocks acceptance of every route until it is
either gated or removed from the route's scope with a stated reason; the
current ungated list and the reason each stays ungated are in the manifest's
`ungated_exclusions`. Literal codes raised in source but absent from the
registry are listed under `unregistered_refusals` and do not count.
