# Bounded authorization-state analysis

The framework now has a source checker for a specific hook-placement property:
every catalogued secured host or in-process dispatch follows a successful
decision of the required permission class for the same principal and request. A
dispatch consumes that authorization in the model; another physical dispatch
requires a new decision. This is analysis evidence under explicit contracts,
not a formal soundness theorem for Python or a proof of whole-framework complete
mediation.

The method is inspired by Zhang, Edwards, and Jaeger's
[Using CQUAL for Static Analysis of Authorization Hook Placement](https://www.usenix.org/legacy/event/sec02/full_papers/zhang/zhang_html/).
It does not run CQUAL. It implements a bounded, path-sensitive authorization-state
analysis over Python ASTs. The distinction from ordinary taint analysis is that
it tracks a successful decision's permission class and object identities, rather
than just the presence of a security wrapper or the origin of input data.

## Run and interpret the report

The [checked-in report](mediation-report.json) records the current source
snapshot. Regenerate it after changing checked sources, summaries, or the
checker; CI generates fresh evidence rather than trusting this snapshot.

From the repository root:

```bash
cd libs/prebuilt
uv run python -m langgraph.prebuilt.security.mediation --output mediation-report.json
```

The default command exits **1** while overall coverage is incomplete. This is
expected for the current inventory. To gate only the explicitly enumerated
dispatch claims:

```bash
uv run python -m langgraph.prebuilt.security.mediation --check-claims --output mediation-report.json
```

This command exits **0** only when all eight dispatch sites in four entry-point
checks are `verified_under_contract`. It still writes `complete: false`. CI uses this
narrowly named gate and uploads the entire report, including unresolved entries.
Missing files, parse errors, missing/ambiguous functions, changed call shapes,
unknown calls, unsupported statements, and path-budget exhaustion cannot produce
a verified claim. Sources are parsed, never imported or executed by the checker.

The report carries source, checker, and catalog SHA-256 hashes. It contains no
timestamps or absolute checkout paths, so identical inputs produce identical
reports. A source hash identifies the input; it is not a signature or proof.

## Current coverage

| Controlled operation | Analysis status |
| --- | --- |
| Guarded and `ToolNode` host dispatch, sync and async | Checked under source-bound helper contracts |
| Guarded and `ToolNode` in-process dispatch, sync and async | Checked under source-bound helper contracts |
| Principal binding and policy helper implementations | Reviewed function bodies are hash-bound; arbitrary policy modules remain trusted |
| In-process executable and injected-argument correspondence | Runtime identity checks plus regression tests; no per-access confinement |
| Grant filtering, lowering, activation, and receipt validity | Source-bound and regression-tested for implemented Linux authority domains |
| Reservations, cancellation, and worker termination lifetime | Covered for Linux workers; in-process background work is unsupported |
| Delegation, authority transfer, and shared budgets | Scope attenuation and explicit label transfer covered; live cross-session reservations unsupported |
| Model calls, result publication, checkpoint and artifact transfers | Inventory published; several boundaries require explicit application opt-in |
| Arbitrary dynamic Python, dependency code, and original tool aliases | Unsupported |

The inventory is independent of which rows currently pass. Adding callbacks or
passing tests does not change unresolved rows to verified. The dispatch claims
check call authorization; separate source-bound evidence records the grant and
lifecycle contracts.

## Publication boundaries

Tool results receive automatic `post`/`apost` notification before `ToolNode`
publishes them. Linux-worker external effects are limited by the activated grant.
Other boundaries are not automatically intercepted:

| Boundary | Contract |
| --- | --- |
| Model requests | The application must wrap the complete effect lifetime with `SessionFlowPolicy.guard_operation`. |
| Checkpoint and artifact copies | The application must call `SessionFlowPolicy.transfer_session` before publication to another session. |
| Callbacks and tracing | The application must configure and hold `guard_operation` around the complete sink lifetime. |
| In-process tool effects | Trusted after call authorization; resource accesses are not mediated individually. |

These opt-in APIs fail closed when used, but their existence does not prove that
an application used them on every publication path.

## Model and assumptions

The checked implementation is `langgraph/prebuilt/security/mediation.py`; the
reviewed inventory and helper summaries are in `_mediation_catalog.py`.

An authorizer summary specifies its decision return value, a permission class,
and selectors for the principal/request identities that decision covers. An
operation summary specifies the permission class and actual argument identities
required at dispatch. Each framework summary names source-evidence records whose
function bodies and SHA-256 hashes appear in the JSON report. This makes review
drift fail closed: the dependent obligation becomes unresolved until the
catalogued digest is explicitly updated after review. It does not infer the
correctness of arbitrary policy modules or prove identity authentication.

For secured `ToolNode` in-process calls, framework injection occurs before
`prepare` and `permission`, so policy receives the complete argument mapping.
Dispatch then verifies the registered executable object, principal, call id,
tool name, and argument mapping against that authorized request. A wrapper cannot
replace the executable while retaining authorization for the registered name.

The checker models local aliases and reassignment, tuple-return projections,
allow/deny/approval branches, short-circuit conditions, early returns, raises,
and synchronous/asynchronous dispatch. An allow guard establishes authorization
only when its decision came from a matching authorizer summary. A fresh request
or principal does not inherit an old decision. Assertions cannot establish
authorization because Python can disable them.

Exception handlers conservatively start without authorization facts or known
local identities. `finally` bodies are checked on normal and abrupt paths.
This overapproximation can report unresolved or unverified code that is safe;
it does not certify exception timing. Loops, heap writes, dynamic callees, and
unsupported expression forms prevent a verified result. Path exploration is
bounded; reaching the bound is unresolved, never success.

The source model assumes stable nested security-relevant object contents, ordinary
attribute access, stable call targets, the declared `Verdict` enum, and trusted
configuration. It does not model hostile descriptors, monkeypatching, native
code, mutable objects changed by another task, or dependency internals. Every
reviewed opaque helper is listed in the output. Its hidden effects and mutation
behavior remain assumptions; changing its implementation requires review even
when this gate passes. A local reassignment can be checked without claiming a
general heap-alias or interprocedural proof.

## Maintenance and next proof obligations

The checker has model-level tests for both authorized paths and incomplete
paths, wrong permission classes, changed identities, aliases, repeated dispatch,
exception handling, `finally`, unsupported syntax, and exhausted analysis bounds.
These snippets are abstract fixtures, not executed tool implementations. The
framework regression test checks the actual four entry points against the same
engine. Passing these tests validates implementation examples, not a soundness
theorem for every possible AST.

Review changes to the catalog as changes to the trusted computing base. Do not
add an unknown call to `trusted_calls` merely to clear the gate. Document its
identity-preservation and effect contract first. An unresolved site is an
analysis obligation, not automatically a demonstrated security defect.

Remaining work is concentrated outside the verified call gates: automated
interception of publication APIs, a lifecycle contract for in-process background
work and timed-out policy threads, and transfer semantics for live reservations
or numeric budgets. The existing [escape analyzer](escape-analysis.md) remains
useful for discovering operations outside this catalog; confinement remains
necessary for untrusted code. Neither a clean escape scan nor a passing dispatch
gate should be presented as proof that the entire MAC interface is complete.
