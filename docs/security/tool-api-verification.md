# Secured Tool API verification

When a host executor is configured, ToolNode selects that route independently
of whether preparation retained the principal and security-call fields. A
missing field produces `host:missing_security_context`; it cannot select local
tool execution. Regression checks exercise both missing fields, separately and
together, through synchronous and asynchronous calls.
The private local-dispatch methods on ToolNode and the guarded executor also
reject host mode at entry with `host:in_process_execution_disabled`, even when
called directly with a matching principal and request. These local methods do
not implicitly switch to host execution or mint authorization.

Run the verifier from `libs/prebuilt`:

```sh
uv run python -m langgraph.prebuilt.security.tool_api_verifier --output tool-api-report.json
```

The integrated [source-verification framework](source-verification.md) now runs
this matrix alongside interprocedural source analysis in CI.

Exit zero means **every discovered execution entry point passed the enumerated
API-conformance matrix**, and the source-analysis claims and reviewed source
evidence remain valid. Exit one means the claim is not established. CI runs this
matrix through the integrated command and uploads the report even when verification fails. There is no option
to ignore failures or accept only the already passing APIs.

## Contract and discovery

The verifier discovers inherited callable methods and exposed callback fields on
secured objects and on their adapters. Each method is explicitly classified as
execution, adapter construction, inspection, or trusted construction. Unknown
methods and unavailable method source fail inventory coverage. Source digests,
owners, parameter names, and installed dependency versions are recorded.

The matrix uses both legacy `Tool` and `StructuredTool` implementations, each
secured through `guarded_tool` and `ToolNode`. It covers synchronous/asynchronous
calls, run methods, batching, completion-order batching, streaming, transforms,
event versions, log streams, low-level run methods, and exposed callbacks. It
also exercises binding, configuration, retries, secured fallbacks, listeners,
composition, mapping, output selection/assignment, conversion to tools, copying,
and configurable alternatives. Configurable adapters' prepared objects are
checked too.

For each supported entry point the matrix exercises allow, policy denial,
missing principal, and missing scope. The pure local tool body consumes a fresh
permission record for its exact input, so an unapproved body execution fails.
Every case is repeated with a synthetic host and with a host that denies
activation. The host oracle requires the exact authorized principal/request
objects and attributed policy constraints; it detects any local callback
execution or fallback. This checks the existing `ToolNode` and `guarded_tool`
implementations, not the separate `HostRouter`. The synthetic receipt is only
routing test data, never evidence of kernel enforcement. Separate real Linux
tests exercise legacy tools through conversion and both event-stream versions.
Batch members have distinct input values. Allow cases require the expected
number of executions; denial cases require zero executions and the expected
denial reason. Unsupported event APIs must raise the specifically expected
`NotImplementedError` without execution. Arbitrary exceptions do not count as
successful security checks. Unhandled asynchronous stream errors also fail the
overall gate.

## What the claim means

`complete` is computed from inventory coverage, all conformance cases, reviewed
source evidence, source-analysis claims, and asynchronous error accounting. It
is not a manually assigned success flag. A failing case includes the family,
adapter, API, mode, event version, permission/execution counts, unmatched
permissions, and diagnostic. Developers should fix the implementation or a
proven fixture defect, then rerun the entire matrix. Do not change expectations
simply to make failures disappear.

This is **finite conformance completeness**, not an all-input static proof like
a sound qualifier/type analysis. Adapter parameters are explicitly chosen and
compositions are finite. Custom subclasses, arbitrary policy code, replacement
executables, hostile mutation, retained original unguarded tools, effects inside
in-process tools, and every possible runtime configuration are not proved safe.
Inspection and construction methods are inventoried but their semantics remain
trusted; discovery does not prove those classifications correct. The bounded
source analyzer still uses reviewed helper contracts and opaque trusted calls.

`whole_framework_mac_complete` remains a separate result. Passing Tool API
conformance cannot establish complete publication mediation, termination/lifetime
correctness, confidentiality, or mediation of every Python side effect.

## Current results

See [the recorded summary](tool-api-summary.json). All **15,744 cases pass** across
72 family/adapter configurations and three execution backends, with zero
background stream errors. Fixed implementation defects were schema-less legacy
tools losing arguments, converted-tool callbacks losing explicit runtime/security
configuration, immutable policy declarations being copied as trace metadata,
and ToolNode event streams lacking a root lifecycle for pre-dispatch errors.

The source claim gate additionally checks that all four existing host-dispatch
methods forward the constraints from their successful policy decision. Negative
source tests reject missing, substituted and superseded constraints. This is
still a bounded check under reviewed helper contracts. The separate whole-source
analysis remains unresolved; passing this matrix does not upgrade it to a proof.

The existing source checker was also corrected so reviewed helper digest drift
invalidates its claim gate and related coverage statuses, rather than merely
marking an obligation unresolved.
