# Static information-flow control from manifests

Static IFC is optional at application setup. It does not require event callbacks,
standardized analyzer findings, or runtime provenance tracking. The enforcement
entry point is `cedar_security(..., static_flow=StaticFlowPolicy(...))` for the
source-bound in-process dispatcher. [Demo 14b](../../../workspace/14b_static_information_flow/README.md)
shows admission success and rejection without executing a tool body.

## Why a manifest check is not enough

A manifest lists requested resource authority. Source/manifest consistency checks
that the inferred function-body effects fit within that authority. It does not
classify information as secret, establish destination clearance, or forbid a
secret read and public write that are both declared.

Static IFC adds a policy check to that admission path. Trusted application policy
supplies read labels, input bounds, write clearances and return clearance. These
cannot be inferred from resource names or an assertion such as `returns sensitive`.
For the supported subset, the conservative bound is:

```text
bound = input labels ∪ labels of every declared read
require bound ⊆ clearance of every declared write and of the return destination
```

All declared authority contributes, including unused permissions and operations in
different orders. There is no declassification rule, path-sensitive relaxation or
claim that a reported potential flow actually occurred. This can reject safe
programs; it avoids treating unproved variable-level dependencies as safe.

## Control versus reporting

`StaticFlowPolicy` is imported from `langgraph.prebuilt.analysis.static_flow`.
Its classifications are copied into immutable mappings and sets. During
`ManifestAdmission`, the existing checker first verifies the actual function and
its approved terminal bindings. The policy then requires a compatible flow bound.
Both `potential_flow` and `unknown` raise `SecurityConfigurationError`, preventing
the security configuration from being created for that tool. Async bodies undergo
the same admission check.

The existing admission machinery binds source to the loaded executable body and
validates the function code, defaults, API bindings and resource clients again
before invocation. A subsequently changed body cannot reuse the admission. The
normal resource grant and authorization requirements still apply. A static pass is
not a runtime permission grant; the returned SecurityConfig must be used on the
secured execution path. Direct calls outside that path remain outside its scope.

`check_manifest_flow` is the separate reporting utility. It parses supplied source
text without importing or executing it and returns `compatible`, `potential_flow`
or `unknown`, the joined bound, potential sink conflicts and the underlying
source-consistency report. Plugin writers can use that report in their own tools.
A report alone does not control execution and does not establish that supplied
source text is the executable body; the admission integration supplies that binding.

## Configuration

```python
from langgraph.prebuilt.analysis.static_flow import StaticFlowPolicy

flow = StaticFlowPolicy(
    read_labels={("fs", "/private/report.txt"): {"secret"}},
    input_labels=set(),
    return_clearance={"secret"},
    write_clearances={("fs", "/internal/summary.txt"): {"secret"}},
)
```

Keys are `(resource class, literal resource selector)`. An empty set means public;
`None` or an absent required classification means unknown, not public. The default
operation roles classify `fs::read` as a source and `fs::write` as a sink. Applications
may supply trusted `operation_roles` for other resource classes; any declared
operation without a role rejects admission. Typed registered resource clients are
checked through the same existing source-consistency machinery.

Only fixed literal, unconditioned resource rules are supported initially. Templates,
wildcards and selector-conditioned rules report unknown. Unsupported source and
source/manifest mismatches cannot yield a compatible result. Static IFC currently
requires the in-process admission path; passing it with a custom isolated dispatcher
raises an error rather than silently ignoring it.

## Scope and assumptions

This is a conservative tool-level information-flow admission rule over a supported
source subset. Resource classifications, input bounds, return destination clearance,
operation roles, reviewed terminal implementations and application setup are trusted.
Resource identity and normalization must correspond to the classified objects.
The source checker excludes module initialization and decorator execution. The
analysis does not prove arbitrary Python safe, track individual variables, cover
timing/covert channels, or constrain later uses of a returned value in another
unchecked component. Whole-workflow guarantees require composition and runtime
boundary enforcement as appropriate.

Runtime analysis in [demo 14](../../../workspace/14_information_flow/README.md)
remains useful: it propagates labels for actual tracked values and checks actual
instrumented destinations. Static admission and runtime enforcement are complementary.
