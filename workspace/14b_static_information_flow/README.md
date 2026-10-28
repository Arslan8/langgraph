# Demo 14b: static information-flow control

Demo 14 propagates labels while values are created at runtime. This companion
checks the tool's source and manifest during setup and **rejects admission** if
its possible confidentiality bound exceeds the destination's clearance.

The tool body never runs. No report file, model, network service, Cedar executable,
or sandbox is needed for this admission-only demonstration.

## Run

```bash
libs/prebuilt/.venv/bin/python workspace/14b_static_information_flow/demo.py
```

Expected outcomes:

```text
public: REJECTED before execution
internal: ADMITTED by the static IFC gate
unclassified: REJECTED before execution
Tool body never executed; the report file was not read.
```

The script also prints the reason for each rejection and asserts these outcomes.
If needed, run `uv sync --directory libs/prebuilt` first.

## The control

[manifest.slp](manifest.slp) declares the tool's file-read authority:

```text
runs inprocess
fs read /private/report.txt need
returns sensitive
```

The trusted application supplies confidentiality classifications and installs the
static gate as part of ordinary tool admission:

```python
security = cedar_security(
    read_report,
    manifest=manifest,
    policy="permit(principal, action, resource);",
    static_flow=StaticFlowPolicy(
        read_labels={("fs", "/private/report.txt"): {"secret"}},
        input_labels=set(),
        return_clearance=clearance,
    ),
)
```

- The existing source checker verifies that the actual tool body uses approved
  resource APIs and that its inferred effects are covered by the manifest.
- Static IFC joins the input confidentiality bound and every declared read label.
- Every declared write destination and the return destination must have clearance
  for the resulting bound. Public clearance is an empty set; internal clearance
  includes `secret`; an unclassified clearance is `None` and rejects admission.
- Only a compatible result permits construction of the security configuration.
  A potential flow or unknown evidence raises `SecurityConfigurationError`.

Here, the destination is the tool's caller, represented by `return_clearance`.
The `returns sensitive` manifest annotation does not infer or prove confidentiality;
classification still comes from trusted policy. Demo 14's provider destinations
and this demo's return destinations illustrate the same clearance rule at different
boundaries.

For later execution, attach the returned `security` to the normal secured ToolNode
or guarded-tool path. Static admission does not grant resource permissions or
replace runtime authorization. This demo deliberately stops after admission.

## Try it

Remove `secret` from the internal clearance: that case is rejected too (and the
expected-outcome assertion must be updated). Remove the file's classification:
admission is rejected as unknown. Change the source to an undeclared read: the
source/manifest check rejects it before the IFC check can admit it.

## Why conservative?

This is static IFC using a **declared authority bound**, not a precise analysis of
individual Python variables. An unused secret-read permission still contributes
to the bound. A constant return or an output written before the read can therefore
be rejected even when that particular data dependence would be safe.

That conservatism makes the small supported check useful without pretending to
understand arbitrary Python. Unsupported syntax/calls, unclassified operations,
missing labels, conditional rules, resource templates, and wildcard selectors do
not silently pass. Policy inputs are copied and frozen. The existing admission
machinery binds the check to the actual function and approved API identities and
rechecks those bindings before invoking it.

Scope remains tool-local and in-process: trusted application setup and resource
classifications, reviewed terminal APIs, fixed literal resources, and the source
checker's supported function-body subset. Module initialization, decorators,
resource identity/normalizer correctness, timing/covert channels and downstream
use of returned data are outside this proof. This does not establish whole-program
noninterference or secure arbitrary direct Python calls. Other dispatchers are
explicitly rejected when this static gate is requested.

[Static IFC API and reasoning](../../docs/security/analysis/static-flow.md) ·
[Runtime companion](../14_information_flow/README.md) · [All demos](../README.md)
