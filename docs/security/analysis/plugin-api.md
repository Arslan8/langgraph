# Analysis plugins

Import contracts from `langgraph.prebuilt.analysis`. `Analyzer` supplies
`analyze(event, context)` and `aanalyze(event, context)`, returning `AnalysisResult`.
Findings carry stable IDs, analyzer identity/version, namespaced code, subject and
evidence references, explicit status and configuration digest. Optional scores must
be finite in [0, 1]. They are not calibrated confidence.

Register `AnalyzerRegistration` explicitly at the root with subscribed event strings,
dependencies, required/advisory mode, timeout and content access. No import-time
registration occurs. Duplicate IDs, unknown schemas/producers, missing dependencies,
advisory dependencies of required plugins, and cycles are rejected. Register custom
`EventSpec` objects with schema, phase, producer and barrier. Registration alone does
not instrument any Python operation.

A minimal second plugin is in
`libs/prebuilt/tests/analysis/test_runtime_access.py` (`Marker`). It uses the same
public result schema to mark `example.department.restricted`; its separate policy is
in `test_policy_bridge.py`. To give a plugin a custom event:

```python
from langgraph.prebuilt.analysis import EventSpec, Registry, AnalyzerRegistration

spec = EventSpec("example.document", "before", "document_adapter", True)
# analyzer implements the public Analyzer protocol.
registry = Registry(
    (spec,),
    (AnalyzerRegistration("department", "1", analyzer, (spec.name,)),),
    producers=frozenset({"document_adapter"}),
)
```

The application must actually emit the event and await the barrier at its document
admission boundary. `context.resolver.resolve(ref)` requires configured content
access and an in-scope reference. `context.provenance.ancestors(ref)` is scoped too.
Dependencies ensure upstream committed findings are available in
`context.prior_findings`. A benign finding cannot remove previous annotations.

Annotation and dependency proposals are additional restrictions. Registered domains
combine proposals with current labels. Plugins cannot remove mandatory edges,
declassify confidentiality, endorse integrity or mint grants. Integrity and
confidentiality retain the existing `SecurityLabels` representation. A future
trusted declassification/endorsement API is deliberately absent from this demo.

Run the contract and second-plugin checks:

```sh
cd libs/prebuilt
uv sync
uv run pytest tests/analysis/test_contracts.py tests/analysis/test_runtime_access.py tests/analysis/test_policy_bridge.py
```
