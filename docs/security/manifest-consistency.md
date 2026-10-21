# Static manifest consistency checks

`check_manifest_consistency` compares a Python tool function's resource effects
with its `.slp` security manifest without importing or executing the source.
It checks capability coverage: each modeled effect must have a matching class,
operation, and resource pattern in an active manifest rule. Extra declarations
are reported as `unused_rules`, rather than treated as errors.

```python
from langgraph.prebuilt.security.manifest_consistency import (
    ManifestOperation,
    check_manifest_consistency,
)
from langgraph.prebuilt.security import parse_security_manifest

manifest = parse_security_manifest("""
class fs {
  operations read write
  object path
  normalizer identity
  attrs
  enforced_by trusted_tool
}
tool read_document {
  fs read @{path} need
}
""")
source = """
from document_store import read

def read_document(path):
    return read(path)
"""
report = check_manifest_consistency(
    source,
    manifest,
    tool_name="read_document",
    operations=(
        ManifestOperation("document_store.read", "fs", "read", "path"),
    ),
)
assert report["consistent"]
```

The operation model is an explicit, reviewed trust assumption: this API performs
only the named operation on the resource argument at `position` (default zero)
or keyword `parameter`. Other arguments and the result must be inert data; the
API must not execute callbacks or defer effects. Models must include all effects
of the terminal API. Do not model an arbitrary helper as a terminal to silence
an unknown result. General helpers currently produce `unknown`.

The checker supports top-level function bodies, local argument aliases, imported
API aliases, literal resources, simple f-string templates, and `if`/`else`
branches comparing the closed manifest selector to string literals with `==`
or `!=`. It checks each allowed selector value independently. It does not
analyze rejected selector values, which the manifest authorizer must deny before
execution. Resource expressions are compared structurally before normalization;
two paths which happen to normalize to the same object may require review.

Reports have three outcomes:

- `consistent`: all analyzed effects are covered under the stated assumptions.
- `mismatch`: a manifest argument is missing, or a modeled effect/resource is
  absent from the active declarations. Other parts of the function can still be
  unknown; inspect `issues` for both kinds of findings.
- `unknown`: unsupported Python, unresolved resources, or unmodeled calls prevent
  a conclusion. Unknown is never accepted as consistent.

Reports include source line numbers, observed effects, matching rule indices,
unused rule indices, and the source SHA-256. Unused rules in an incomplete
analysis are not evidence that a permission can safely be removed.

This initial checker assumes inert string inputs and trusted terminal bindings.
It does not verify module initialization, decorators, default argument
expressions, monkey patching, arbitrary object behavior, `runs`, `returns`, or
runtime authorization. In particular, matching a `want` declaration does not
prove the tool handles a denied optional grant. It complements authorization
and enforcement checks; it does not prove Python confinement. Unsupported loops,
exception handling, helper calls, and dynamic dispatch remain unknown.

## Command line

Save reviewed operation models as a JSON array:

```json
[
  {
    "target": "document_store.read",
    "class_name": "fs",
    "operation": "read",
    "parameter": "path",
    "position": 0
  }
]
```

Run from an environment containing `langgraph-prebuilt`:

```sh
python -m langgraph.prebuilt.security.manifest_consistency \
  tools.py tools.slp --tool read_document --operations operations.json \
  --output consistency.json
```

`--function` selects a Python function whose name differs from the manifest tool
name. Omitting `--operations` leaves all calls unmodeled. The command exits zero
only for `consistent`; mismatches, unknown behavior, and invalid inputs exit one.
