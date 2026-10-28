# Superseded evaluation records

These records are retained for auditability but are excluded by
`regenerate_results.py`.

- `fare-bare-model`: called the model directly and used a substring oracle.
- `tool-census-placeholders`: counted pass-only placeholder sources.
- `host-compilation-preparation-mismatch`: changed the manifest in the
  missing-capability case and did not reuse the same parsed objects.
- `ace-repeated-host-probe`: repeated one availability probe under nine labels.
- `isolategpt-unscoped-sandbox`: did not clearly identify its standalone-module
  scope.
- `lean-missing-toolchain-path`: failed before replay because `lake` was absent
  from `PATH`.

The sibling non-superseded directories contain the corrected authoritative
records.
