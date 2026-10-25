# Demo 16: inspecting analysis

Read a committed finding through `AnalysisClient`, then match it to its snapshot and completion notification. Labels and provenance are available through the same client.

Run from the repository root with the prebuilt environment:

```bash
libs/prebuilt/.venv/bin/python workspace/16_analysis_inspection/demo.py
```

If the environment is missing, run `uv sync --directory libs/prebuilt` first.
No model, network, credentials, Cedar CLI, or Linux sandbox is needed.

## What to look for

The public query and subscription reference the same canonical finding; reading them does not rerun the analyzer.

The script asserts the expected behavior and exits unsuccessfully on a mismatch.

## Try it

Query `AnalysisQuery(analyzer_id="missing")` separately and print its empty records. Filters select stored results.

## Scope

The access context is supplied by this trusted local script. In an application it must come from authenticated caller identity; inspection results cannot authorize execution.

[All demos and setup notes](../README.md)
