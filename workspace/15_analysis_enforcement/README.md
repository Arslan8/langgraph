# Demo 15: analysis enforcement

Invoke the same permitted tool with a working analyzer and an unavailable analyzer. `AnalysisGate` requires usable analysis for the pending tool operation.

Run from the repository root with the prebuilt environment:

```bash
libs/prebuilt/.venv/bin/python workspace/15_analysis_enforcement/demo.py
```

If the environment is missing, run `uv sync --directory libs/prebuilt` first.
No model, network, credentials, Cedar CLI, or Linux sandbox is needed.

## What to look for

Complete analysis permits one local effect. Unavailable required analysis prevents the tool body from running: zero effects.

The script asserts the expected behavior and exits unsuccessfully on a mismatch.

## Try it

Make the analyzer fail in both cases and update the expected outcomes. Ordinary DAC permission alone cannot bypass required analysis.

## Scope

This demonstrates availability gating on a guarded tool, not malicious-content classification. Analysis completion is only one condition in the existing permission chain.

[All demos and setup notes](../README.md)
