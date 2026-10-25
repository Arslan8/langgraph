# Demo 18: evaluating an analyzer

Run one keyword analyzer against four labeled examples. Count a true positive, true negative, false positive and false negative, then calculate precision and recall.

Run from the repository root with the prebuilt environment:

```bash
libs/prebuilt/.venv/bin/python workspace/18_analysis_evaluation/demo.py
```

If the environment is missing, run `uv sync --directory libs/prebuilt` first.
No model, network, credentials, Cedar CLI, or Linux sandbox is needed.

## What to look for

Each confusion-matrix category has one example. Precision and recall are both 50%. Boundary processing time varies by machine.

The script asserts the expected behavior and exits unsuccessfully on a mismatch.

## Try it

Add another benign sentence containing `secret` and update the expected counts. Precision falls because the analyzer produces another false positive.

## Scope

This tiny synthetic fixture teaches measurement; it is not a quality benchmark or a sensitive-data detector. Timing includes runtime processing and is not overhead relative to an uninstrumented baseline. No enforcement policy runs here.

[All demos and setup notes](../README.md)
