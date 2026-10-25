# Demo 13: provenance

Track one document through a summary and a formatted answer. Explicit parent references preserve where each value came from.

Run from the repository root with the prebuilt environment:

```bash
libs/prebuilt/.venv/bin/python workspace/13_provenance/demo.py
```

If the environment is missing, run `uv sync --directory libs/prebuilt` first.
No model, network, credentials, Cedar CLI, or Linux sandbox is needed.

## What to look for

The final answer retains both earlier values as ancestors. A separate document with identical text has a different identity.

The script asserts the expected behavior and exits unsuccessfully on a mismatch.

## Try it

Add `unrelated` to the parents of the answer and update the last assertion. It becomes an ancestor because you explicitly declared its influence.

## Scope

These are trusted, explicitly declared dependencies. The store does not infer which inputs an arbitrary Python function actually used.

[All demos and setup notes](../README.md)
