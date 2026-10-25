# Demo 11: an analysis plugin

Register one analyzer for `input.admit` and inspect the finding it returns. Start with `DocumentMarker`, then follow its registration into `boundary.before`.

Run from the repository root with the prebuilt environment:

```bash
libs/prebuilt/.venv/bin/python workspace/11_analysis_plugin/demo.py
```

If the environment is missing, run `uv sync --directory libs/prebuilt` first.
No model, network, credentials, Cedar CLI, or Linux sandbox is needed.

## What to look for

The output shows one event producing one namespaced finding bound to the document.

The script asserts the expected behavior and exits unsuccessfully on a mismatch.

## Try it

Change the document text. The marker still reports it as seen: classification logic belongs in `analyze`, while the runtime schedules and records it.

## Scope

This marker demonstrates the plugin contract only. A finding does not itself grant or deny permission.

[All demos and setup notes](../README.md)
