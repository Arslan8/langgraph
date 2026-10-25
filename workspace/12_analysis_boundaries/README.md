# Demo 12: execution boundaries

Wrap a local stand-in for a model with a request and response analysis boundary. The printed sequence makes the execution order visible.

Run from the repository root with the prebuilt environment:

```bash
libs/prebuilt/.venv/bin/python workspace/12_analysis_boundaries/demo.py
```

If the environment is missing, run `uv sync --directory libs/prebuilt` first.
No model, network, credentials, Cedar CLI, or Linux sandbox is needed.

## What to look for

`model.request -> model executes -> model.response`, followed by `Response: Hello`.

The script asserts the expected behavior and exits unsuccessfully on a mismatch.

## Try it

Change the local model response. The boundary order stays the same, and the response still depends on the prompt.

## Scope

The model is an ordinary local function. Only this explicitly wrapped call is instrumented; registration alone does not intercept other functions.

[All demos and setup notes](../README.md)
