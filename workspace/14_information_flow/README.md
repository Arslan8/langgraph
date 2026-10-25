# Demo 14: information flow

Label one source `secret`, derive a summary, then check submission to public and cleared model destinations under one fixed policy.

Run from the repository root with the prebuilt environment:

```bash
libs/prebuilt/.venv/bin/python workspace/14_information_flow/demo.py
```

If the environment is missing, run `uv sync --directory libs/prebuilt` first.
No model, network, credentials, Cedar CLI, or Linux sandbox is needed.

## What to look for

The summary inherits `secret`. Public submission is denied; internal submission is allowed. Only the allowed destination enters the local submission list.

The script asserts the expected behavior and exits unsuccessfully on a mismatch.

## Try it

Remove `secret` from the internal clearance and change its expected verdict to `DENY` and the expected submission list to empty. Both destinations should be denied.

## Scope

No provider is contacted. Source labels and destination clearances are trusted declarations, not inferred classifications. This demonstrates confidentiality flow, not every custom label domain.

[All demos and setup notes](../README.md)
