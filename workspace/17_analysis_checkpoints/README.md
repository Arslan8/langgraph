# Demo 17: analysis checkpoints

Save a signed analysis checkpoint, close its database, and restore its values into a fresh database. Then attempt a restore under a different policy.

Run from the repository root with the prebuilt environment:

```bash
libs/prebuilt/.venv/bin/python workspace/17_analysis_checkpoints/demo.py
```

If the environment is missing, run `uv sync --directory libs/prebuilt` first.
No model, network, credentials, Cedar CLI, or Linux sandbox is needed.

## What to look for

Value identity, source ancestry and confidentiality survive restore. A policy mismatch is rejected.

The script asserts the expected behavior and exits unsuccessfully on a mismatch.

## Try it

Change the restored policy back to the original configuration. Restore succeeds; update the expected rejection accordingly.

## Scope

Temporary SQLite files are cleaned up. The envelope stays in trusted process memory for this lesson; a production application must persist it and protect its signing key. This is the explicit checkpoint binding, not a graph-resume tutorial.

[All demos and setup notes](../README.md)
