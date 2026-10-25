# Static manifest verification

A real decorated tool is checked automatically during `cedar_security` setup.

Run from the repository root with the prebuilt environment:

```bash
libs/prebuilt/.venv/bin/python workspace/07_manifest_verification/demo.py
```

The incorrect resource declaration fails before the tool runs. Replace `/tmp/other-report.txt` with `@{path}` to cover the read. A constant return also passes because declared permissions need not be used.

To see why declaring a resource does not authorize arbitrary Python APIs, run:

```bash
libs/prebuilt/.venv/bin/python workspace/07_manifest_verification/bypasses.py
```

Both direct `Path.read_text` access and reflection through `getattr` are rejected
at admission, even with both file reads declared. Neither tool body executes.
No Cedar CLI or sandbox is needed for these rejection examples.

[All demos and setup notes](../README.md)
