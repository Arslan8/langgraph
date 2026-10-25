# Using a database mediator

Configure per-record read, write, and delete permissions using the SQLite mediator.

Run from the repository root with the prebuilt environment:

```bash
libs/prebuilt/.venv/bin/python workspace/06_database/demo.py
```

`worker.py` implements the database tool. Add `--step` to pause before each scenario. Requires Python 3.11+.

Requires Linux Landlock, libseccomp, and the Cedar CLI.

[All demos and setup notes](../README.md)
