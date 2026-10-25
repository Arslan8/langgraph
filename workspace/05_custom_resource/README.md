# Custom resource class: pump

Authorize device operations independently of socket access.

Run from the repository root with the prebuilt environment. Start the simulator
in the first terminal:

```bash
libs/prebuilt/.venv/bin/python workspace/05_custom_resource/simulator.py
```

Run the controller in a second terminal:

```bash
libs/prebuilt/.venv/bin/python workspace/05_custom_resource/demo.py
```

`worker.py` contains the isolated tool. Add `--demo` to the controller command
for the complete permission matrix.

Requires Linux Landlock, libseccomp, and the Cedar CLI.

[All demos and setup notes](../README.md)
