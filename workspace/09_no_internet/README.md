# Mandatory access control: no internet

Apply an operator-owned MAC policy independently of DAC.

Run from the repository root with the prebuilt environment:

```bash
libs/prebuilt/.venv/bin/python workspace/09_no_internet/demo.py
```

`no_internet.cedar` supplies the MAC policy; `worker.py` is the confined tool.

Requires Linux Landlock, libseccomp, and the Cedar CLI.

[All demos and setup notes](../README.md)
