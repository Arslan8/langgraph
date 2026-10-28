# Alternative backend feasibility

Bubblewrap 0.9.0 is installed. Its current production preflight fails during
network namespace setup. The failure does not establish that the executable was
missing or that previous runs could not execute it.

The historical `../e6/verified-v2/samples.jsonl` contains 280 host invocations
(including first use and warmups), all marked valid with enforced receipts
identifying `linux-bubblewrap-v1`. Its host capture records Bubblewrap 0.9.0 on
2026-10-26. These saved artifacts support the earlier execution claim; the cause
of the changed permission behavior has not been established.

Current feasibility probes:

| Backend | Observed result | Evidence |
| --- | --- | --- |
| Rootless Docker | Container starts with network disabled, read-only root, no capabilities, no-new-privileges, and memory/PID limits. Granted file read succeeds; writing that read-only file and creating a root file fail. Host fixture unchanged. | [container smoke](container-smoke.json) |
| Landlock ABI 7 | Child process installs a ruleset without namespace creation. Granted read succeeds; another file read and a write to the granted read-only file raise PermissionError. Host fixtures unchanged. | [Landlock smoke](landlock-smoke.json), [capability probe](capabilities.json) |

These are successful feasibility checks, not performance samples, a complete
security census, or production adapter ports. Docker's configured network isolation
was not separately attacked in this smoke test. Landlock's test handles file reads
and writes only; it does not test process, IPC, network or resource-limit controls.

A container backend and a Landlock-based backend are viable evaluation candidates.
They must get separate identities and policy/capability descriptions. Reuse the
same operation corpus and allowed/forbidden controls, measure their actual startup,
policy and execution costs, and apply the fixed repetition protocol. Do not pool
their timing samples with the old Bubblewrap cohort or claim identical isolation
semantics. A Landlock-based replacement needs explicit complementary controls for
obligations outside its supported restrictions.
