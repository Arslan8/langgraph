# Opaque native executable chain

Fixed chain: `/usr/bin/env` invokes `/bin/cat` to read a granted file. The host does not statically verify these binaries. A separately named exec-enabled seccomp profile permits process creation, exec and waiting. Filesystem confinement remains active and inherited by descendants. This profile differs from the minimal profile used in the main operation census.

100 measured calls per mode: five fresh process sessions, 20 measured calls each, after ten warmups per session. The container is reused per session; every call starts a new Python worker and its native chain.

| Mode | Mean ms | SD ms | P95 ms | Paired added ms | Session 95% CI ms |
| --- | ---: | ---: | ---: | ---: | --- |
| plain | 56.542 | 6.341 | 68.906 | — | — |
| landlock | 58.183 | 6.262 | 69.322 | 1.641 | [1.026, 2.255] |
| container | 101.248 | 3.362 | 105.646 | 44.706 | [37.920, 51.493] |

Both host profiles prevent hidden-file disclosure in all 15 checks per mode (three per session); the plain chain discloses it in all 15. All allowed timing calls succeed. The actual verified-language admission checker rejects this raw subprocess tool. No rejection latency is treated as useful execution.

Landlock constrains filesystem access across this chain; the exec-enabled Landlock profile does not enforce a process-count quota. Docker applies a PID ceiling. Neither result establishes confinement for every native program or a successful application port.

Intervals are approximate Student t intervals on five session means, with four degrees of freedom. Same-host sessions may remain correlated.

[Plan and admission diagnostic](plan.json), [raw calls](samples.jsonl), [full statistics](summary.json), [worker source](binary_worker.py.txt).
