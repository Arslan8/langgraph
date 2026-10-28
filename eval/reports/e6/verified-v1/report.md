# Production verified-language versus host isolation

50 randomized paired measured calls per workload; 5 warmups and one first-use pair. Every returned value is checked against the full expected content, and every invocation has a production receipt.

Verified means actual cedar_security source admission (ManifestAdmission), runtime binding validation, Cedar authorization, grant activation, and the approved read_text API. No synthetic checker or unchecked Python baseline is used. Host means LinuxSandboxExecutor with its default Cedar policy and fresh confined worker. Executors are reused; host workers remain fresh per invocation.

| Workload | Verified mean ms | Host mean ms | Paired added ms | Added SD ms | Added variance ms² | Host / verified |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| constant_control | 17.003 | 363.056 | 346.053 | 68.555 | 4699.772 | 21.35x |
| read_32b | 25.229 | 364.407 | 339.178 | 71.392 | 5096.776 | 14.44x |
| read_4kib | 25.764 | 366.484 | 340.720 | 69.673 | 4854.294 | 14.22x |
| read_64kib | 25.611 | 382.048 | 356.437 | 70.184 | 4925.758 | 14.92x |
| two_reads_32b | 25.338 | 363.241 | 337.904 | 72.045 | 5190.517 | 14.34x |

## Attribution and setup

Whole-call timing covers executor.invoke through returned receipt. The following nested timing scopes are not additive: verified execution is its dispatcher (binding validation, grant activation, admitted function, receipt); host execution is _run_worker (activation, transport, supervision, operation, teardown). Policy is verified _authorize versus host Cedar filter. Different policy frontends mean the total difference measures these implementations, not a universal isolation tax.

| Workload | Verified policy ms | Host policy ms | Verified execution ms | Host worker ms |
| --- | ---: | ---: | ---: | ---: |
| constant_control | 16.766 | 233.369 | 0.143 | 95.088 |
| read_32b | 24.847 | 235.426 | 0.276 | 94.984 |
| read_4kib | 25.386 | 236.162 | 0.273 | 95.937 |
| read_64kib | 25.193 | 232.675 | 0.307 | 115.077 |
| two_reads_32b | 24.910 | 234.541 | 0.323 | 94.205 |

Setup is excluded from invocation latency. Independent repeated setup samples include the real static admission pass; nested admission timing is separately retained.

| Workload | Verified setup mean ms | Static admission mean ms | Admission SD ms | Host setup mean ms |
| --- | ---: | ---: | ---: | ---: |
| constant_control | 7.570 | 7.177 | 0.219 | 26.301 |
| read_32b | 7.823 | 7.360 | 0.180 | 25.878 |
| read_4kib | 10.585 | 10.147 | 9.704 | 24.354 |
| read_64kib | 7.645 | 7.175 | 0.254 | 25.547 |
| two_reads_32b | 7.666 | 7.236 | 0.167 | 24.303 |

## Coverage and interpretation

The built-in verified filesystem API currently exposes read_text. The direct open/pathlib/os/mmap/ctypes and mutation programs from the 16-operation experiment are also submitted to the real checker; see admission-census.json for exact source and rejection diagnostics. These are raw-API admission probes, not evidence that all equivalent functionality is impossible through registered typed resource clients. Read workloads are ported to the approved API. A rejected operation is not assigned a runtime or counted as a successful operation.

Both modes perform equivalent computation or read identical UTF-8 bytes from the same read-only fixture. The two-read workload returns the second read in both modes. Host uses the existing JSON worker; verified mode returns directly, so serialization and process lifecycle are intentionally included in whole-call cost. The 64 KiB read is a size variant, not an additional API operation.

Trusted assumptions remain: coordinator, approved API, interpreter and stable bindings. This does not establish confinement of opaque native binaries by static verification. No model calls or durable audit sink. Single CPU affinity, cache-warm files, uncontrolled CPU frequency. SD/variance are within-run variability, not across-machine confidence.

Evidence: [raw samples](samples.jsonl), [summary](summary.json), [setup samples](setup.json), [admission census](admission-census.json), [plan](plan.json), [host before](host-before.json), [host after](host-after.json), [source archive](sources.tar.gz).

Reproduce from eval: `uv run python -m slanggraph_eval.isolation.verified --output reports/e6/verified-new --samples 50 --warmup 5`
