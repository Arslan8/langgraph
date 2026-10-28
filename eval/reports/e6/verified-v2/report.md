# Production verified-language versus host isolation

50 randomized paired measured calls per workload; 5 warmups and one first-use pair. Every returned value is checked against the full expected content, and every invocation has a production receipt.

Verified means actual cedar_security source admission (ManifestAdmission), runtime binding validation, Cedar authorization, grant activation, and the approved read_text API. No synthetic checker or unchecked Python baseline is used. Host means LinuxSandboxExecutor with its default Cedar policy and fresh confined worker. Both application resource grants contain only the read fixture (no resources for the constant control). Executors are reused; host workers remain fresh per invocation.

| Workload | Verified mean ms | Host mean ms | Paired added ms | Added SD ms | Added variance ms² | Host / verified |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| constant_control | 18.479 | 319.774 | 301.295 | 36.116 | 1304.375 | 17.31x |
| read_32b | 28.466 | 330.207 | 301.740 | 37.792 | 1428.204 | 11.60x |
| read_4kib | 27.830 | 331.581 | 303.751 | 34.993 | 1224.479 | 11.91x |
| read_64kib | 27.344 | 360.600 | 333.256 | 40.938 | 1675.896 | 13.19x |
| two_reads_32b | 28.130 | 330.491 | 302.361 | 35.602 | 1267.494 | 11.75x |

## Attribution and setup

Whole-call timing includes call construction, executor.invoke and receipt canonicalization. The following nested timing scopes are not additive: verified execution is its dispatcher (binding validation, grant activation, admitted function, receipt); host execution is _run_worker (activation, transport, supervision, operation, teardown). Policy is verified _authorize versus host Cedar filter. Different policy frontends mean the total difference measures these implementations, not a universal isolation tax.

| Workload | Verified policy ms | Host policy ms | Verified execution ms | Host worker ms |
| --- | ---: | ---: | ---: | ---: |
| constant_control | 18.212 | 194.815 | 0.162 | 95.353 |
| read_32b | 28.029 | 205.699 | 0.313 | 95.753 |
| read_4kib | 27.400 | 205.947 | 0.312 | 97.267 |
| read_64kib | 26.889 | 208.951 | 0.338 | 122.539 |
| two_reads_32b | 27.659 | 206.032 | 0.356 | 95.952 |

Setup is excluded from invocation latency. Ten consecutive in-process setup samples per workload include the real static admission pass; nested admission timing is separately retained.

| Workload | Verified setup mean ms | Static admission mean ms | Admission SD ms | Host setup mean ms |
| --- | ---: | ---: | ---: | ---: |
| constant_control | 7.892 | 7.502 | 0.410 | 25.393 |
| read_32b | 7.142 | 6.717 | 0.172 | 24.940 |
| read_4kib | 11.149 | 10.703 | 10.673 | 25.314 |
| read_64kib | 8.258 | 7.783 | 0.619 | 25.927 |
| two_reads_32b | 8.483 | 8.005 | 0.207 | 25.697 |

## Coverage and interpretation

The built-in verified filesystem API currently exposes read_text. The direct open/pathlib/os/mmap/ctypes and mutation programs from the 16-operation experiment are also submitted to the real checker; see admission-census.json for exact source and rejection diagnostics. These are raw-API admission probes, not evidence that all equivalent functionality is impossible through registered typed resource clients. Read workloads are ported to the approved API. A rejected operation is not assigned a runtime or counted as a successful operation.

Both modes perform equivalent computation or read identical UTF-8 bytes from the same read-only fixture. The two-read workload returns the second read in both modes. Host uses the existing JSON worker; verified mode returns directly, so serialization and process lifecycle are intentionally included in whole-call cost. The 64 KiB read is a size variant, not an additional API operation.

Trusted assumptions remain: coordinator, approved API, interpreter and stable bindings. This does not establish confinement of opaque native binaries by static verification. No model calls or durable audit sink. Single CPU affinity, cache-warm files, uncontrolled CPU frequency. SD/variance are within-run variability, not across-machine confidence.

Evidence: [raw samples](samples.jsonl), [summary](summary.json), [setup samples](setup.json), [admission census](admission-census.json), [plan](plan.json), [host before](host-before.json), [host after](host-after.json), [source archive](sources.tar.gz).

Reproduce from eval: `uv run python -m slanggraph_eval.isolation.verified --output reports/e6/verified-new --samples 50 --warmup 5`

The host additionally requires runtime/interpreter and private temporary-directory permissions, recorded in its receipts. Static admission recompiles the containing source module; its cost therefore depends on module size. Source archives freeze the measured code; post-run report wording clarifies timing and permission scope without changing measurements.
