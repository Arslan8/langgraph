# Per-operation microbenchmark

50 measured pairs per operation, 5 warm-up pairs and one first-use pair. Each invocation starts a fresh worker. All measured operations succeed in both conditions, verified by the original parent-side effect oracles.

The baseline is a plain Python subprocess; the treatment uses the production Linux executor with the default Cedar policy backend. This is not a measurement of the Pandas language sandbox or of statically verified language mode. No synthetic restricted-language comparator is included.

## Whole-call latency and incremental overhead

These times include dispatch, JSON transport, worker startup, policy and activation work, operation execution and teardown. Fixture construction, executor construction/preflight, and parent oracle/evidence persistence are outside the timer. No model calls or durable audit sink are involved.

| Operation | Python mean ms | Host mean ms | Added ms | Added SD ms | Added variance ms² | Host/Python | Host P95 ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| compute_control | 27.35 | 415.82 | 388.47 | 41.21 | 1698.07 | 15.20x | 465.99 |
| open_read | 27.71 | 419.09 | 391.39 | 34.62 | 1198.26 | 15.13x | 462.51 |
| pathlib_read | 32.96 | 413.02 | 380.06 | 48.81 | 2382.69 | 12.53x | 481.88 |
| os_read | 27.28 | 417.45 | 390.17 | 40.02 | 1601.26 | 15.30x | 458.79 |
| mmap_read | 27.61 | 420.91 | 393.30 | 38.64 | 1493.07 | 15.25x | 461.35 |
| ctypes_read | 30.32 | 409.75 | 379.43 | 43.42 | 1885.08 | 13.51x | 458.59 |
| stat_metadata | 26.53 | 421.31 | 394.78 | 41.89 | 1755.06 | 15.88x | 469.91 |
| listdir_names | 27.67 | 412.79 | 385.12 | 40.29 | 1623.54 | 14.92x | 460.17 |
| write | 26.70 | 416.33 | 389.64 | 41.48 | 1720.50 | 15.60x | 463.10 |
| append | 27.15 | 409.88 | 382.72 | 44.73 | 2000.88 | 15.10x | 475.57 |
| truncate | 27.57 | 415.87 | 388.30 | 40.25 | 1620.18 | 15.09x | 463.12 |
| create | 27.18 | 419.69 | 392.51 | 34.74 | 1206.78 | 15.44x | 466.87 |
| unlink | 27.29 | 415.49 | 388.21 | 44.82 | 2009.24 | 15.23x | 464.22 |
| mkdir | 27.42 | 410.84 | 383.42 | 42.82 | 1833.56 | 14.98x | 460.67 |
| write_4kib | 27.44 | 413.37 | 385.92 | 43.30 | 1875.14 | 15.06x | 463.81 |
| fsync | 28.16 | 426.57 | 398.41 | 34.87 | 1215.60 | 15.15x | 473.93 |

## Operation body only

The inner monotonic timer surrounds the operation statements after imports. It excludes startup, compilation, import initialization, grant preparation, policy evaluation, and result transport. It includes Python wrappers, open/close, and user-space work in those statements, so it is not pure syscall time. Sub-microsecond results can be dominated by clock overhead; the compute control is retained and no timer cost is subtracted. These worker-reported timing values are measurement telemetry, not security evidence.

| Operation | Python mean us | Host mean us | Paired added us | Paired SD us | Python median us | Host median us |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| compute_control | 0.349 | 0.391 | 0.042 | 0.095 | 0.360 | 0.405 |
| open_read | 49.415 | 51.382 | 1.967 | 9.006 | 49.108 | 52.434 |
| pathlib_read | 71.556 | 72.272 | 0.715 | 11.694 | 73.206 | 74.132 |
| os_read | 11.818 | 15.958 | 4.140 | 3.778 | 12.005 | 15.976 |
| mmap_read | 35.724 | 32.898 | -2.826 | 6.368 | 35.387 | 33.926 |
| ctypes_read | 82.799 | 100.543 | 17.744 | 15.776 | 84.626 | 102.141 |
| stat_metadata | 7.003 | 10.080 | 3.077 | 2.081 | 6.804 | 10.255 |
| listdir_names | 27.432 | 30.298 | 2.866 | 5.728 | 27.597 | 30.602 |
| write | 131.566 | 132.575 | 1.010 | 23.179 | 131.532 | 139.347 |
| append | 67.402 | 58.964 | -8.437 | 14.378 | 68.322 | 61.332 |
| truncate | 40.835 | 41.406 | 0.571 | 13.305 | 39.872 | 42.113 |
| create | 108.223 | 105.303 | -2.920 | 20.079 | 112.692 | 107.581 |
| unlink | 65.985 | 64.325 | -1.660 | 13.650 | 67.293 | 63.522 |
| mkdir | 68.484 | 78.043 | 9.559 | 22.276 | 69.853 | 78.121 |
| write_4kib | 121.148 | 111.456 | -9.692 | 35.268 | 121.740 | 115.980 |
| fsync | 790.126 | 957.085 | 166.959 | 739.428 | 685.020 | 788.058 |

## Host-stage means (ms)

The exclusive columns sum to host dispatch time. Policy means Cedar filtering; worker includes activation and supervision as well as the inner operation. Do not add the inner operation timing to worker time. Constructor/preflight time is separate and must be added only when modeling a newly constructed executor.

| Operation | Grant | Policy | Attest | Negotiate | Worker | Other invoke | Outside invoke | Constructor/preflight |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| compute_control | 7.66 | 275.20 | 7.45 | 21.73 | 102.46 | 0.36 | 0.95 | 30.07 |
| open_read | 7.59 | 275.35 | 7.57 | 22.81 | 104.44 | 0.37 | 0.97 | 29.46 |
| pathlib_read | 7.57 | 269.85 | 7.53 | 22.09 | 104.66 | 0.36 | 0.97 | 29.36 |
| os_read | 7.65 | 273.73 | 7.50 | 22.62 | 104.59 | 0.37 | 0.99 | 29.39 |
| mmap_read | 7.69 | 276.21 | 7.55 | 23.08 | 105.04 | 0.38 | 0.98 | 29.69 |
| ctypes_read | 7.53 | 267.17 | 7.49 | 23.30 | 102.94 | 0.37 | 0.95 | 29.26 |
| stat_metadata | 7.65 | 277.68 | 7.59 | 23.15 | 103.91 | 0.37 | 0.96 | 29.90 |
| listdir_names | 7.59 | 269.56 | 7.50 | 22.92 | 103.89 | 0.36 | 0.97 | 29.68 |
| write | 7.54 | 270.87 | 7.51 | 23.01 | 106.08 | 0.36 | 0.96 | 29.39 |
| append | 7.65 | 269.78 | 7.50 | 22.28 | 101.38 | 0.35 | 0.93 | 29.79 |
| truncate | 7.62 | 272.86 | 7.57 | 22.47 | 104.00 | 0.37 | 0.97 | 29.75 |
| create | 7.61 | 273.26 | 7.51 | 23.74 | 106.24 | 0.36 | 0.97 | 29.58 |
| unlink | 7.52 | 272.60 | 7.54 | 22.89 | 103.62 | 0.36 | 0.96 | 29.08 |
| mkdir | 7.57 | 266.71 | 7.49 | 22.69 | 105.05 | 0.37 | 0.97 | 29.38 |
| write_4kib | 7.63 | 272.22 | 7.48 | 22.28 | 102.46 | 0.36 | 0.94 | 29.93 |
| fsync | 7.71 | 281.25 | 7.57 | 23.21 | 105.48 | 0.37 | 0.97 | 29.77 |

## Scope, sizes, and unsupported operations

Read fixtures contain a 32-byte random token. The write case replaces a 32-byte file with a 6-byte marker; append adds that marker; truncate sets length to zero; create writes a 6-byte marker. write_4kib writes 4096 bytes. fsync measures open, 6-byte write, flush, fsync and close together. Directory listing returns the small fresh output fixture. Reads use a visible read-only file; permitted mutations use a writable subtree. Exact sources are in plan.json.

The current minimal host backend does not support useful child-exec chains or network service operations. Rename, links and metadata mutation are also outside its allowed syscall set. Their rejection times are not reported as successful-operation overhead. SQLite authorization and static-verification cost remain separate unmeasured workloads.

Order is shuffled within each round; one logical CPU is used by parent and children. Host configuration/load is captured before and after the batch. OS caches and CPU frequency are uncontrolled; these newly created files are cache-warm, not a storage-throughput benchmark. SD/variance describe within-run jitter. Negative body deltas do not establish a host speedup. Different mount topology, scheduling and allocation can affect body time. No confidence claim across tasks, machines or storage devices is made.

Raw data: [samples.jsonl](samples.jsonl), [summary.json](summary.json), [plan.json](plan.json), [host capture](host-before.json), [exact source archive](sources.tar.gz). Statistics retain full precision including median, P95, min/max, SD and variance for every timing scope.

```sh
cd eval
uv run python -m slanggraph_eval.isolation.operations \
  --samples 50 --warmup 5 --output reports/e6/operations-new
```
