# Historical runtime observations — preliminary

These are recorded observations, not accepted primary performance results. They have not been replicated under the fixed session protocol. The plain-Python experiments do not measure verified-language isolation. Ratios describe only their named workload and cohort; they do not establish a general speed advantage or a pure kernel-isolation cost. Raw observations and actual sample counts are preserved for audit.

## 4. Application runtime overhead and variance

These costs come from replaying the same recorded, successful February computation and inputs through A/B/C—not from E6 or a no-op. Each configuration has 100 measured calls, ten warmups and one first-use call in one session; A/B/C order rotates by round. Fixture setup and integration initialization are excluded; dispatch, subprocess/host execution, synchronous audit, and integration evidence IO are included. Every result is checked to equal 120. Raw samples and nested spans were recomputed and checked against the saved summaries.

| Configuration | n | Mean ms | SD ms | Variance ms² | Median ms | P95 ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| A | 100 | 267.19 | 6.84 | 46.80 | 265.00 | 280.56 |
| B | 100 | 545.54 | 31.53 | 993.96 | 544.34 | 583.76 |
| C | 100 | 930.93 | 42.95 | 1844.46 | 916.64 | 1010.42 |

| Paired contrast | Mean increment ms | SD ms | Variance ms² | Ratio of means |
| --- | ---: | ---: | ---: | ---: |
| B-A | 278.35 | 32.91 | 1083.09 | 2.042x |
| C-A | 663.74 | 42.55 | 1810.20 | 3.484x |
| C-B | 385.39 | 54.98 | 3022.34 | 1.706x |

C adds 663.74 ms relative to A (248.4% overhead). C versus B adds 385.39 ms.

### Where the application overhead comes from

Historical replay uses 100 measured calls per configuration; its audit diagnostic uses 20. These are separate single-session cohorts. Stage statistics remain in the raw summaries; no new session intervals exist.

[Replay statistics](../results/pandas-runtime-20261026-v1/summary.json)

| Replay configuration / measured scope | Mean ms | SD ms |
| --- | ---: | ---: |
| A / upstream_subprocess_ms | 267.11 | 6.84 |
| B / upstream_subprocess_ms | 267.03 | 5.22 |
| C / _compile_grant_ms | 20.56 | 2.22 |
| C / _run_worker_ms | 325.58 | 18.74 |
| C / invoke_ms | 614.54 | 20.12 |
| B / audit write (separate diagnostic) | 273.94 | 32.12 |
| C / audit write (separate diagnostic) | 274.52 | 8.96 |

Historical pilot only: five full-workflow clean repetitions include model inference, setup, strace, and the oracle. These are separately reported in seconds:

| Condition | n | Mean s | SD s | Variance s² | Median s | Min-max s |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| A | 5 | 12.777 | 1.410 | 1.989 | 12.236 | 11.986-15.293 |
| B | 5 | 12.725 | 0.195 | 0.038 | 12.736 | 12.437-12.979 |
| C | 5 | 15.354 | 0.118 | 0.014 | 15.298 | 15.243-15.543 |

Full-workflow C/A is 1.202x (+20.2%), with paired increment 2.577 s (SD 1.446 s). This is an observed total-workflow difference, not isolated enforcement overhead. The first A run includes post-restart model loading and is retained. Five runs of one task do not estimate across-application variance. [Raw replay](../results/pandas-runtime-20261026-v1/), [audit diagnostic](../results/pandas-runtime-audit-profile-20261026-v1/), and [full-workflow cohort](../results/pandas-e2e-repetitions-20261026-attempt2/) remain separate. Thirty earlier server-unavailable launches are retained as infrastructure failures, not as successful defenses.

## 5. Matched backend overhead: new E6 runtime experiment

The previous median over mixed successes and rejections was not a valid overhead estimate. This new experiment uses only three successful workloads: arithmetic, canary-file read, and 4 KiB write. For each workload/condition there are 100 measured calls and ten warmups in one session, plus a first-use call. Order is shuffled within each paired round with seed 20261026. Each call starts a fresh worker; executor construction/preflight is outside the dispatch timer and recorded separately. No model or durable audit sink is involved. The same positive oracle must pass for every timing sample.

| Workload | Condition | n | Mean ms | SD ms | Variance ms² | Median ms | P95 ms |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| arithmetic | trusted | 100 | 28.14 | 3.18 | 10.12 | 28.85 | 31.15 |
| arithmetic | language_helper | 100 | 28.14 | 2.98 | 8.89 | 28.99 | 31.59 |
| arithmetic | host | 100 | 430.63 | 50.82 | 2582.42 | 445.93 | 480.34 |
| arithmetic | host_language_helper | 100 | 428.47 | 50.30 | 2530.32 | 445.78 | 476.11 |
| allowed_read | trusted | 100 | 27.72 | 3.52 | 12.37 | 28.97 | 31.15 |
| allowed_read | language_helper | 100 | 28.10 | 3.43 | 11.74 | 29.09 | 31.27 |
| allowed_read | host | 100 | 433.31 | 45.59 | 2078.02 | 447.36 | 478.07 |
| allowed_read | host_language_helper | 100 | 431.74 | 49.10 | 2411.28 | 448.03 | 481.50 |
| allowed_small_file | trusted | 100 | 27.92 | 3.50 | 12.27 | 29.12 | 31.96 |
| allowed_small_file | language_helper | 100 | 28.16 | 3.26 | 10.60 | 29.09 | 31.50 |
| allowed_small_file | host | 100 | 433.61 | 52.87 | 2795.11 | 447.99 | 491.47 |
| allowed_small_file | host_language_helper | 100 | 431.19 | 49.51 | 2451.25 | 446.89 | 481.22 |

| Workload | Paired contrast | Increment ms | SD ms | Variance ms² | Overhead |
| --- | --- | ---: | ---: | ---: | ---: |
| arithmetic | host-trusted | 402.49 | 48.52 | 2354.13 | 1430.2% |
| arithmetic | host_language_helper-language_helper | 400.33 | 48.69 | 2370.87 | 1422.6% |
| arithmetic | host_language_helper-host | -2.16 | 34.06 | 1160.10 | -0.5% |
| allowed_read | host-trusted | 405.59 | 43.06 | 1854.05 | 1463.4% |
| allowed_read | host_language_helper-language_helper | 403.64 | 46.73 | 2183.56 | 1436.6% |
| allowed_read | host_language_helper-host | -1.57 | 32.98 | 1087.41 | -0.4% |
| allowed_small_file | host-trusted | 405.69 | 50.68 | 2568.25 | 1452.9% |
| allowed_small_file | host_language_helper-language_helper | 403.03 | 47.80 | 2284.60 | 1431.3% |
| allowed_small_file | host_language_helper-host | -2.43 | 31.65 | 1001.60 | -0.6% |

### Measured source of backend cost

The following exclusive partition sums to the host dispatch total. Each stage is measured by wrapping the production method without changing enforcement. Policy is the CedarPolicyBackend.filter span: the production backend writes policy/request files, validates with the Cedar CLI, and launches an authorize command for each evaluated rule. This is policy-engine/serialization/process cost, not kernel sandbox overhead. See [the measured implementation](../../libs/prebuilt/langgraph/prebuilt/security/cedar.py). Other-invoke is an arithmetic residual, not a named measured mechanism. Worker includes launch, confinement activation, execution, result handling and teardown. The combined language/host stage results are retained in summary.json.

| Workload | Stage | Mean ms | SD ms | Share of dispatch |
| --- | --- | ---: | ---: | ---: |
| arithmetic | attest | 7.621 | 0.423 | 1.8% |
| arithmetic | grant | 7.764 | 0.432 | 1.8% |
| arithmetic | negotiate | 23.643 | 6.990 | 5.5% |
| arithmetic | other_invoke | 0.361 | 0.053 | 0.1% |
| arithmetic | outside_invoke | 0.949 | 0.149 | 0.2% |
| arithmetic | policy | 285.193 | 34.782 | 66.2% |
| arithmetic | worker | 105.096 | 12.909 | 24.4% |
| allowed_read | attest | 7.604 | 0.383 | 1.8% |
| allowed_read | grant | 7.804 | 0.494 | 1.8% |
| allowed_read | negotiate | 23.495 | 4.041 | 5.4% |
| allowed_read | other_invoke | 0.370 | 0.047 | 0.1% |
| allowed_read | outside_invoke | 1.049 | 0.361 | 0.2% |
| allowed_read | policy | 285.139 | 31.127 | 65.8% |
| allowed_read | worker | 107.848 | 12.597 | 24.9% |
| allowed_small_file | attest | 7.672 | 0.592 | 1.8% |
| allowed_small_file | grant | 7.776 | 0.449 | 1.8% |
| allowed_small_file | negotiate | 23.349 | 4.295 | 5.4% |
| allowed_small_file | other_invoke | 0.372 | 0.056 | 0.1% |
| allowed_small_file | outside_invoke | 1.001 | 0.257 | 0.2% |
| allowed_small_file | policy | 286.062 | 36.010 | 66.0% |
| allowed_small_file | worker | 107.382 | 14.616 | 24.8% |

For the matched read workload, policy filtering accounts for 285.14 ms (65.8%) of host dispatch; worker execution/supervision accounts for 107.85 ms (24.9%). The dominant measured backend cost is policy filtering, not simply worker launch. Across these tiny operations host latency is nearly constant, so fixed per-call work dominates useful computation.

Policy and worker spans also have the largest stage-level SDs. Their variances must not be added: correlated timing fluctuations contribute covariance. Paired-overhead SD is computed from same-round differences. Small negative host+helper versus host differences are within variation and do not establish a speedup. This pinned-CPU, instrumented cohort differs from the earlier unrestricted-affinity security census; its timings are not pooled with the old mixed-outcome medians.

| Workload | Host setup/preflight mean ms | SD ms |
| --- | ---: | ---: |
| arithmetic | 30.52 | 2.51 |
| allowed_read | 30.72 | 2.46 |
| allowed_small_file | 30.61 | 2.93 |

[Runtime plan](e6/runtime-v1/plan.json), [raw samples](e6/runtime-v1/samples.jsonl), [derived statistics](e6/runtime-v1/summary.json), and [source archive](e6/runtime-v1/sources.tar.gz) identify the exact experiment. Small instrumentation costs are included; no uninstrumented speedup is inferred. These are sequential within-host timing observations, not independent tasks; SD/variance describe observed jitter. No unsupported IID confidence interval or population-level ASR is reported.

![Security reachability and paired runtime distributions](evaluation-summary.png)

## 6. Per-operation microbenchmarks

Historical backend microbenchmark: 16 operation/API variants, 50 measured pairs each, five warmups and one first-use pair in one session. The baseline is plain Python, not verified language execution.

| Operation | Python mean ms | Host mean ms | Paired overhead ms | Overhead SD ms | Overhead variance ms² | Host/Python |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| compute_control | 27.35 | 415.82 | 388.47 | 41.21 | 1698.07 | 15.20x |
| open_read | 27.71 | 419.09 | 391.39 | 34.62 | 1198.26 | 15.13x |
| pathlib_read | 32.96 | 413.02 | 380.06 | 48.81 | 2382.69 | 12.53x |
| os_read | 27.28 | 417.45 | 390.17 | 40.02 | 1601.26 | 15.30x |
| mmap_read | 27.61 | 420.91 | 393.30 | 38.64 | 1493.07 | 15.25x |
| ctypes_read | 30.32 | 409.75 | 379.43 | 43.42 | 1885.08 | 13.51x |
| stat_metadata | 26.53 | 421.31 | 394.78 | 41.89 | 1755.06 | 15.88x |
| listdir_names | 27.67 | 412.79 | 385.12 | 40.29 | 1623.54 | 14.92x |
| write | 26.70 | 416.33 | 389.64 | 41.48 | 1720.50 | 15.60x |
| append | 27.15 | 409.88 | 382.72 | 44.73 | 2000.88 | 15.10x |
| truncate | 27.57 | 415.87 | 388.30 | 40.25 | 1620.18 | 15.09x |
| create | 27.18 | 419.69 | 392.51 | 34.74 | 1206.78 | 15.44x |
| unlink | 27.29 | 415.49 | 388.21 | 44.82 | 2009.24 | 15.23x |
| mkdir | 27.42 | 410.84 | 383.42 | 42.82 | 1833.56 | 14.98x |
| write_4kib | 27.44 | 413.37 | 385.92 | 43.30 | 1875.14 | 15.06x |
| fsync | 28.16 | 426.57 | 398.41 | 34.87 | 1215.60 | 15.15x |

The inner timer separately measures operation statements after imports, excluding compilation, startup, policy evaluation and transport. It includes Python wrappers, open/close and user-space work; it is not pure syscall time. [Body timing, stage breakdown and scope](e6/operations-v1/report.md) and [full-precision CSV](e6/operations-v1/operations.csv) accompany the [raw samples](e6/operations-v1/samples.jsonl). No denial is passed off as a faster successful operation; unsupported child-exec chains, network operations and metadata mutations are listed explicitly in the report.

![Per-operation overhead and body time](e6/operations-v1/operations.png)

## 6a. Actual source-verified language execution versus Linux

Historical production comparison: 50 measured pairs per workload after five warmups in one session. Actual source admission, runtime binding checks and Cedar authorization are retained. Setup uses ten repeats per workload. These measurements have not yet been rerun under the new protocol.

| Workload | Verified mean ms | Host mean ms | Paired added ms | Added SD ms | Host/verified |
| --- | ---: | ---: | ---: | ---: | ---: |
| constant_control | 18.479 | 319.774 | 301.295 | 36.116 | 17.31x |
| read_32b | 28.466 | 330.207 | 301.740 | 37.792 | 11.60x |
| read_4kib | 27.830 | 331.581 | 303.751 | 34.993 | 11.91x |
| read_64kib | 27.344 | 360.600 | 333.256 | 40.938 | 13.19x |
| two_reads_32b | 28.130 | 330.491 | 302.361 | 35.602 | 11.75x |

[Full production comparison, static admission costs and policy/execution breakdown](e6/verified-v2/report.md). The two executors have different policy frontends; their total difference is implementation overhead, not a pure kernel isolation tax. Raw API probes from the previous 16-operation experiment are submitted to the actual verifier and rejection diagnostics are saved. Rejected operations receive no successful-operation runtime. Broad typed-resource ports and a verified-mode application port remain necessary for broader claims.

