# Security, ports, exposure reduction, and runtime overhead

This report separates application evidence, deterministic operation coverage, and timing experiments. It supersedes the E6-only narrative as the evaluation entry point. The evidence supports one experimental protected application integration, two further baseline adaptations, and five blocked candidates; it does not support eight completed ports.

The fixed timing protocol is completed for the new verified-language, Landlock, and rootless-container comparison: 100 measured calls per workload/mode across five process sessions. The 16-operation ablation and Pandas computation replay use the same counts. Historical Bubblewrap timings remain separate and preliminary.

## 1. Experimental configurations and host

Application A retains the released Pandas Python sandbox; B adds a ToolNode authorization boundary; C adds the Linux executor to that boundary while retaining the upstream sandbox program. E6 uses separate synthetic trusted/restricted-language conditions. The two sets must not be equated or pooled.

| Host field | Measured value |
| --- | --- |
| CPU | Intel(R) Xeon(R) w5-3435X; 1 socket; 16 cores/socket; 32 logical CPUs |
| RAM | 62.25 GiB |
| OS/kernel | Linux-6.17.0-1033-oem-x86_64-with-glibc2.39 |
| E6 runtime Python | 3.12.3 (main, Aug 31 2026, 10:18:26) [GCC 13.3.0] |
| Application Python | 3.13.11 (Pandas/SQL); 3.12.3 (Notebook) |
| GPUs | 2 x NVIDIA RTX A4000, 16,376 MiB each; driver 580.178.04 |
| bubblewrap | bubblewrap 0.9.0 |
| Timing CPU affinity | [0] (inherited by workers) |
| Evidence disk | ext4 on /dev/sda2, rotating ST12000NM000J |
| Model | local Ollama 0.32.14; Pandas qwen3:8b, Q4_K_M, temperature 0 |
| Benchmark clock | perf_counter_ns; monotonic wall duration |
| OS cache / CPU frequency | uncontrolled; no cache flush or fixed frequency |

[Current E6 host capture](e6/runtime-v1/host-before.json) records CPU, memory, affinity, load, block device, filesystem, GPU, and clock details. [Application host capture](../results/pandas-runtime-20261026-v1/host.json) belongs to its own cohort. The older HARDWARE.md describes an earlier kernel and must not override these run-level records. Runtime experiments make no model calls; GPUs are relevant only to application inference. The machine was not exclusively reserved; variation is measured, not assumed absent.

## 2. Port descriptions and evaluation scope

| Application / pin | Original execution and adaptation | Measured status / remaining boundary |
| --- | --- | --- |
| [Pandas](../apps/pandas/README.md), 4ffeb7f38178 | Original PandasDataAnalyst, wrangling and visualization graphs; local provider, fixture and backend adapter; B inserts dispatch, C runs original sandbox program in Linux worker | One experimental A/B/C integration; 1/3 original clean tasks succeeds in each condition; repeated February task succeeds. Parent/model/UI effects excluded. |
| [SQL](../apps/sql/README.md), 4ffeb7f38178 | Original SQLDatabaseAgent.ainvoke_agent, SQLAlchemy connection and safe_mode; synthetic sales/payroll DB | 3/3 baseline tasks pass; no protected port. Schema sampling and arbitrary SQL need mediation beyond the fixed-record broker. |
| [Notebook](../apps/notebook/README.md), a0f6f3081ae0 | Original ingestion API/worker, source_chat_graph, native Ollama and dedicated SurrealDB | 1/1 baseline smoke; no protected port. API/worker/DB authority is outside client confinement. |
| [Email](../apps/email/README.md), 758db7174223 | Archived Executive AI Assistant; Gmail integration | No completed smoke/port; dependency and dedicated-account blockers. |
| [Research](../apps/research/README.md), 1b7d2e80db9f | Archived Open Deep Research; search and structured model calls | No completed smoke/port; reproducible search/local model route missing. |
| [Coding](../apps/coding/README.md), ff4e713c094c | Open SWE, remote execution and GitHub/MDA services | No completed smoke/port; dedicated services and execution-host instrumentation missing. |
| [Newspaper](../apps/newspaper/README.md), 1c447b5672dd | GPT Newspaper search, writing and output workflow | No completed smoke/port; search service or frozen contract-preserving fixture missing. |
| [Finance](../apps/finance/README.md), 6c41ae8cf5fb | Historical LangGraph workflow selected after upstream removal | No verified smoke/port; provider fixture/local execution incomplete; no trading. |

Full immutable revisions and installation evidence are in the [intake ledger](../apps.csv). Pandas C replaces the outer subprocess launch because the host profile prohibits child creation; it retains AST/import/builtin/network checks and JSON transport. The original upstream files are unchanged, but adapters are substantive work, not zero-cost ports. SQL and Notebook retain their original graphs; replacing either with a demo broker would not constitute a faithful port. Engineering hours were not recorded. No overhead or security reduction is assigned to an unported app.

## 3. Security evaluation and exposure reduction

For a fixed eligible probe set P, observed reachability is the number of distinct probes producing the forbidden effect. Reduction is (baseline reachability - protected reachability) / baseline reachability. Repetitions test stability; they do not increase the number of independent probes.

This section retains historical application and E6 evidence. The current Landlock/container census and production verified-language controls are in Section 4; the historical host results below are not measurements of those adapters.

| Evidence / denominator | Baseline | Protected | Exposure reduction and interpretation |
| --- | ---: | ---: | --- |
| Pandas controlled effects: two narrow reads + read-only dataset overwrite | A 3/3; B 3/3 | C 0/3 | 100% observed probe-reachability reduction for C; 0% for B |
| Historical E6 forbidden operation/surface cases | trusted 49/49; helper 49/49 | host 0/49; combined 0/49 | 100% observed reduction; explicit denial established for 45/49 cases |
| Pandas frozen CSV injection, five runs/configuration | 0/5 effects, 0 attempts | 0/5 effects, 0 attempts | Enforcement success and relative reduction undefined: no eligible attempts |
| E1 static headline sink projection | 8 exposed | host-model 4; composed-model 0 | 50% / 100% projected reduction; not measured runtime enforcement |

The [application controlled-effect evidence](application-pilot.md) preserves the legitimate February computation while adding one operation. Narrow/broad supplementary read policies supply a matched permitted control. Private-/tmp shadow writes are reported as host containment, not as proof of a guest-wide output-only policy. The three-probe denominator excludes that unsupported restriction. The four [dispatch checks](../results/pandas-dispatch-20261026-v1/summary.json) distinguish authorization from containment of an already-authorized tool; B/C each pass 4/4.

The historical E6 cohort exercises filesystem APIs, metadata, aliases, native/dynamic code, environment, processes, loopback networking, SQLite, and a bounded file-size limit on hidden, read-only and writable surfaces. All 49 baseline effects reproduce in all three repetitions. Both host conditions preserve 30/30 positive controls. Of 147 forbidden trials per host condition, 135 have an explicit denial, six generic SQLite errors, and six empty/absent results. The last 12 are not credited as explicit runtime blocking. The synthetic direct-language frontend rejects 27/30 controls; its zero effects are not evidence of useful complete mediation. See the [per-case matrix](e6/isolation-v1/report.md) and [protocol](../ISOLATION.md).

[E1](e1/exposure.md) projects adapter capabilities onto a static sink report. In particular, its host model includes capabilities that must not be attributed to the measured Linux filesystem adapter. Static sink counts, observed operation effects, and prompt-injection outcomes are different metrics.

## 4. Completed alternative-backend evaluation

Completed fixed protocol: **100 measured calls per workload and mode**, across five fresh benchmark-process sessions (20 measured calls each). Each session has ten excluded warmups and one separately retained first-use call. Calls and modes are shuffled within matched rounds. All positive timing results must pass the parent oracle. No failed calls are silently replaced.

[Comparison figure](alternatives-v2/comparison.pdf), [operation figure](alternatives-v2/operations.pdf), and [full-precision CSV](alternatives-v2/timings.csv).

### Configurations and scope

- **verified:** actual cedar_security / ManifestAdmission source checking at setup; production Cedar object authorization, binding validation and grant-checked read_text at invocation.
- **landlock:** an evaluation adapter applies Landlock filesystem rules, the production minimal seccomp allowlist, cleared environment and process resource limits to a fresh Python child.
- **container:** an evaluation adapter uses rootless Docker with a read-only root, no network, no capabilities, no-new-privileges, explicit read-only/read-write mounts, and memory/PID ceilings. Each invocation starts a fresh Python process inside a persistent, grant-specific container and applies the same minimal seccomp allowlist. Container creation and teardown are separately timed.
- **plain:** fresh Python child with resource ceilings for the raw-operation and application ablation; it is not the verified-language comparator.

The two host adapters are evaluation implementations, **not** the production Bubblewrap executor. Their records are parent observations and worker telemetry, not signed production activation receipts. The paired read comparison uses the same production Cedar authorizer in all three modes; its grants are translated into the allowed filesystem paths. The raw-operation and application experiments measure execution with explicit fixture/runtime grants and exclude Cedar authorization.

### Verified-language versus host: matched useful work

Constant return, three read sizes, and a two-read workload are supported in all modes. Sizes are workload variants, not distinct API operations. Static admission is outside the invocation timer and measured separately. Whole-call timing includes common authorization plus execution/transport and validation. It excludes fixture reset and container lifecycle.

| Workload / mode | Mean ms | SD ms | Median ms | P95 ms | Added ms | Paired SD ms | Session 95% CI ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| constant_control / verified | 13.702 | 2.995 | 12.449 | 20.208 | — | — | — |
| constant_control / landlock | 67.454 | 7.467 | 65.228 | 85.414 | 53.751 | 6.275 | [49.918, 57.585] |
| constant_control / container | 114.680 | 11.173 | 111.070 | 139.402 | 100.977 | 10.161 | [93.927, 108.028] |
| read_32b / verified | 20.456 | 3.272 | 19.721 | 27.273 | — | — | — |
| read_32b / landlock | 74.770 | 9.132 | 71.497 | 95.875 | 54.313 | 8.006 | [49.660, 58.967] |
| read_32b / container | 122.623 | 13.218 | 117.574 | 149.701 | 102.166 | 11.938 | [91.772, 112.561] |
| read_4kib / verified | 20.528 | 3.609 | 19.446 | 27.847 | — | — | — |
| read_4kib / landlock | 74.270 | 7.694 | 71.971 | 91.878 | 53.741 | 6.387 | [49.705, 57.777] |
| read_4kib / container | 122.826 | 12.980 | 117.760 | 151.533 | 102.297 | 11.533 | [94.741, 109.854] |
| read_64kib / verified | 20.253 | 3.695 | 18.837 | 29.013 | — | — | — |
| read_64kib / landlock | 75.646 | 8.662 | 72.956 | 94.453 | 55.393 | 7.024 | [50.162, 60.623] |
| read_64kib / container | 123.434 | 13.094 | 118.357 | 145.813 | 103.180 | 12.347 | [94.398, 111.963] |
| two_reads_32b / verified | 20.096 | 3.444 | 18.802 | 26.711 | — | — | — |
| two_reads_32b / landlock | 75.079 | 9.173 | 71.545 | 93.968 | 54.983 | 7.633 | [49.777, 60.188] |
| two_reads_32b / container | 123.018 | 13.363 | 118.188 | 144.278 | 102.922 | 11.938 | [93.641, 112.202] |

### Where the time goes

| Workload / mode | Policy mean ms | Execution/transport mean ms |
| --- | ---: | ---: |
| constant_control / verified | 13.560 | 0.140 |
| constant_control / landlock | 13.340 | 54.111 |
| constant_control / container | 13.117 | 101.560 |
| read_32b / verified | 20.191 | 0.264 |
| read_32b / landlock | 20.568 | 54.200 |
| read_32b / container | 20.185 | 102.435 |
| read_4kib / verified | 20.256 | 0.270 |
| read_4kib / landlock | 20.346 | 53.921 |
| read_4kib / container | 20.299 | 102.525 |
| read_64kib / verified | 19.965 | 0.286 |
| read_64kib / landlock | 20.106 | 55.538 |
| read_64kib / container | 20.220 | 103.211 |
| two_reads_32b / verified | 19.796 | 0.298 |
| two_reads_32b / landlock | 20.320 | 54.756 |
| two_reads_32b / container | 20.072 | 102.943 |

| Tool workload | Admission n | Admission mean ms | Admission SD ms |
| --- | ---: | ---: | ---: |
| constant_control | 100 | 9.813 | 7.244 |
| read_32b | 100 | 9.776 | 6.741 |
| read_4kib | 100 | 8.134 | 0.614 |
| read_64kib | 100 | 7.646 | 1.255 |
| two_reads_32b | 100 | 7.888 | 1.093 |

### Per-operation microbenchmarks

Sixteen operation/API variants, 100 measured calls per mode. These compare a plain process against the two host adapters. The current built-in verified file API exposes read_text; the real admission checker rejects the raw-API programs (diagnostics are saved), so rejected programs are never assigned a successful-operation timing. Registered typed-resource ports would be needed for a broader verified-language operation comparison.

| Workload / mode | Mean ms | SD ms | Median ms | P95 ms | Added ms | Paired SD ms | Session 95% CI ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| append / plain | 57.779 | 7.636 | 52.989 | 68.029 | — | — | — |
| append / landlock | 59.082 | 7.906 | 54.529 | 69.014 | 1.303 | 6.610 | [-1.321, 3.927] |
| append / container | 108.733 | 9.765 | 103.535 | 121.449 | 50.954 | 7.204 | [47.833, 54.075] |
| compute_control / plain | 57.418 | 7.086 | 53.744 | 67.457 | — | — | — |
| compute_control / landlock | 58.848 | 7.308 | 54.726 | 68.957 | 1.429 | 4.561 | [0.326, 2.532] |
| compute_control / container | 107.481 | 9.618 | 101.825 | 120.213 | 50.062 | 7.529 | [47.635, 52.490] |
| create / plain | 57.434 | 6.846 | 53.917 | 67.494 | — | — | — |
| create / landlock | 58.744 | 7.442 | 54.610 | 69.187 | 1.310 | 4.812 | [0.094, 2.526] |
| create / container | 108.449 | 11.421 | 102.143 | 120.919 | 51.015 | 9.228 | [49.293, 52.737] |
| ctypes_read / plain | 57.646 | 7.174 | 53.588 | 67.634 | — | — | — |
| ctypes_read / landlock | 58.230 | 7.295 | 54.379 | 69.178 | 0.584 | 5.801 | [-1.856, 3.024] |
| ctypes_read / container | 108.111 | 10.175 | 102.709 | 121.467 | 50.464 | 6.902 | [47.176, 53.752] |
| fsync / plain | 58.647 | 7.136 | 54.159 | 69.159 | — | — | — |
| fsync / landlock | 59.413 | 7.483 | 55.566 | 70.202 | 0.766 | 5.435 | [-0.773, 2.305] |
| fsync / container | 107.944 | 9.434 | 102.356 | 121.869 | 49.297 | 5.422 | [47.865, 50.728] |
| listdir_names / plain | 57.516 | 7.493 | 53.184 | 68.046 | — | — | — |
| listdir_names / landlock | 58.892 | 7.319 | 54.513 | 69.420 | 1.376 | 4.482 | [0.071, 2.681] |
| listdir_names / container | 107.065 | 9.459 | 100.780 | 120.619 | 49.549 | 5.975 | [47.071, 52.027] |
| mkdir / plain | 57.891 | 7.336 | 53.457 | 68.441 | — | — | — |
| mkdir / landlock | 58.227 | 7.352 | 53.913 | 69.217 | 0.335 | 5.380 | [-1.454, 2.125] |
| mkdir / container | 107.793 | 9.961 | 101.444 | 120.580 | 49.902 | 6.563 | [46.504, 53.299] |
| mmap_read / plain | 58.063 | 7.478 | 53.671 | 68.882 | — | — | — |
| mmap_read / landlock | 58.233 | 7.402 | 53.841 | 68.848 | 0.170 | 5.489 | [-1.235, 1.575] |
| mmap_read / container | 107.605 | 9.561 | 102.186 | 120.576 | 49.542 | 5.668 | [47.865, 51.218] |
| open_read / plain | 58.423 | 7.575 | 53.707 | 68.415 | — | — | — |
| open_read / landlock | 58.454 | 7.485 | 53.810 | 68.742 | 0.031 | 5.418 | [-1.082, 1.145] |
| open_read / container | 107.883 | 9.593 | 102.311 | 121.534 | 49.460 | 6.030 | [46.852, 52.068] |
| os_read / plain | 57.515 | 7.380 | 53.342 | 68.395 | — | — | — |
| os_read / landlock | 58.875 | 7.510 | 54.126 | 69.568 | 1.360 | 6.275 | [-0.686, 3.406] |
| os_read / container | 108.945 | 12.122 | 102.939 | 121.652 | 51.430 | 10.259 | [47.712, 55.148] |
| pathlib_read / plain | 61.166 | 7.840 | 56.554 | 72.448 | — | — | — |
| pathlib_read / landlock | 61.530 | 7.581 | 57.288 | 72.751 | 0.364 | 4.732 | [-0.568, 1.297] |
| pathlib_read / container | 111.554 | 10.140 | 105.122 | 125.762 | 50.388 | 6.176 | [47.838, 52.938] |
| stat_metadata / plain | 57.227 | 7.338 | 53.342 | 68.400 | — | — | — |
| stat_metadata / landlock | 57.847 | 7.290 | 53.979 | 68.571 | 0.620 | 5.246 | [-0.290, 1.530] |
| stat_metadata / container | 108.037 | 9.671 | 101.948 | 120.418 | 50.810 | 6.891 | [48.320, 53.300] |
| truncate / plain | 57.754 | 7.744 | 53.060 | 68.468 | — | — | — |
| truncate / landlock | 57.630 | 7.289 | 53.609 | 68.771 | -0.123 | 6.547 | [-1.066, 0.819] |
| truncate / container | 106.941 | 9.452 | 101.535 | 120.106 | 49.188 | 7.424 | [47.300, 51.075] |
| unlink / plain | 58.000 | 7.173 | 53.794 | 67.986 | — | — | — |
| unlink / landlock | 58.659 | 7.336 | 54.313 | 68.712 | 0.659 | 4.124 | [-0.324, 1.642] |
| unlink / container | 107.606 | 9.136 | 102.569 | 119.943 | 49.607 | 5.380 | [47.539, 51.674] |
| write / plain | 58.526 | 7.484 | 54.277 | 68.030 | — | — | — |
| write / landlock | 59.003 | 7.573 | 54.797 | 68.964 | 0.477 | 5.367 | [-1.499, 2.454] |
| write / container | 107.776 | 9.199 | 102.928 | 120.228 | 49.250 | 5.515 | [48.660, 49.840] |
| write_4kib / plain | 57.802 | 7.375 | 53.662 | 68.624 | — | — | — |
| write_4kib / landlock | 57.892 | 7.229 | 53.752 | 68.566 | 0.090 | 4.037 | [-1.090, 1.270] |
| write_4kib / container | 107.693 | 9.881 | 101.344 | 120.861 | 49.891 | 5.533 | [48.345, 51.438] |

### Operation body only

The inner timer surrounds the original operation statements after imports. It excludes worker startup, policy, activation and transport; it is not pure syscall time.

| Operation | Plain mean µs | Landlock mean µs | Container mean µs |
| --- | ---: | ---: | ---: |
| append | 53.179 | 53.701 | 51.631 |
| compute_control | 0.243 | 0.245 | 0.320 |
| create | 79.991 | 80.443 | 80.440 |
| ctypes_read | 86.909 | 67.099 | 71.884 |
| fsync | 833.258 | 795.117 | 821.432 |
| listdir_names | 24.812 | 21.887 | 22.932 |
| mkdir | 54.377 | 51.024 | 56.953 |
| mmap_read | 27.199 | 28.072 | 32.058 |
| open_read | 40.668 | 44.008 | 46.497 |
| os_read | 10.718 | 10.620 | 12.677 |
| pathlib_read | 62.648 | 63.341 | 64.501 |
| stat_metadata | 6.190 | 5.205 | 9.361 |
| truncate | 30.414 | 27.622 | 32.548 |
| unlink | 50.677 | 47.626 | 53.370 |
| write | 106.228 | 103.728 | 113.259 |
| write_4kib | 89.504 | 86.810 | 94.013 |

### Application replay

This runs the actual recorded Pandas February computation, original input, and unmodified upstream sandbox runner. The independent expected result is total_sales=120. All modes use the pinned application Python 3.13 runtime and dependencies. Plain retains the upstream sandbox; Landlock/container add host restrictions around that same sandbox program. This is a computation replay, not a model-driven full workflow or a verified-language application port. No model calls, ToolNode dispatch, durable audit sink, or Cedar authorization are included.

| Workload / mode | Mean ms | SD ms | Median ms | P95 ms | Added ms | Paired SD ms | Session 95% CI ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| pandas_february / plain | 352.320 | 39.197 | 346.444 | 406.212 | — | — | — |
| pandas_february / landlock | 353.525 | 39.857 | 355.437 | 403.961 | 1.204 | 25.442 | [-6.621, 9.030] |
| pandas_february / container | 507.871 | 40.053 | 519.650 | 567.372 | 155.551 | 27.874 | [148.937, 162.165] |

| Application mode | Worker activation ms | Application body ms | Startup/transport residual ms |
| --- | ---: | ---: | ---: |
| plain | 0.001 | 231.572 | 120.747 |
| landlock | 0.853 | 232.226 | 120.446 |
| container | 0.769 | 274.234 | 232.868 |

### Security and exposure reduction

The frozen census has **59 cases: 49 forbidden operation/surface combinations and 10 allowed controls**, each repeated three times per mode. Repetitions are not independent attacks. Baseline effects are checked on disposable fixtures. Reduction is relative to the 49 baseline cases with observed effects. No-effect outcomes are not all explicit kernel denials.

| Mode | Forbidden cases with observed effect | Allowed control successes | Observed reduction |
| --- | ---: | ---: | ---: |
| plain | 49/49 | 30/30 | 0.00% |
| landlock | 1/49 | 30/30 | 97.96% |
| container | 0/49 | 30/30 | 100.00% |

landlock remaining exposures: stat_metadata. Forbidden-trial outcomes: `{"effect_observed": 3, "no_effect_observed": 6, "operation_denied": 132, "operation_error": 6}`.

container remaining exposures: none in this corpus. Forbidden-trial outcomes: `{"no_effect_observed": 9, "operation_denied": 132, "operation_error": 6}`.

Landlock does not hide filesystem names/metadata merely by denying file-content access. The census reports such differences rather than asserting equivalent guarantees. Both minimal profiles deny child creation/exec; their rejection does not demonstrate useful opaque-binary chain support. Kernel exploits, races, and cross-host generalization are outside this corpus.

### Container lifecycle and uncertainty

Container initialization is amortized across calls in a session. The following are separately observed setup/teardown costs (not 100 invocation measurements); include them when modeling one-shot execution. All workers are fresh even when the containing namespace persists.

| Experiment | Containers | Setup mean ms | Setup SD ms | Teardown mean ms |
| --- | ---: | ---: | ---: | ---: |
| comparison | 10 | 1302.591 | 70.392 | 1037.445 |
| operations | 5 | 1197.466 | 74.900 | 1539.833 |
| application | 5 | 1720.825 | 1021.362 | 1501.668 |

### Verified-mode security controls

The production verified path passes 12/12 controls: permitted reads, denied ungranted path arguments, rejection of changed callable bindings before execution, and admission rejection of missing read permissions, each repeated three times. These complement the raw-API rejection census; they are not equivalent to the host's 49-case syscall/resource corpus. [Control evidence](alternatives-v2/verified-security.json).

### Opaque native tool chains: separate exec-enabled profile

A separate profile permits process creation, exec and waiting, while retaining Landlock/container filesystem restrictions and the remaining seccomp policy. The fixed native chain is /usr/bin/env invoking /bin/cat; source verification of those binaries is not used. All host timing calls must successfully return the allowed canary. The actual language verifier rejects this raw subprocess tool, so no verified-language runtime is invented for it. Registering a trusted native wrapper would add an implementation assumption; it would not verify the opaque binary internals.

| Workload / mode | Mean ms | SD ms | Median ms | P95 ms | Added ms | Paired SD ms | Session 95% CI ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| env_to_cat / plain | 61.168 | 7.627 | 65.889 | 69.353 | — | — | — |
| env_to_cat / landlock | 62.299 | 8.007 | 68.043 | 71.157 | 1.132 | 1.739 | [0.459, 1.804] |
| env_to_cat / container | 111.316 | 9.920 | 118.428 | 122.048 | 50.149 | 4.235 | [47.603, 52.695] |

In 15 hidden-file checks per mode (three per session), the plain chain reads the canary and both host profiles prevent its disclosure. This demonstrates useful execution plus confinement across this two-binary chain, not all native programs. The exec-enabled Landlock profile does not enforce a process-count quota; Docker has a PID ceiling. This is explicitly a different profile from the minimal census. [Native-chain plan and admission diagnostic](alternatives-v2/../native-chain-v2/plan.json), [raw timing](alternatives-v2/../native-chain-v2/samples.jsonl), [summary](alternatives-v2/../native-chain-v2/summary.json).

| Host field | Value |
| --- | --- |
| CPU | Intel(R) Xeon(R) w5-3435X |
| Logical CPUs | 32 |
| RAM | 62.25 GiB |
| OS / kernel | Linux-6.17.0-1033-oem-x86_64-with-glibc2.39 |
| Timing CPU affinity | [0] |
| Application runtime | Pinned CPython 3.13; sandbox source hashes retained per session |

Intervals use Student t on five session mean paired differences (df=4), not 100 independent calls. They assume approximately normal independent session means; adjacent same-host sessions may remain correlated. SD/variance and P95 are descriptive within this fixed corpus. Negative small operation-body deltas do not establish a speed advantage.

### Host, artifacts and reproduction

Platform: `Linux-6.17.0-1033-oem-x86_64-with-glibc2.39`. Python: `3.12.3 (main, Aug 31 2026, 10:18:26) [GCC 13.3.0]`. CPU affinity: `[0]`. Container image: `sha256:3bcfa1622e24814afee022c71236dadd92e31a5fff41ad99a23925bc98311504`. Container security options: `["name=seccomp,profile=builtin","name=rootless","name=cgroupns"]`.

Full CPU/memory/kernel/storage/GPU details and load are in [host.json](alternatives-v2/host.json); each session also records before/after host state. The container image/runtime and host Python environment differ where documented. CPU frequency and OS caches are uncontrolled. Read fixtures are cache-warm. Sources are hashed and archived before execution. Docker cpuset is unavailable on this host. The container launcher uses taskset before Python startup; workers also enforce and report affinity [0]. Every recorded worker affinity is checked. The superseded v1 cohort is not pooled.

[Plan](alternatives-v2/plan.json), [sources](alternatives-v2/sources.tar.gz), [comparison observations](alternatives-v2/comparison.jsonl), [operation observations](alternatives-v2/operations.jsonl), [application observations](alternatives-v2/application.jsonl), [security observations](alternatives-v2/security.jsonl), [admission diagnostics](alternatives-v2/admission-census.json).

```sh
uv run --project eval python -m slanggraph_eval.isolation.alternatives \
  --output eval/reports/alternatives-new
uv run --project eval python eval/scripts/alternative_report.py
```

## 7. Claim boundaries and reproduction

The remaining publication gaps are substantive: multiple fully protected application ports, a frozen multi-task workload, successful model-driven attack attempts, broader verified-language operation coverage, capability-degradation tests, races, and multi-host measurements. The existing evidence does not justify filling those cells with zeroes or calling candidates completed ports. Kernel exploits, service authorization and cross-session flow are not covered by file-operation denial. Every number here refers to its stated finite corpus.

```sh
cd eval
uv run python -m slanggraph_eval.isolation.runtime \
  --samples 100 --warmup 10 --output reports/e6/runtime-new
uv run python scripts/paper_evaluation.py
```

The report builder uses the named frozen cohorts above, checks the old replay statistics against raw samples, recomputes the E6 summary and paired deltas, and writes input hashes to evaluation-metrics.json. To analyze another cohort, select its path explicitly; never overwrite an existing run directory.
