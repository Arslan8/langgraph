# Verified language, Landlock, and rootless-container evaluation

Completed fixed protocol: **100 measured calls per workload and mode**, across five fresh benchmark-process sessions (20 measured calls each). Each session has ten excluded warmups and one separately retained first-use call. Calls and modes are shuffled within matched rounds. All positive timing results must pass the parent oracle. No failed calls are silently replaced.

[Comparison figure](comparison.pdf), [operation figure](operations.pdf), and [full-precision CSV](timings.csv).

## Configurations and scope

- **verified:** actual cedar_security / ManifestAdmission source checking at setup; production Cedar object authorization, binding validation and grant-checked read_text at invocation.
- **landlock:** an evaluation adapter applies Landlock filesystem rules, the production minimal seccomp allowlist, cleared environment and process resource limits to a fresh Python child.
- **container:** an evaluation adapter uses rootless Docker with a read-only root, no network, no capabilities, no-new-privileges, explicit read-only/read-write mounts, and memory/PID ceilings. Each invocation starts a fresh Python process inside a persistent, grant-specific container and applies the same minimal seccomp allowlist. Container creation and teardown are separately timed.
- **plain:** fresh Python child with resource ceilings for the raw-operation and application ablation; it is not the verified-language comparator.

The two host adapters are evaluation implementations, **not** the production Bubblewrap executor. Their records are parent observations and worker telemetry, not signed production activation receipts. The paired read comparison uses the same production Cedar authorizer in all three modes; its grants are translated into the allowed filesystem paths. The raw-operation and application experiments measure execution with explicit fixture/runtime grants and exclude Cedar authorization.

## Verified-language versus host: matched useful work

Constant return, three read sizes, and a two-read workload are supported in all modes. Sizes are workload variants, not distinct API operations. Static admission is outside the invocation timer and measured separately. Whole-call timing includes common authorization plus execution/transport and validation. It excludes fixture reset and container lifecycle.

| Workload / mode | Mean ms | SD ms | Median ms | P95 ms | Added ms | Paired SD ms | Session 95% CI ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| constant_control / verified | 13.104 | 1.904 | 12.676 | 16.652 | — | — | — |
| constant_control / landlock | 65.805 | 5.359 | 64.432 | 80.927 | 52.700 | 4.918 | [50.099, 55.301] |
| constant_control / container | 110.238 | 4.759 | 109.233 | 117.297 | 97.134 | 4.646 | [95.868, 98.400] |
| read_32b / verified | 19.780 | 3.108 | 19.000 | 26.111 | — | — | — |
| read_32b / landlock | 73.370 | 7.342 | 71.373 | 91.010 | 53.590 | 6.694 | [51.078, 56.103] |
| read_32b / container | 117.014 | 5.291 | 115.991 | 125.878 | 97.234 | 5.507 | [95.987, 98.480] |
| read_4kib / verified | 20.015 | 2.908 | 19.175 | 26.740 | — | — | — |
| read_4kib / landlock | 73.272 | 7.017 | 71.517 | 92.177 | 53.257 | 5.757 | [50.475, 56.038] |
| read_4kib / container | 117.930 | 6.491 | 115.874 | 132.691 | 97.915 | 5.887 | [95.931, 99.899] |
| read_64kib / verified | 19.915 | 3.119 | 19.176 | 26.648 | — | — | — |
| read_64kib / landlock | 74.293 | 7.419 | 72.356 | 93.074 | 54.378 | 6.565 | [50.585, 58.170] |
| read_64kib / container | 118.179 | 4.967 | 117.355 | 127.320 | 98.263 | 4.351 | [96.961, 99.565] |
| two_reads_32b / verified | 19.834 | 2.915 | 19.125 | 26.397 | — | — | — |
| two_reads_32b / landlock | 73.700 | 7.729 | 71.559 | 91.910 | 53.866 | 7.299 | [50.577, 57.154] |
| two_reads_32b / container | 117.257 | 6.420 | 115.869 | 127.326 | 97.424 | 6.365 | [95.456, 99.392] |

### Where the time goes

| Workload / mode | Policy mean ms | Execution/transport mean ms |
| --- | ---: | ---: |
| constant_control / verified | 12.965 | 0.137 |
| constant_control / landlock | 12.987 | 52.816 |
| constant_control / container | 12.819 | 97.417 |
| read_32b / verified | 19.516 | 0.262 |
| read_32b / landlock | 19.576 | 53.792 |
| read_32b / container | 19.439 | 97.573 |
| read_4kib / verified | 19.742 | 0.271 |
| read_4kib / landlock | 19.674 | 53.596 |
| read_4kib / container | 19.513 | 98.415 |
| read_64kib / verified | 19.630 | 0.283 |
| read_64kib / landlock | 19.760 | 54.531 |
| read_64kib / container | 19.734 | 98.442 |
| two_reads_32b / verified | 19.533 | 0.299 |
| two_reads_32b / landlock | 19.962 | 53.736 |
| two_reads_32b / container | 19.292 | 97.963 |

| Tool workload | Admission n | Admission mean ms | Admission SD ms |
| --- | ---: | ---: | ---: |
| constant_control | 100 | 7.048 | 5.480 |
| read_32b | 100 | 7.266 | 6.095 |
| read_4kib | 100 | 5.929 | 1.176 |
| read_64kib | 100 | 5.909 | 1.188 |
| two_reads_32b | 100 | 5.860 | 1.100 |

## Per-operation microbenchmarks

Sixteen operation/API variants, 100 measured calls per mode. These compare a plain process against the two host adapters. The current built-in verified file API exposes read_text; the real admission checker rejects the raw-API programs (diagnostics are saved), so rejected programs are never assigned a successful-operation timing. Registered typed-resource ports would be needed for a broader verified-language operation comparison.

| Workload / mode | Mean ms | SD ms | Median ms | P95 ms | Added ms | Paired SD ms | Session 95% CI ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| append / plain | 54.243 | 5.824 | 51.861 | 67.479 | — | — | — |
| append / landlock | 55.082 | 5.801 | 52.996 | 68.162 | 0.839 | 4.800 | [0.207, 1.471] |
| append / container | 98.805 | 3.558 | 98.084 | 104.777 | 44.562 | 5.337 | [41.477, 47.647] |
| compute_control / plain | 53.256 | 5.042 | 51.642 | 65.877 | — | — | — |
| compute_control / landlock | 54.890 | 5.488 | 53.124 | 67.814 | 1.634 | 5.030 | [0.432, 2.836] |
| compute_control / container | 99.222 | 3.481 | 98.602 | 104.564 | 45.966 | 5.014 | [44.112, 47.821] |
| create / plain | 54.098 | 5.531 | 52.232 | 66.998 | — | — | — |
| create / landlock | 54.486 | 5.254 | 52.744 | 67.115 | 0.388 | 4.373 | [-0.393, 1.168] |
| create / container | 98.976 | 2.976 | 98.365 | 104.381 | 44.877 | 5.095 | [41.768, 47.987] |
| ctypes_read / plain | 54.711 | 6.068 | 52.169 | 66.850 | — | — | — |
| ctypes_read / landlock | 55.124 | 5.722 | 52.969 | 68.132 | 0.413 | 5.972 | [0.030, 0.796] |
| ctypes_read / container | 98.775 | 3.310 | 97.980 | 104.304 | 44.064 | 5.390 | [41.620, 46.507] |
| fsync / plain | 55.845 | 5.924 | 53.481 | 67.678 | — | — | — |
| fsync / landlock | 56.092 | 5.882 | 53.672 | 68.741 | 0.247 | 4.450 | [-0.831, 1.325] |
| fsync / container | 100.744 | 6.826 | 99.397 | 106.002 | 44.899 | 6.669 | [43.556, 46.242] |
| listdir_names / plain | 54.549 | 6.162 | 52.178 | 67.265 | — | — | — |
| listdir_names / landlock | 55.005 | 6.004 | 52.493 | 68.506 | 0.456 | 4.983 | [-0.882, 1.793] |
| listdir_names / container | 98.660 | 2.994 | 98.392 | 103.260 | 44.111 | 5.847 | [40.369, 47.854] |
| mkdir / plain | 54.386 | 5.689 | 52.084 | 67.502 | — | — | — |
| mkdir / landlock | 55.411 | 6.156 | 53.288 | 68.186 | 1.025 | 4.575 | [-0.126, 2.176] |
| mkdir / container | 98.976 | 3.737 | 98.062 | 107.180 | 44.589 | 5.879 | [40.047, 49.131] |
| mmap_read / plain | 54.505 | 6.192 | 52.207 | 67.823 | — | — | — |
| mmap_read / landlock | 54.689 | 5.374 | 52.906 | 67.538 | 0.184 | 5.718 | [-1.357, 1.725] |
| mmap_read / container | 99.378 | 3.667 | 98.658 | 105.927 | 44.873 | 6.041 | [42.376, 47.370] |
| open_read / plain | 54.831 | 6.212 | 52.343 | 67.504 | — | — | — |
| open_read / landlock | 55.416 | 5.484 | 53.177 | 68.007 | 0.585 | 5.816 | [-0.496, 1.666] |
| open_read / container | 100.196 | 11.452 | 98.785 | 105.360 | 45.365 | 12.655 | [39.395, 51.334] |
| os_read / plain | 54.496 | 6.175 | 52.199 | 67.226 | — | — | — |
| os_read / landlock | 55.504 | 6.235 | 52.871 | 68.472 | 1.008 | 5.808 | [-0.922, 2.939] |
| os_read / container | 98.395 | 3.376 | 97.626 | 103.129 | 43.899 | 5.512 | [40.022, 47.776] |
| pathlib_read / plain | 57.898 | 6.324 | 55.502 | 71.479 | — | — | — |
| pathlib_read / landlock | 58.488 | 6.085 | 56.112 | 72.103 | 0.590 | 4.947 | [-0.412, 1.592] |
| pathlib_read / container | 101.899 | 3.278 | 101.389 | 108.103 | 44.001 | 6.105 | [40.515, 47.487] |
| stat_metadata / plain | 54.217 | 5.378 | 52.386 | 66.874 | — | — | — |
| stat_metadata / landlock | 55.264 | 6.010 | 52.818 | 68.082 | 1.047 | 4.564 | [0.382, 1.712] |
| stat_metadata / container | 99.550 | 3.922 | 98.593 | 106.752 | 45.333 | 5.469 | [42.125, 48.542] |
| truncate / plain | 54.380 | 5.786 | 51.931 | 66.209 | — | — | — |
| truncate / landlock | 54.903 | 5.730 | 52.779 | 68.140 | 0.523 | 3.693 | [-0.229, 1.275] |
| truncate / container | 98.831 | 3.315 | 98.082 | 103.686 | 44.451 | 5.408 | [40.357, 48.545] |
| unlink / plain | 54.448 | 5.634 | 52.723 | 67.615 | — | — | — |
| unlink / landlock | 55.030 | 5.625 | 53.184 | 68.413 | 0.582 | 6.308 | [-0.907, 2.071] |
| unlink / container | 99.117 | 3.079 | 98.648 | 104.442 | 44.670 | 5.416 | [40.749, 48.591] |
| write / plain | 54.464 | 5.889 | 52.170 | 67.591 | — | — | — |
| write / landlock | 54.720 | 5.530 | 52.926 | 68.266 | 0.255 | 4.934 | [-0.800, 1.311] |
| write / container | 99.410 | 3.654 | 98.657 | 104.376 | 44.946 | 5.692 | [41.329, 48.563] |
| write_4kib / plain | 54.132 | 5.668 | 52.035 | 67.104 | — | — | — |
| write_4kib / landlock | 55.129 | 5.953 | 53.076 | 67.575 | 0.997 | 5.064 | [0.298, 1.697] |
| write_4kib / container | 98.830 | 3.194 | 98.401 | 103.948 | 44.698 | 5.051 | [41.564, 47.833] |

### Operation body only

The inner timer surrounds the original operation statements after imports. It excludes worker startup, policy, activation and transport; it is not pure syscall time.

| Operation | Plain mean µs | Landlock mean µs | Container mean µs |
| --- | ---: | ---: | ---: |
| append | 49.913 | 50.588 | 47.852 |
| compute_control | 0.225 | 0.231 | 0.225 |
| create | 75.153 | 75.942 | 74.899 |
| ctypes_read | 83.917 | 63.197 | 62.042 |
| fsync | 810.035 | 774.814 | 738.203 |
| listdir_names | 22.717 | 21.117 | 22.742 |
| mkdir | 51.398 | 49.812 | 54.535 |
| mmap_read | 25.771 | 26.463 | 28.469 |
| open_read | 39.449 | 42.265 | 42.935 |
| os_read | 10.088 | 9.803 | 10.798 |
| pathlib_read | 59.739 | 59.470 | 57.598 |
| stat_metadata | 5.697 | 5.065 | 8.128 |
| truncate | 29.006 | 26.559 | 29.610 |
| unlink | 51.860 | 45.690 | 52.598 |
| write | 99.412 | 95.819 | 104.256 |
| write_4kib | 85.412 | 85.360 | 86.299 |

## Application replay

This runs the actual recorded Pandas February computation, original input, and unmodified upstream sandbox runner. The independent expected result is total_sales=120. All modes use the pinned application Python 3.13 runtime and dependencies. Plain retains the upstream sandbox; Landlock/container add host restrictions around that same sandbox program. This is a computation replay, not a model-driven full workflow or a verified-language application port. No model calls, ToolNode dispatch, durable audit sink, or Cedar authorization are included.

| Workload / mode | Mean ms | SD ms | Median ms | P95 ms | Added ms | Paired SD ms | Session 95% CI ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| pandas_february / plain | 334.901 | 36.031 | 317.278 | 397.102 | — | — | — |
| pandas_february / landlock | 336.102 | 35.659 | 319.833 | 400.318 | 1.201 | 17.147 | [-1.146, 3.549] |
| pandas_february / container | 464.616 | 14.188 | 464.723 | 482.062 | 129.715 | 34.680 | [96.978, 162.452] |

| Application mode | Worker activation ms | Application body ms | Startup/transport residual ms |
| --- | ---: | ---: | ---: |
| plain | 0.001 | 218.942 | 115.958 |
| landlock | 0.799 | 220.160 | 115.143 |
| container | 0.658 | 244.542 | 219.417 |

## Security and exposure reduction

The frozen census has **59 cases: 49 forbidden operation/surface combinations and 10 allowed controls**, each repeated three times per mode. Repetitions are not independent attacks. Baseline effects are checked on disposable fixtures. Reduction is relative to the 49 baseline cases with observed effects. No-effect outcomes are not all explicit kernel denials.

| Mode | Forbidden cases with observed effect | Allowed control successes | Observed reduction |
| --- | ---: | ---: | ---: |
| plain | 49/49 | 30/30 | 0.00% |
| landlock | 1/49 | 30/30 | 97.96% |
| container | 0/49 | 30/30 | 100.00% |

landlock remaining exposures: stat_metadata. Forbidden-trial outcomes: `{"effect_observed": 3, "no_effect_observed": 6, "operation_denied": 132, "operation_error": 6}`.

container remaining exposures: none in this corpus. Forbidden-trial outcomes: `{"no_effect_observed": 9, "operation_denied": 132, "operation_error": 6}`.

Landlock does not hide filesystem names/metadata merely by denying file-content access. The census reports such differences rather than asserting equivalent guarantees. Both minimal profiles deny child creation/exec; their rejection does not demonstrate useful opaque-binary chain support. Kernel exploits, races, and cross-host generalization are outside this corpus.

## Container lifecycle and uncertainty

Container initialization is amortized across calls in a session. The following are separately observed setup/teardown costs (not 100 invocation measurements); include them when modeling one-shot execution. All workers are fresh even when the containing namespace persists.

| Experiment | Containers | Setup mean ms | Setup SD ms | Teardown mean ms |
| --- | ---: | ---: | ---: | ---: |
| comparison | 10 | 1252.521 | 149.596 | 1003.404 |
| operations | 5 | 1287.520 | 106.299 | 1330.814 |
| application | 5 | 1246.945 | 46.252 | 1396.785 |

## Verified-mode security controls

The production verified path passes 12/12 controls: permitted reads, denied ungranted path arguments, rejection of changed callable bindings before execution, and admission rejection of missing read permissions, each repeated three times. These complement the raw-API rejection census; they are not equivalent to the host's 49-case syscall/resource corpus. [Control evidence](verified-security.json).

## Opaque native tool chains: separate exec-enabled profile

A separate profile permits process creation, exec and waiting, while retaining Landlock/container filesystem restrictions and the remaining seccomp policy. The fixed native chain is /usr/bin/env invoking /bin/cat; source verification of those binaries is not used. All host timing calls must successfully return the allowed canary. The actual language verifier rejects this raw subprocess tool, so no verified-language runtime is invented for it. Registering a trusted native wrapper would add an implementation assumption; it would not verify the opaque binary internals.

| Workload / mode | Mean ms | SD ms | Median ms | P95 ms | Added ms | Paired SD ms | Session 95% CI ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| env_to_cat / plain | 56.542 | 6.341 | 53.766 | 68.906 | — | — | — |
| env_to_cat / landlock | 58.183 | 6.262 | 55.123 | 69.322 | 1.641 | 2.289 | [1.026, 2.255] |
| env_to_cat / container | 101.248 | 3.362 | 100.553 | 105.646 | 44.706 | 5.985 | [37.920, 51.493] |

In 15 hidden-file checks per mode (three per session), the plain chain reads the canary and both host profiles prevent its disclosure. This demonstrates useful execution plus confinement across this two-binary chain, not all native programs. The exec-enabled Landlock profile does not enforce a process-count quota; Docker has a PID ceiling. This is explicitly a different profile from the minimal census. [Native-chain plan and admission diagnostic](../native-chain-v1/plan.json), [raw timing](../native-chain-v1/samples.jsonl), [summary](../native-chain-v1/summary.json).

| Host field | Value |
| --- | --- |
| CPU | Intel(R) Xeon(R) w5-3435X |
| Logical CPUs | 32 |
| RAM | 62.25 GiB |
| OS / kernel | Linux-6.17.0-1033-oem-x86_64-with-glibc2.39 |
| Timing CPU affinity | [0] |
| Application runtime | Pinned CPython 3.13; sandbox source hashes retained per session |

Intervals use Student t on five session mean paired differences (df=4), not 100 independent calls. They assume approximately normal independent session means; adjacent same-host sessions may remain correlated. SD/variance and P95 are descriptive within this fixed corpus. Negative small operation-body deltas do not establish a speed advantage.

## Host, artifacts and reproduction

Platform: `Linux-6.17.0-1033-oem-x86_64-with-glibc2.39`. Python: `3.12.3 (main, Aug 31 2026, 10:18:26) [GCC 13.3.0]`. CPU affinity: `[0]`. Container image: `sha256:3bcfa1622e24814afee022c71236dadd92e31a5fff41ad99a23925bc98311504`. Container security options: `["name=seccomp,profile=builtin","name=rootless","name=cgroupns"]`.

Full CPU/memory/kernel/storage/GPU details and load are in [host.json](host.json); each session also records before/after host state. The container image/runtime and host Python environment differ where documented. CPU frequency and OS caches are uncontrolled. Read fixtures are cache-warm. Sources are hashed and archived before execution.

[Plan](plan.json), [sources](sources.tar.gz), [comparison observations](comparison.jsonl), [operation observations](operations.jsonl), [application observations](application.jsonl), [security observations](security.jsonl), [admission diagnostics](admission-census.json).

```sh
uv run --project eval python -m slanggraph_eval.isolation.alternatives \
  --output eval/reports/alternatives-new
uv run --project eval python eval/scripts/alternative_report.py
```
