# E6 operation-level isolation evaluation

Recorded: 2026-10-26T02:50:44.663283+00:00. Seed: 20261025. Repetitions: 3.

These are deterministic synthetic probes, not prompt-injection ASR or a comparison against a released language sandbox. Counts below are trials; repeated cases are not independent samples.

| Condition | Allowed effects / controls | Forbidden effects / trials | Validated forbidden cases | Median dispatch ms |
| --- | ---: | ---: | ---: | ---: |
| trusted | 30/30 | 147/147 | 49 | 23.55 |
| language_direct | 3/30 | 0/147 | 49 | 20.80 |
| language_helper | 30/30 | 147/147 | 49 | 24.86 |
| host | 30/30 | 0/147 | 49 | 299.93 |
| host_language_helper | 30/30 | 0/147 | 49 | 295.15 |

Dispatch time includes fresh-worker launch and execution, excludes executor construction/preflight and fixture/oracle work, and mixes operation types. It is descriptive; use matched successful controls for performance claims. Per-trial setup and dispatch times are retained in trials.jsonl.

## Every case and observed outcome

E = effect observed; D = operation denied; A = admission rejected; N = no effect observed; X = operation error; U = setup unavailable; ? = inconclusive. Only E establishes the effect; N/X/U/? are not credited as runtime blocking. D in a host condition requires activation evidence. Baseline validation is also required before interpreting D.

| Case | Family | Surface | Intended | trusted | language_direct | language_helper | host | host_language_helper |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| arithmetic | compute | hidden | allow | E:3 | E:3 | E:3 | E:3 | E:3 |
| allowed_read | filesystem | hidden | allow | E:3 | A:3 | E:3 | E:3 | E:3 |
| allowed_write | filesystem | hidden | allow | E:3 | A:3 | E:3 | E:3 | E:3 |
| open_read | filesystem | hidden | deny | E:3 | A:3 | E:3 | D:3 | D:3 |
| pathlib_read | filesystem | hidden | deny | E:3 | A:3 | E:3 | D:3 | D:3 |
| os_read | filesystem | hidden | deny | E:3 | A:3 | E:3 | D:3 | D:3 |
| io_read | filesystem | hidden | deny | E:3 | A:3 | E:3 | D:3 | D:3 |
| mmap_read | filesystem | hidden | deny | E:3 | A:3 | E:3 | D:3 | D:3 |
| glob_names | filesystem | hidden | deny | E:3 | A:3 | E:3 | N:3 | N:3 |
| listdir_names | filesystem | hidden | deny | E:3 | A:3 | E:3 | D:3 | D:3 |
| scandir_names | filesystem | hidden | deny | E:3 | A:3 | E:3 | D:3 | D:3 |
| stat_metadata | filesystem | hidden | deny | E:3 | A:3 | E:3 | D:3 | D:3 |
| write | filesystem | hidden | deny | E:3 | A:3 | E:3 | D:3 | D:3 |
| append | filesystem | hidden | deny | E:3 | A:3 | E:3 | D:3 | D:3 |
| truncate | filesystem | hidden | deny | E:3 | A:3 | E:3 | D:3 | D:3 |
| unlink | filesystem | hidden | deny | E:3 | A:3 | E:3 | D:3 | D:3 |
| rename | filesystem | hidden | deny | E:3 | A:3 | E:3 | D:3 | D:3 |
| replace | filesystem | hidden | deny | E:3 | A:3 | E:3 | D:3 | D:3 |
| chmod | metadata | hidden | deny | E:3 | A:3 | E:3 | D:3 | D:3 |
| utime | metadata | hidden | deny | E:3 | A:3 | E:3 | D:3 | D:3 |
| create | filesystem | hidden | deny | E:3 | A:3 | E:3 | D:3 | D:3 |
| mkdir | filesystem | hidden | deny | E:3 | A:3 | E:3 | D:3 | D:3 |
| hardlink | filesystem | hidden | deny | E:3 | A:3 | E:3 | D:3 | D:3 |
| symlink | filesystem | hidden | deny | E:3 | A:3 | E:3 | D:3 | D:3 |
| symlink_read | alias | hidden | deny | E:3 | A:3 | E:3 | D:3 | D:3 |
| traversal_read | alias | hidden | deny | E:3 | A:3 | E:3 | D:3 | D:3 |
| dirfd_read | alias | hidden | deny | E:3 | A:3 | E:3 | D:3 | D:3 |
| ctypes_read | native | hidden | deny | E:3 | A:3 | E:3 | D:3 | D:3 |
| exec_read | dynamic | hidden | deny | E:3 | A:3 | E:3 | D:3 | D:3 |
| eval_read | dynamic | hidden | deny | E:3 | A:3 | E:3 | D:3 | D:3 |
| importlib_read | dynamic | hidden | deny | E:3 | A:3 | E:3 | D:3 | D:3 |
| environment | ambient | hidden | deny | E:3 | A:3 | E:3 | N:3 | N:3 |
| proc_environment | ambient | hidden | deny | E:3 | A:3 | E:3 | D:3 | D:3 |
| subprocess | process | hidden | deny | E:3 | A:3 | E:3 | D:3 | D:3 |
| shell | process | hidden | deny | E:3 | A:3 | E:3 | D:3 | D:3 |
| tcp_connect | network | hidden | deny | E:3 | A:3 | E:3 | D:3 | D:3 |
| sqlite_read | database | hidden | deny | E:3 | A:3 | E:3 | X:3 | X:3 |
| sqlite_write | database | hidden | deny | E:3 | A:3 | E:3 | X:3 | X:3 |
| readonly_write | filesystem | readonly | deny | E:3 | A:3 | E:3 | D:3 | D:3 |
| readonly_append | filesystem | readonly | deny | E:3 | A:3 | E:3 | D:3 | D:3 |
| readonly_truncate | filesystem | readonly | deny | E:3 | A:3 | E:3 | D:3 | D:3 |
| readonly_unlink | filesystem | readonly | deny | E:3 | A:3 | E:3 | D:3 | D:3 |
| allowed_write_subtree | filesystem | writable | allow | E:3 | A:3 | E:3 | E:3 | E:3 |
| allowed_append_subtree | filesystem | writable | allow | E:3 | A:3 | E:3 | E:3 | E:3 |
| allowed_truncate_subtree | filesystem | writable | allow | E:3 | A:3 | E:3 | E:3 | E:3 |
| allowed_unlink_subtree | filesystem | writable | allow | E:3 | A:3 | E:3 | E:3 | E:3 |
| allowed_create_subtree | filesystem | writable | allow | E:3 | A:3 | E:3 | E:3 | E:3 |
| allowed_mkdir_subtree | filesystem | writable | allow | E:3 | A:3 | E:3 | E:3 | E:3 |
| writable_rename | filesystem | writable | deny | E:3 | A:3 | E:3 | D:3 | D:3 |
| writable_replace | filesystem | writable | deny | E:3 | A:3 | E:3 | D:3 | D:3 |
| writable_chmod | metadata | writable | deny | E:3 | A:3 | E:3 | D:3 | D:3 |
| writable_utime | metadata | writable | deny | E:3 | A:3 | E:3 | D:3 | D:3 |
| writable_hardlink | filesystem | writable | deny | E:3 | A:3 | E:3 | D:3 | D:3 |
| writable_symlink | filesystem | writable | deny | E:3 | A:3 | E:3 | D:3 | D:3 |
| writable_subprocess | process | writable | deny | E:3 | A:3 | E:3 | D:3 | D:3 |
| writable_shell | process | writable | deny | E:3 | A:3 | E:3 | D:3 | D:3 |
| file_size_limit | resource | hidden | deny | E:3 | A:3 | E:3 | D:3 | D:3 |
| allowed_small_file | resource | hidden | allow | E:3 | A:3 | E:3 | E:3 | E:3 |
| native_write | native | hidden | deny | E:3 | A:3 | E:3 | D:3 | D:3 |

## Interpretation limits

The language frontend accepts arithmetic and a prebound helper only. The helper is a deliberate trusted-code assumption. This establishes a trust-boundary contrast, not that language sandboxes are inherently unsound. Host enforcement still trusts the coordinator, policy compiler, launcher, worker shim, runtime baseline, and kernel.

This single-host finite corpus excludes kernel exploits, races, cross-session information flow, external services, network allow policies, distributed brokers, and destructive exhaustion. SQLite failures alone do not demonstrate SQL authorization. Repetitions check stability; no population ASR, binomial confidence interval, or universal containment claim is supported.

See eval/ISOLATION.md for the protocol and remaining evaluation scope.
