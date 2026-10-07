# Linux enforcement acceptance report

This report freezes and evaluates contract `linux-filesystem-v1`. The validated
implementation revision is `96ef1df9` on `course/security-modules`. A later
contract change must name the changed requirement and explain why this evidence
no longer applies.

## Frozen security contract

The supported boundary is:

- calls to statically configured local Python tools mediated by `ToolNode` or
  `guarded_tool` and executed by `LinuxSandboxExecutor` in a fresh worker;
- hostile primary tool code and dependencies, which may execute only after the
  worker is released;
- regular-file reads, live directory-subtree reads, exact-file
  `read+write+truncate`, and directory-subtree
  `read+write+create+delete+truncate`;
- explicit CPU, address-space, per-file-size, private-tmpfs, open-descriptor,
  no-process-creation, and wall-time limits; and
- classified source/sink scheduling when operator labels conservatively bound
  every readable input and outward effect, every transfer is mediated, and the
  persistent SQLite flow store is used.

The trusted computing base is the coordinator, authentication and principal
binding, authorization modules, grant compiler, policy backend, launcher,
startup shim, interpreter startup, bubblewrap, libseccomp, Linux kernel, audit
and flow stores, profiles, manifests, schema stubs, and runtime-baseline
selection.

The milestone excludes network and service authority, arbitrary unmediated
Python nodes or aliases, filesystem snapshots, dependency identity, RSS or
cgroup-memory quotas, aggregate persistent writable-storage quotas, and
automatic end-to-end information-flow security. The adapter rejects requests
that need those guarantees. Filesystem grants are live path grants: external
mutation is visible. Special files and directory grants crossing a nested host
mount are rejected. Independently named aliases are separate policy resources.

## Actual execution path

| Transition | Component and source | Inputs and security state | Failure behavior |
| --- | --- | --- | --- |
| Request to authorization | `ToolNode._execute_tool_sync` and `_execute_tool_async` in `tool_node.py:1300` and `tool_node.py:1596`; `_prepare_security_request` at `tool_node.py:901` | Bound principal and normalized arguments are trusted framework state; model arguments are untrusted. DAC, prepare, MAC, approval, history, and policy constraints are read or updated. | A malformed request, missing principal, normalizer error, audit error, or non-allow decision returns denial before dispatch. |
| Authorization to immutable grant | `LinuxSandboxExecutor._compile_grant` in `security/linux.py:357`; `compile_grant` in `security/enforcement.py:207` | Authenticated principal, profile, normalized intent, pinned artifact digest, and explicit runtime baseline. | Missing or mismatched profiles and denied DAC candidates raise `HostExecutionDenied`; tool code has not started. |
| Grant to native plan | policy filtering in `security/policy.py:63`, `compile_obligations` in `security/enforcement.py:407`, and `EnforcementCoordinator.negotiate` at `security/enforcement.py:788` | The complete grant, requirement ledger, mandatory constraints, host statement, and exact obligations. | Diagnostics, removed needs, unsupported obligations, or lowering errors deny before worker release. |
| Plan to blocked worker | `_worker_command` and `_run_worker` in `security/linux.py:756` and `security/linux.py:577` | Descriptor-bound regular resources, verified artifact bytes, clear environment, explicit protocol FDs, resource limits, and plan digest. | Any spawn, mount, status, setup, or protocol failure kills the blocked worker and denies. No `GO` is sent. |
| Setup to activation evidence | trusted shim `_apply_limits` and `_apply_seccomp` in `security/_linux_worker.py:164` and `security/_linux_worker.py:186`; parent `_execution_context` at `security/linux.py:1248`; coordinator activation and receipt validation at `security/enforcement.py:845` and `security/enforcement.py:892` | The trusted shim digest is in host evidence. It emits the challenge and plan digest only after successful limit and filter installation. The parent reads kernel process state and binds it to grant, plan, host, and actual payload identity. | Setup exceptions exit before ready. A mismatched frame, kernel state, context, evidence signature, freshness window, or obligation set prevents `GO`. |
| Activation to release | `_run_worker` in `security/linux.py:577` | A validated receipt covering all assigned obligations. | The parent writes `GO` only after validation. Post-release frames are read only as untrusted results and cannot be reused as activation evidence. |
| Release to execution and result | shim `_invoke`, `_write` in `security/_linux_worker.py:220` and `security/_linux_worker.py:281`; parent `_readline_json` at `security/linux.py:1329` | Pinned primary source and dependencies execute under the installed boundary. Arguments and results are bounded JSON data. | Tool exception is `FAILED`; timeout, malformed output, abnormal exit, or ambiguous completion is `INDETERMINATE`. Result data never executes in the parent. |
| Result to termination confirmation | `_confirm_worker_terminated` and `LinuxSandboxExecutor.confirm_termination` in `security/linux.py:1370` and `security/linux.py:304` | Kernel boot ID, PID, and start time, not worker output. | The supervisor kills and checks the exact identity. Unconfirmed termination produces a recovery identity and never reports success. Async cancellation waits for this path. |
| Termination to reservation release | `_finalize_security_flow` in `tool_node.py:991`, equivalent guarded path, and SQLite `retain`/`recover` in `security/flow.py:478` and `security/flow.py:515` | Confirmed termination releases normally. Uncertain termination durably retains the sink reservation with boot/PID/start-time evidence. | Retention failure is indeterminate and remains fail-closed. After restart, `recover_termination` at `security/flow.py:673` releases only after the executor confirms termination. |

## Acceptance evidence

| ID | Status | Enforcing mechanism and failure behavior | Focused evidence |
| --- | --- | --- | --- |
| A1 | Satisfied | Baseline grant lines account for `/usr`, interpreter, trusted shim, pinned source, every runtime root, private `/tmp`, environment values, descriptors 0–2, and every limit. Bubblewrap uses `--clearenv`, `close_fds`, explicit descriptor passing, and only plan mounts. Mandatory policy can remove baseline authority, which then fails requirement recheck. | `test_linux_worker_clears_ambient_environment`, `test_linux_worker_inherits_no_ambient_descriptors`, `test_mandatory_policy_can_reject_runtime_baseline`, and the hostile-file probe. |
| A2 | Satisfied | Exact obligations are assessed before lowering. Writable mounts require the complete representable operation set. The syscall filter excludes rename, link, symlink, metadata mutation, `ioctl`, process creation, sockets, exec, and mounts. Canonical selectors must be regular files/directories; nested mounts, special files, exclusions, and unsupported domains fail negotiation. Mounts are descriptor-bound and ordered parent before child. | `test_writable_directory_exposes_only_supported_operation_set`, narrow-mutation tests, resource-identity replacement test, special-file test, nested-mount test, and unsupported-network test. |
| A3 | Satisfied | Bubblewrap establishes namespaces, mounts, capabilities, environment, and working directory before interpreter startup. Python uses `-I -S -B`; the trusted shim installs limits and seccomp before ready. Runtime roots enter `sys.path` and pinned source is compiled only after `GO`. | `test_untrusted_runtime_root_cannot_initialize_before_confinement`, artifact-change, shadow-module, unchecked-bytecode, and in-process-callback tests. |
| A4 | Satisfied within the trusted-local-host contract | The trusted shim is digest-bound in host evidence and has one path from limit/filter installation to ready. The parent verifies challenge and native-plan digest, then checks actual payload namespace, capabilities, `NoNewPrivs`, seccomp mode, thread count, mount-table digest, credentials, cgroup, boot, PID, and start time. Receipt signatures bind context, plan, grant, host, nonce, obligations, and expiry. | Activation-receipt integration and durable-audit tests plus coordinator context-mismatch tests. This proves local trusted setup, not remote or hardware attestation. |
| A5 | Satisfied | Request and response frames are capped at 1 MiB before JSON decoding; decoded depth is 64 and node count 100,000. The protocol accepts data-only built-in JSON shapes. Tool stdout/stderr are isolated from protocol at Python level; direct descriptor writes can only supply untrusted result frames, block on bounded pipes, or cause protocol failure. Post hooks are trusted. | `test_worker_protocol_bounds_request_and_response`, ambient-descriptor test, and result-type validation. |
| A6 | Satisfied | Success is returned only after process wait and kernel identity disappearance. Timeout kills the worker. Async cancellation shields and joins the execution thread. Unconfirmed termination retains a recovery identity and any active flow sink; it is not released by `finally`. | Wall-time termination test, cancellation test, and unconfirmed-termination recovery test. |
| A7 | Satisfied under the contract's classification and mediation assumptions | Source labels are joined atomically before execution and never lowered on failure. Source/sink reservations serialize conflicts. Transfers raise the destination label atomically before data exposure by the caller. Host execution with flow rejects a process-local store. SQLite persists labels, active sinks, and unresolved recovery identities; recovery needs kernel termination evidence. | Failed-source test, parallel source/sink test, cross-connection reservation test, transfer conflict/durability tests, and restart recovery test. |
| A8 | Satisfied | `cpu_ms` is `RLIMIT_CPU` and requires whole seconds; `address_space_bytes` is `RLIMIT_AS`; `file_size_bytes` is per-file `RLIMIT_FSIZE`; `nofile` is `RLIMIT_NOFILE`; `pids=1` is enforced by the no-process-creation seccomp profile; `tmpfs_bytes` is the aggregate private `/tmp` size; `wall_ms` is the supervisor deadline followed by confirmed termination. Profile `memory_bytes` and non-whole-second CPU requests are rejected. No aggregate persistent-storage limit is claimed. | File/tmpfs growth test, process/thread probes, wall timeout, and inexact-limit rejection test. |

No A1–A8 item is marked satisfied solely because an interface exists or the
overall suite passes. Each status above depends on the cited execution path and
its focused failure test.

## Confirmed defects corrected

- A6/A7: unconditional `finally` release after uncertain termination. The flow
  reservation is now retained durably and has evidence-gated recovery.
- A6: cancellation of `asyncio.to_thread` previously allowed the caller to
  unwind while the worker thread continued. Cancellation now waits for worker
  completion or returns the unconfirmed-termination failure.
- A2: special files and directory grants spanning nested mounts were accepted
  as ordinary binds. They now fail before release.
- A2: unrestricted `ioctl` could expose mutation behavior beyond the declared
  filesystem operation set. It was removed from `@minimal`.
- A8: arbitrary millisecond CPU limits were claimed despite whole-second
  `RLIMIT_CPU` granularity, and `RLIMIT_AS` was named as memory. Inexact CPU and
  physical-memory claims now reject; active baseline limits have exact names.
- A7: a host executor could be combined with the process-local flow store. That
  configuration now fails; restart-safe flow requires persistent storage.

## Remaining limitations and validation environment

There are no unresolved in-scope acceptance questions at this revision. The
explicit exclusions in the frozen contract remain limitations, not accepted
extensions. In particular, this report makes no claim for remote network or
service access, unmediated graph code, filesystem snapshots, dependency
identity, RSS, aggregate persistent-storage consumption, or complete automatic
information-flow tracking.

Validation ran on 2026-10-07 with Linux `6.17.0-1032-oem` x86-64, bubblewrap
`0.9.0`, libseccomp `2.5.5-1ubuntu3.1`, glibc `2.39`, and Python `3.12.3`.
`make format` and `make lint` passed. The complete unmodified prebuilt command
`make test` passed 518 tests, including the real Linux integration cases above;
the focused Linux and flow run passed 55 tests. These totals are corroborating
regression evidence, not the basis for any individual status.
