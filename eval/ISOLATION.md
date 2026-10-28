# E6: trusted code, language restrictions, and host isolation

E6 adds a **matched runtime operation census** to the static E1 census and the
Pandas application pilot. Its unit is an operation/authority-surface pair, not an
LLM attack prompt. It asks what happens when code below an admitted tool boundary
attempts an operation that the workload did not authorize.

## Research questions and hypotheses

1. **Trust boundary:** do restrictions on caller syntax also constrain effects
   inside an admitted, trusted helper? Compare `language_direct` with
   `language_helper`; the latter explicitly changes the trusted computing base.
2. **Runtime enforcement:** does the Linux executor constrain the same helper
   despite its ability to use Python, native libraries, or child-process APIs?
   Compare `trusted` with `host`, and `language_helper` with
   `host_language_helper`.
3. **Utility:** do legitimate computation and filesystem operations still work?
   Every condition runs the positive controls. A system that rejects everything
   must not receive a utility-preserving security claim.
4. **Mechanism attribution:** are effects constrained only because a resource is
   hidden, or also on visible read-only and writable objects? Report these
   surfaces separately. Writable metadata/process probes prevent attributing
   every denial to namespace hiding.

The central hypothesis is conditional: a language boundary that trusts a helper's
implementation depends on that helper honoring its contract; an activated host
boundary can limit that helper's ambient resource authority. This is not a claim
that every language sandbox is bypassable or that language restrictions have no
value. A closed language with complete mediation of all reachable primitives is
a materially different design.

## Conditions and trusted computing bases

| Condition | Caller restriction | Effect implementation | Resource boundary |
| --- | --- | --- | --- |
| `trusted` | none | fixed probe | ordinary fresh Python process |
| `language_direct` | synthetic AST allowlist and empty builtins | submitted probe | same OS authority as baseline |
| `language_helper` | same allowlist; caller is `result = helper()` | explicitly trusted prebound helper contains the probe | same OS authority as baseline |
| `host` | none | same fixed probe | actual `LinuxSandboxExecutor` |
| `host_language_helper` | same admitted helper call | same helper | actual `LinuxSandboxExecutor` |

The synthetic language frontend is deliberately small: literals, arithmetic,
assignment, and a no-argument prebound helper call. Imports, attributes, direct
I/O, and other calls are rejected. It is an executable mechanism ablation, **not
a reproduction of CaMeL, RestrictedPython, PyPy sandbox, WASI, or the repository's
ManifestAdmission API**. Its severe direct-call utility restriction must remain
visible in every table. The helper cases are controlled implementation variants,
not discoveries of vulnerabilities in third-party code. The existing released
baseline evaluations and Pandas pilot remain separate evidence cohorts.

The trusted baseline uses a fresh subprocess for measurement hygiene; that
separates interpreter state but does not remove the process's filesystem or
network authority. Process separation alone is not the host condition. Host
conditions use the production executor's namespace/mount configuration, default
deny seccomp, cleared environment, limits, activation protocol, and verified
receipt. They call the executor directly: E6 isolates the backend mechanism and
does not claim to exercise graph authorization or the full ToolNode pipeline.

The host trusts the coordinator, profile/compiler, launcher, Python worker shim,
runtime baseline, bubblewrap/libseccomp, and kernel. The tool probe does not need
to honor its declared filesystem behavior. Runtime roots expose only the
benchmark package in addition to the executor's standard runtime baseline.

## Frozen operation corpus

The executable inventory is `src/slanggraph_eval/isolation/cases.py`; every run
embeds the complete source and metadata for all cases in `manifest.json`.

| Family | Executed coverage |
| --- | --- |
| Computation | arithmetic positive control |
| Filesystem reads | builtins, pathlib, os descriptors, io, mmap |
| Discovery | glob, listdir, scandir, stat |
| Mutation | overwrite, append, truncate, unlink, rename, replace, file creation, mkdir, hardlink, symlink |
| Metadata | chmod and timestamps |
| Aliases | existing symlink, parent traversal, directory-relative open |
| Native and dynamic paths | libc via ctypes read/write, exec, eval, importlib |
| Ambient state | environment lookup and `/proc/self/environ` |
| Processes | direct subprocess and shell, with hidden and writable destinations |
| Network | a real loopback TCP connection and canary send |
| Database | SQLite read and committed update |
| Resource ceiling | bounded 2 MiB write versus a 1 MiB file-size limit, paired with a 4 KiB positive control |

The corpus has **59 cases: 49 forbidden probes and 10 positive controls**. Cases
include API and mount-surface variants; these are not 59 independent security
mechanisms. A writable directory permits creation, including mkdir. Rename,
link, metadata changes, and child creation are tested separately from that
permitted operation set. SQLite probes concern access to a backing file; they do
not test row/table authorization. TCP denial does not establish domain-aware,
HTTP-aware, or credential-aware network policy.

## Protocol and effect oracles

For every condition/case/repetition, create a new temporary fixture with a
random content canary and random filename. Give the worker the paths, never the
expected secret contents (except the network token used solely for sending).
Keep the protected tree outside the runtime roots. Expose a separate read-only
file and writable output subtree to the host worker.

Run jobs in seeded shuffled order. Each invocation uses a fresh worker and
fixture; there is no model, adaptive prompt search, or live external service.
The baseline is a positive exploitability control for each case. Before drawing
a denial conclusion, verify that the corresponding trusted baseline produced
the effect on this host. Failure of that control removes support for the
conclusion; it must not become a successful defense outcome.

The parent examines filesystem content/existence/metadata, SQLite state, and
loopback bytes. Read probes must return the independently generated canary;
knowing the requested path is insufficient. The worker returns its execution
phase and exception, but that response does not by itself establish a forbidden
effect or successful defense. Evidence includes the expected canary, output and
target digests, metadata, network bytes, response, timing, exact policy and its
digest, and the full activation receipt. The file-size test checks the bound,
not absence of any partial write.

Use these outcome categories without merging them:

- `effect_observed`: the effect oracle succeeded, even if an error also occurred.
- `admission_rejected`: the language frontend refused the source before execution.
- `operation_denied`: a recognized permission/path/mount/size error; host cases
  require an activation receipt. Attribution additionally requires the baseline
  positive control. This category includes namespace nonexistence and read-only
  mount failures, not only seccomp errors.
- `no_effect_observed`: execution returned without the effect; it is not credited
  as a demonstrated runtime denial.
- `operation_error`: another exception (including generic SQLite errors); no
  automatic security credit.
- `setup_unavailable`: construction/preflight failed; no worker result.
- `inconclusive`: launch/protocol/timeout failure or missing activation evidence.

The runner exits 1 for an observed forbidden host effect and 2 for unavailable or
inconclusive trials or failed utility controls outside the intentionally
restricted `language_direct` condition. The complete raw outcomes remain saved.
A zero exit does not turn generic operation errors into demonstrated blocking.

## Reproduction and artifact integrity

From `eval/`:

```sh
uv run --project . python -m slanggraph_eval.isolation.run \
  --repetitions 3 --seed 20261025 --output reports/e6/isolation-v1
uv run --project . pytest tests/test_isolation.py
```

Use a fresh output directory; the runner refuses to overwrite an existing run.
The saved measurement report is
[the E6 report](reports/e6/isolation-v1/report.md). `trials.jsonl` is flushed after
every trial, `summary.json` retains denominators, and `manifest.json` records the
corpus, seed, Python/platform, installed distributions, interpreter hash, Git
revision, and source inventory. `sources.tar.gz` archives the evaluation package
and local prebuilt/core/checkpoint Python sources, including working-tree edits.
Its digest is retained in the manifest. Activation receipts identify actual
host mechanisms and launch measurements. Hashes identify evidence; they are not
independent third-party attestation or a guarantee against a compromised parent.

This suite performs only fixed, locally defined operations against disposable
fixtures and a local listener. Resource probes are bounded. It accepts no
user-supplied probe files. Do not replace the corpus with unbounded adversarial
code under the ordinary-process conditions.

## Statistical analysis and paper claims

Report distinct cases and repetition counts separately. The current three
repetitions check deterministic reproducibility. They are not independent attacks
and do not justify a binomial ASR confidence interval. Report per-case outcomes,
family/surface coverage, baseline validation, allowed-operation success, and all
missing/unsupported/inconclusive cases. Do not discard integration failures or
count an unavailable host as enforcing anything.

Timing includes fresh worker launch and execution but excludes fixture/oracle
work; construction and namespace preflight have their own recorded duration.
The all-case median is descriptive because admission refusal and successful I/O
perform different work. For a performance claim, restrict to matched successful
positive controls, retain per-case paired measurements, and run more repetitions
on a reserved machine. E5 and application macrobenchmarks remain the appropriate
places for broader performance claims. E6 does not claim an optimized warm-worker
comparison or application task utility from arithmetic/filesystem controls.

A defensible paper conclusion is limited to the finite operations, policies,
backend revision, and recorded Linux host. Generalization requires a separately
pinned corpus and fresh runs on additional kernel/distribution configurations.
Keep the synthetic ablation distinct from released-system and application results.

## Coverage still requiring separate experiments

Do not count these as tested or silently infer them from the current operations:

- Real language-runtime baselines with their released policies and supported
  libraries; their utility may be substantially better than the synthetic DSL.
- Concurrent rename/symlink/TOCTOU races, nested mounts, inherited descriptors,
  imported-module initialization, adversarial protocol frames, worker teardown,
  and changed deployment/runtime artifacts. Existing library regressions cover
  parts of these boundaries but are not E6 measurements.
- CPU, address-space, descriptor, thread/process-count, aggregate temporary disk,
  wall-clock exhaustion, or persistent-storage quotas beyond the bounded file
  test. Resource settings in a receipt are not evidence of exercising each cap.
- UDP/Unix sockets, DNS, TLS, HTTP redirects, external egress, service allow
  policies, mail, credential brokers, and remote database/object authorization.
- Cross-tool/session information flow, callbacks, checkpoint/resume, unwrapped
  aliases, delegation, cancellation races, and graph mediation completeness.
- Kernel/interpreter vulnerabilities, side channels, malicious administrators,
  multi-tenant scheduling, microVM/Windows/WASI backends, and cryptographic remote
  attestation.

These omissions bound the claim; a broad operation census cannot establish
universal sandbox security.

## Matched overhead extension

The [combined evaluation](reports/paper-evaluation.md) now adds a separate runtime
cohort: three successful workloads, four conditions, ten warm-ups and 100 measured
calls per cell, plus first-use samples. It reports paired increments, SD, variance,
percentiles, constructor/preflight time, and measured policy/grant/attestation/
negotiation/worker spans. No rejection samples enter the overhead denominator.
The original E6 security medians remain historical descriptive observations.

```sh
uv run python -m slanggraph_eval.isolation.runtime --samples 100 --warmup 10 \
  --output reports/e6/runtime-new
uv run python scripts/paper_evaluation.py
```

## Per-operation microbenchmark

[The operation report](reports/e6/operations-v1/report.md) covers successful read
APIs, metadata lookup, enumeration, write, append, truncate, create, delete, mkdir,
and fsync, with a computation control. Each of 16 operation/API variants has
50 paired observations after five warm-ups. Whole-call and operation-body timers
are distinct; the latter excludes imports, source compilation, policy preparation,
and worker startup. Body timings include Python wrappers and are not pure syscall
latencies. Both conditions must pass functional oracles. Unsupported operations
are excluded explicitly rather than timed as successful enforcement.

```sh
uv run python -m slanggraph_eval.isolation.operations --samples 50 --warmup 5 \
  --output reports/e6/operations-new
uv run python scripts/operation_report.py
```

The report/CSV validator targets the named `operations-v1` cohort, independently
checks recorded output hashes/returned values, and verifies the source archive.
Update that explicit selection to analyze a new cohort. The benchmark is an OS
backend comparison against a plain Python subprocess, not a comparison against
static verification or the upstream Pandas sandbox.

## Production verified-language comparator

Use [verified-v2/report.md](reports/e6/verified-v2/report.md) for the actual
source-verified in-process versus Linux comparison. The harness is
`src/slanggraph_eval/isolation/verified.py`. It invokes production
`cedar_security`/`ManifestAdmission`, measures admission separately, and retains
runtime binding validation and real Cedar authorization. Both modes receive only
the read fixture grant; the constant-return control has no resource grant.

The shared supported workloads are constant return, text reads of 32 B/4 KiB/64
KiB, and two 32 B reads. Size variants are not independent API operations.
Each has 50 measured paired rounds, five warmups and a first-use pair. Ten
independent setup measurements per workload retain static admission and executor
construction costs. Exact sources, host snapshots, receipts, output hashes,
raw samples, stage timings and paired variance accompany the report.

The prior 16 raw-operation programs are submitted to real source admission,
with diagnostics saved separately. Rejection is not successful-operation latency.
The current built-in verified file API exposes `read_text`; broader operations
require ports through approved typed resource clients. This cohort does not
claim those ports have been completed or measure a verified application port.
The earlier synthetic checker and plain Python baselines remain ablations,
not substitutes for the verified-language comparator.

## Fixed-count rerun status

The [repetition protocol](REPETITION_PROTOCOL.md) supersedes ad hoc sample-count
choices for future primary timing claims. Its first full rerun is blocked by host
user-namespace permissions. Earlier 50-call cohorts remain historical observations;
they have not been extended or relabeled. See reports/repeated-v2/preflight.json.

## Completed alternative-backend evaluation

The fixed-count rerun is now complete using separately identified Landlock and
rootless-container evaluation adapters. See [the validated report](reports/alternatives-v2/report.md)
and [native-chain profile](reports/native-chain-v2/report.md). The earlier
Bubblewrap-specific failure remains historical; it is not the status of the new
alternative evaluation. The two host modes share the production minimal seccomp
policy for the main corpus; the native-chain experiment explicitly expands
process/exec support. Container lifecycle costs are measured outside per-call
latencies. Every primary timing cell has 100 measured calls over five sessions.
