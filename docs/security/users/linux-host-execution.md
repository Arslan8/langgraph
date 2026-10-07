# Linux host execution

Use `LinuxSandboxExecutor` when a local Python tool is not trusted to honor its
descriptor. Authorization remains platform-neutral: `.slp`, mandatory modules,
and the final `Grant` do not mention bubblewrap or Linux. The executor is one
adapter that lowers supported obligations to Linux mechanisms.

## Prerequisites

The host needs Linux, bubblewrap, and `libseccomp.so.2`. Unprivileged user
namespaces must be available to the application account. Construction fails if
bubblewrap or libseccomp is unavailable. Construction also runs a real namespace
preflight and checks the exact bubblewrap features used by the launcher, so an
installed but unusable sandbox fails before the graph accepts traffic.

Put the callable imported by the worker in a module that is separate from the
trusted schema stub registered with LangGraph. The operator manifest binds that
module file by canonical path and SHA-256 digest.

```python
import hashlib
from pathlib import Path

from langchain_core.tools import tool
from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    DacOverrides,
    Effect,
    LinuxSandboxExecutor,
    LinuxToolSpec,
    Principal,
    ResourceArg,
    SecurityConfig,
    dac,
    effects,
    parse_profiles,
    with_principal,
)

artifact = Path("/opt/research_tools/report_tools.py").resolve(strict=True)
artifact_digest = hashlib.sha256(artifact.read_bytes()).hexdigest()

profiles = parse_profiles(
    """
tool read_report {
  owner analyst
  grant analyst: call
  runs linux
  syscalls @minimal
  fs read ${path} need
  limits cpu 2s pids 1 nofile 64 wall 5s
}
principal alice {
  roles analyst
  fs read /srv/reports/**
}
""",
    source="security.slp",
)

executor = LinuxSandboxExecutor(
    profiles,
    {
        "read_report": LinuxToolSpec(
            "report_tools:read_report",
            artifact,
            artifact_digest,
        )
    },
    runtime_roots=(artifact.parent,),
)
security = SecurityConfig(
    dac_overrides=DacOverrides(profiles=profiles.tools),
    host_executor=executor,
)

@tool
@dac(owner="analyst", grants={"analyst": "x", "*": "-"})
@effects(Effect.READ, resources=[ResourceArg("path", "path", "realpath")])
def read_report(path: str) -> str:
    """Schema stub. The Linux executor never calls this body."""
    raise RuntimeError("in-process execution is forbidden")

node = ToolNode([read_report], security=security)
principal = Principal(
    "alice",
    frozenset({"analyst"}),
    frozenset(),
    "authenticated-session-id",
)
config = with_principal({}, principal, modules=security.modules)
result = node.invoke(tool_call_input, config=config)
```

The module at `/opt/research_tools/report_tools.py` exports the real
`read_report(path: str)` function. The schema stub and manifest key must have the
same tool name. Every tool reachable from a secured node needs a `LinuxToolSpec`;
missing manifests fail during configuration.

## What happens for each call

1. The normal DAC and mandatory-module stack authorizes normalized arguments.
2. The profile candidate is compiled into an immutable grant. Mandatory typed
   constraints filter that grant and requirements are rechecked.
3. Exact operation, selector, condition, default-deny, syscall, and resource
   obligations are negotiated. Any unsupported required obligation denies.
4. The verified artifact bytes are copied into a private launch file. Python
   starts with `-I -S -B`; runtime roots are not placed on its startup path.
   The trusted shim applies limits and seccomp before the parent releases it,
   and only then adds runtime roots and compiles the pinned source directly. It
   never consults a bytecode cache. A fresh bubblewrap worker receives only
   explicit mounts, an ephemeral `/tmp`, a clear environment, dropped
   capabilities, isolated namespaces, a default-deny seccomp allowlist, and
   resource ceilings.
   Each resource mount is opened by descriptor and its device, inode, and object
   type are revalidated against the authorized canonical path before release.
5. The trusted worker reports a parent challenge and plan digest only after
   installing limits and seccomp. The parent independently verifies the actual
   PID, start time, distinct namespaces, zero capability sets, `NoNewPrivs`,
   seccomp mode, single-thread state, mount-table digest, credentials, cgroup,
   boot identity, and adapter evidence. It verifies an activation receipt
   covering every obligation, then sends `GO`.
6. The worker imports the pinned module, executes exactly one JSON-serializable
   request, returns a bounded and depth-limited JSON result, and exits. Request
   and response frames are capped at 1 MiB. Tool stdout is retained only inside
   the worker's address-space limit, stderr is a bounded pipe, and protocol
   errors contain only an exception type. The supervisor kills a worker that
   times out or survives completion and confirms that its PID/start-time pair
   is gone before returning or releasing flow reservations.

Every successful or failed post-activation call writes the complete canonical
receipt into the normal hash-chained audit stream before its result is accepted.
With `SqliteAuditSink`, that evidence survives restart and participates in
external audit seals. Recent receipts are also available for operational access:

```python
receipts = executor.activation_receipts()
receipt = receipts[-1]
assert receipt.activated_obligations
assert receipt.context_digest
```

The snapshot is bounded to the most recent 1,024 receipts and is not an audit
archive. Production deployments must use `SqliteAuditSink` and retain externally
witnessed chain seals.

## Supported authority

The reference adapter currently supports:

- canonical existing files and directory subtrees mounted read-only;
- exact existing files mounted writable only when the grant includes every
  operation the mount exposes: `read`, `write`, and `truncate`;
- writable directory subtrees only when the grant includes `read`, `write`,
  `create`, `delete`, and `truncate`;
- `@minimal`, implemented as a default-deny syscall allowlist that excludes
  sockets, process creation, executable replacement, namespace changes, mounts,
  ptrace, kernel-key access, and similar escape surfaces; and
- CPU time, address space, per-file size, private `/tmp` size, process count,
  descriptor count, and wall-clock ceilings. Conservative defaults apply even
  when the profile omits limits; operators may replace the complete
  `default_limits` mapping when constructing `LinuxSandboxExecutor`.

Filesystem grants have live path-subtree semantics. A directory grant
authorizes matching children that exist or appear beneath that same mounted
directory object during the call; it is not a snapshot of initial descendants.
External processes permitted to mutate the backing object may do so, and the
worker observes those mutations. Canonical symlink-free selectors and stable
mount descriptors bind the mounted root object, but do not claim content
immutability. Deployments that need snapshot semantics must provide immutable
artifacts or a snapshotting resource adapter.

Selectors must name regular files or directories. FIFOs, sockets, device nodes,
and other special files require another adapter. A directory containing a
nested host mount is also rejected: each mount boundary needs its own explicit
grant. Existing descendant symlinks retain ordinary live-name semantics, but
can resolve only to objects separately visible in the worker namespace.

The writable-mount operation set is deliberately closed. A writable existing
file is accepted only with `read+write+truncate`; a writable directory subtree
requires `read+write+create+delete+truncate`. Narrower mutation sets fail
lowering. Rename, hard-link, symbolic-link, ownership, mode, timestamp, device,
and extended-attribute operations are absent from `@minimal` and therefore
denied. Authorization is path based; independently named hard-link or bind-mount
aliases are not treated as the same policy entity. Operators needing
object-identity policy must exclude such aliases or use an object-aware broker.

Profiles used by this adapter must declare exactly `syscalls @minimal`. Injected
state, store, or `ToolRuntime` arguments are rejected during configuration
because the worker protocol does not carry coordinator capabilities.

The adapter rejects rather than approximates network, HTTP, mail, database,
service, credential, delegation, and executable authority. Those operations need
a broker, service adapter, resource adapter, or another host backend that owns
their exact obligations. A future Windows adapter consumes the same grant and
obligations; applications and mandatory modules do not depend on bubblewrap.

## Runtime baseline and trust boundary

`/usr`, the trusted worker shim, the pinned artifact, every `runtime_roots`
entry, ephemeral `/tmp`, the exact cleared-environment values, parent protocol
descriptors, and default resource ceilings are explicit baseline grant lines.
Mandatory aggregate policy sees them. Interpreter, worker, bubblewrap, and tool
artifact digests are rechecked at dispatch. Keep runtime roots minimal: mounting
an application source tree makes that tree readable by the worker.

"Pinned tool" means the manifest's primary source file only. Runtime roots,
imported Python modules, native extensions, and runtime data are not included in
that artifact digest. They are mounted read-only and cannot initialize through
`PYTHONPATH`, `site`, `.pth`, or `sitecustomize` before confinement, but they may
execute after `GO` with the worker's granted authority. Pin a deployment image
or separately verify dependency artifacts when dependency identity matters.

## Production deployment checklist

A filesystem-only Linux deployment is supported when all of the following hold:

- the orchestrator, policy modules, profiles, schema stubs, and host executor are
  trusted and cannot be modified by the tool account;
- each untrusted entry point is a plain JSON-input/JSON-output Python callable
  with a pinned canonical source file and no injected LangGraph arguments;
- runtime roots contain only required code and data authorized for every tool
  that receives those roots;
- each flow classification conservatively includes all data readable through
  the tool grant, `/usr`, runtime roots, and the private runtime baseline;
- every requested operation fits the supported filesystem/resource subset;
  unsupported network, service, credential, executable, or delegation rules are
  allowed to fail closed;
- `SqliteAuditSink` is on protected storage and its chain head is periodically
  sealed with a separately retained witness key;
- `langgraph-security-taint` reports no unmediated effect path, and the original
  in-process tool aliases are not reachable; and
- deployment tests run on each kernel/distribution image used in production;
- the operator has selected explicit CPU, virtual-address-space, file-size,
  temporary-storage, process, descriptor, and wall-time ceilings for the
  workload. The adapter calls the `RLIMIT_AS` baseline
  `address_space_bytes` and the per-file `RLIMIT_FSIZE` baseline
  `file_size_bytes`. Profile `mem` requests remain `memory_bytes` and are
  rejected because this adapter has no RSS or cgroup-memory mechanism.

`cpu_ms` is accepted only in whole-second increments because the active
mechanism is `RLIMIT_CPU`. `tmpfs_bytes` is an aggregate ceiling for the private
ephemeral `/tmp`; `file_size_bytes` is a per-file ceiling and does not bound
aggregate persistent writable-storage consumption.

Within that boundary, this is a deployable enforcement implementation, not a
simulation. It is not a general-purpose container service or a substitute for a
network/service broker.

The schema stub, decorators, built-in normalizers, principal construction,
profiles, mandatory modules, policy backend, executor, bubblewrap, libseccomp,
and kernel are trusted. The entry-point artifact is not. The local attestation is
authenticated with an executor-private process key; it proves that this process
observed and activated this local worker, not that a remote or compromised host
is trustworthy.

Ordinary graph nodes, callbacks, model clients, checkpoint handlers, and an
unwrapped tool alias remain outside the host-execution boundary. Run escape
analysis in CI and mediate every effectful path. Session-flow policy is still
required when separate allowed calls could compose a sensitive read with a later
outward effect.
