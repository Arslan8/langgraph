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
  limits cpu 2s mem 256M pids 1 nofile 64 wall 5s
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
4. The verified artifact bytes are copied into a private launch file. The worker
   compiles those source bytes directly and never consults a bytecode cache. A fresh
   bubblewrap worker receives only explicit mounts, an ephemeral `/tmp`, a clear
   environment, dropped capabilities, isolated namespaces, a default-deny
   seccomp allowlist, and resource ceilings.
5. The worker reports ready before importing the entry point. The parent binds
   the plan to the actual PID, process start time, namespaces, credentials,
   cgroup, boot identity, and adapter evidence. It verifies an activation
   receipt covering every obligation, then sends `GO`.
6. The worker imports the pinned module, executes exactly one JSON-serializable
   request, returns a bounded JSON result, and exits. The supervisor kills a
   worker that times out or survives completion.

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

## Production deployment checklist

A filesystem-only Linux deployment is supported when all of the following hold:

- the orchestrator, policy modules, profiles, schema stubs, and host executor are
  trusted and cannot be modified by the tool account;
- each untrusted entry point is a plain JSON-input/JSON-output Python callable
  with a pinned canonical source file and no injected LangGraph arguments;
- runtime roots contain only required code and public runtime data;
- every requested operation fits the supported filesystem/resource subset;
  unsupported network, service, credential, executable, or delegation rules are
  allowed to fail closed;
- `SqliteAuditSink` is on protected storage and its chain head is periodically
  sealed with a separately retained witness key;
- `langgraph-security-taint` reports no unmediated effect path, and the original
  in-process tool aliases are not reachable; and
- deployment tests run on each kernel/distribution image used in production;
- the operator has selected explicit CPU, memory, file-size, temporary-storage,
  process, descriptor, and wall-time ceilings for the workload.

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
