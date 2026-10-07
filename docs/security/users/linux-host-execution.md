# Linux host execution

Use `LinuxSandboxExecutor` when a local Python tool is not trusted to honor its
descriptor. Authorization remains platform-neutral: `.slp`, mandatory modules,
and the final `Grant` do not mention bubblewrap or Linux. The executor is one
adapter that lowers supported obligations to Linux mechanisms.

## Prerequisites

The host needs Linux, bubblewrap, and `libseccomp.so.2`. Unprivileged user
namespaces must be available to the application account. Construction fails if
bubblewrap is unavailable; worker activation fails closed if isolation or
seccomp cannot be established.

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
4. The verified artifact bytes are copied into a private launch file. A fresh
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

Recent receipts are available for operational evidence:

```python
receipts = executor.activation_receipts()
receipt = receipts[-1]
assert receipt.activated_obligations
assert receipt.context_digest
```

The snapshot is bounded to the most recent 1,024 receipts. Configure the normal
audit sink and external audit-head anchoring for durable evidence; the snapshot
is not an audit archive.

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
- CPU time, address space, process count, descriptor count, and wall-clock
  ceilings. Conservative defaults apply even when the profile omits limits.

The adapter rejects rather than approximates network, HTTP, mail, database,
service, credential, delegation, and executable authority. Those operations need
a broker, service adapter, resource adapter, or another host backend that owns
their exact obligations. A future Windows adapter consumes the same grant and
obligations; applications and mandatory modules do not depend on bubblewrap.

## Runtime baseline and trust boundary

`/usr`, the trusted worker shim, the pinned artifact, every `runtime_roots`
entry, ephemeral `/tmp`, and default resource ceilings are explicit baseline
grant lines. Mandatory aggregate policy sees them. Keep runtime roots minimal:
mounting an application source tree makes that tree readable by the worker.

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
