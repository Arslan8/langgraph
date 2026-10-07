# Security boundary

The decisive runtime check sits inside the physical `ToolNode` execute callable,
after wrappers and immediately before tool invocation. Wrapper retries and
rewritten requests are checked independently. `guarded_tool` supplies the same
mediation to supported direct calls.

This gives complete mediation for those configured entry points. It is not a
claim that every Python side effect in a process is mediated.

## Trusted components

Treat these as part of the trusted computing base:

- application authentication and `Principal` construction;
- `SecurityConfig`, operator DAC overrides, and flow classifications;
- security modules, built-in normalizers, and audit/flow stores;
- tool discovery and decorators executed in the coordinator process;
- graph nodes, callbacks, renderers, checkpoint handlers, and model clients that
  perform effects outside `ToolNode` or `guarded_tool`; and
- any external sandbox, broker, host adapter, or attestation verifier used by
  the deployment.

Tool descriptors are author claims. They help policy and inventory, but do not
prove that hostile code lacks undeclared effects.

## When tool code is untrusted

On Linux, configure `LinuxSandboxExecutor` for supported local Python tools. It
starts a fresh bubblewrap worker with explicit mounts, a clear environment,
dropped capabilities, namespace isolation, default resource ceilings, and a
default-deny seccomp allowlist. The worker blocks before importing the pinned
tool artifact; the parent verifies a worker-specific activation receipt before
sending the release signal. See [Linux host execution](linux-host-execution.md).

The current adapter intentionally rejects network, service, credential,
delegation, and executable grants. Add a scoped broker or another adapter for
those obligations; do not weaken the Linux worker or treat an unsupported rule
as advisory. Runtime roots and `/usr` are explicit operator-owned baseline
authority and must contain no secrets the tool is not permitted to read.

The in-process path remains available for trusted implementations and upstream
compatibility. It provides authorization, not hostile-code confinement.

## Information-flow boundary

`SessionFlowPolicy` enforces operator-supplied read and outward-effect bounds
across calls, parallel batches, separate ToolNodes, guarded calls, and workers
sharing the durable store. A source-and-sink call is checked after joining its
possible reads. This is a scheduling property, not evidence that an untrusted
implementation obeyed its classification.

The model request and response path, final text, telemetry, tracing, and
unmediated callbacks remain outside automatic mediation. If they can receive or
publish data, give each action a rule and wrap its complete effect lifetime with
`guard_operation()`, or make it an explicitly trusted destination. Background
work and descendants may not outlive the reservation unless an external
supervisor carries the reservation and confinement lease until they exit.

Checkpoint imports, shared artifacts, and inter-session copies must call
`transfer_session()` before exposing the data to the target. Arbitrary copies
that bypass this API are outside the protected model. Static inventory and
escape analysis help find bypasses but do not prove their absence in arbitrary
Python or native dependencies.

## Compatibility mode

`security=None` is intentionally a no-op for upstream compatibility. Only
trusted application code may choose it. Do not expose configuration selection to
the model, tool arguments, messages, graph state, or a delegated child. A
secured ToolNode cannot be reconfigured or downgraded, and delegated graphs
cannot replace inherited security.

For the formal property split and limitations, read
[security properties](../security-properties.md) and
[implementation status](../status.md).
