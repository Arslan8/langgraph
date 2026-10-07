# LangGraph tool security

LangGraph's optional tool-security layer mediates calls that cross `ToolNode` or
`guarded_tool`, with author DAC, operator policy modules, durable approvals,
tamper-evident auditing, redacted observability, and optional conservative
session-wide information-flow enforcement. It is opt-in: omitting `security`
preserves the existing execution path.

Start with the [10-line HOWTO](HOWTO.md), then use the
[behavior reference](reference.md) and [complete public API reference](api.md).
The task-oriented [user guide](users/README.md) covers application integration,
tool authorization, modules, session flow, operations, and deployment boundaries.
The [Linux host execution guide](users/linux-host-execution.md) configures the
working reference adapter for untrusted local Python tools.
The [Linux enforcement acceptance report](linux-enforcement-acceptance.md)
freezes its supported contract and maps A1–A8 to mechanisms and focused
evidence.
Existing applications should follow the [migration guide](migration.md) and
[worked patterns](workflows.md). The constructive DAC language is specified by
the [frozen `.slp` profile grammar](profiles.md). The target path from mandatory
policy to a platform-neutral grant, exact enforcement obligations, verified host
evidence, and worker activation is specified in [grant lowering](lowering.md). The [implementation status](status.md)
separates shipped behavior from the enforcement roadmap. The design rationale is
recorded in the [`adr/`](adr/) directory. Three runnable examples live in
[`examples/`](examples/README.md).

The [security properties and composition boundaries](security-properties.md)
separate per-call resource access control from classified session scheduling,
confused-deputy resistance, revocation, and task-intent integrity. Those
boundaries are part of the security contract, not optional caveats.

## Security boundary

The decisive check runs inside each physical sync or async tool execution,
after wrapper dispatch and immediately before argument injection and
`BaseTool` invocation. A wrapper retry or argument rewrite therefore receives a
new call index and a new decision. Direct tools can use `guarded_tool`, while
child graphs can use `delegate` to receive an explicitly reduced principal.

Security configuration is code, not model-controlled state. Bind principals in
`RunnableConfig`; never place credentials, approvals, policy blobs, or audit
records in graph state or messages.

This is not process-wide mandatory access control. Ordinary graph nodes execute
Python directly and can access files, networks, processes, databases, native
extensions, and unwrapped tools without crossing a tool hook. Run the
[escape analysis](escape-analysis.md) in CI. On Linux, route supported untrusted
tool entry points through `LinuxSandboxExecutor`; use brokers or additional host
adapters for authority its filesystem-focused backend rejects.
