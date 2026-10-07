# Using slangGraph security

This folder is the task-oriented user guide for application developers, tool
authors, security-module authors, and operators. It explains how to use the
implemented framework. Design rationale and future architecture live one level
up and are linked only where they affect deployment decisions.

Start with [getting started](getting-started.md), then choose the guide for your
role:

- [Declare and authorize tools](tool-authorization.md) for descriptors, resource
  normalization, author DAC, and operator overrides.
- [Write restrictive modules](modules-and-delegation.md) for mandatory policy,
  private slots, argument narrowing, approvals, and delegation.
- [Schedule classified sources and sinks](session-flow.md) to block incompatible
  mediated operations in later or concurrent calls.
- [Operate and audit deployments](operations.md) for principal binding, durable
  audit, observability, inventory, escape analysis, and troubleshooting.
- [Understand the security boundary](security-boundary.md) before running
  untrusted code or making process-wide security claims.

The public package is `langgraph.prebuilt.security`. Security remains opt-in:
`security=None` preserves upstream behavior. Once security is configured, bind
the principal at a trusted request boundary and reuse the same
`SecurityConfig` throughout a graph and its delegated children.

## What users can rely on today

Configured calls crossing `ToolNode` or `guarded_tool` receive author DAC,
restrictive mandatory hooks, fail-closed normalization and hook handling,
redacted decision audit, durable approval rechecks, and optional classified
source/sink scheduling. Sync and async paths use the same contracts.

Native worker confinement is a separate layer. The grant, obligation,
host-attestation, adapter-plan, and activation-receipt contracts exist, but tool
execution is not yet routed through a native enforcement adapter. Until that
wiring lands, use an external sandbox when tool code itself is untrusted.
