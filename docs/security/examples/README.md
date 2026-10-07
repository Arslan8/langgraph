# Runnable security examples

These examples cover the decision layer that exists today:

1. [`guarded_tool_audit.py`](guarded_tool_audit.py) binds a principal, applies
   author DAC to a directly invoked tool, and verifies its audit hash chain.
2. [`corporate_recipient_policy.py`](corporate_recipient_policy.py) adds a
   restrictive policy module that rejects mail addressed outside the corporate
   domain.
3. [`constructive_profile.py`](constructive_profile.py) parses a `.slp` profile
   and shows `need` versus `want` behavior during constructive intersection.
4. [`legacy_report_reader.py`](legacy_report_reader.py) adds role, scope, and
   exact-file authorization around an unchanged legacy function.
5. [`legacy_mail_queue.py`](legacy_mail_queue.py) registers an unchanged legacy
   mail queue in a secured graph and adds a mandatory recipient policy.
6. [`resource_boundary.py`](resource_boundary.py) installs `ResourceBoundary`
   for two unchanged tools. With bubblewrap available, the restriction reaches
   actual Linux worker mounts. See
   [resource boundaries](../users/resource-boundary.md).

Run them from the repository checkout:

```bash
cd libs/prebuilt
uv run python ../../docs/security/examples/guarded_tool_audit.py
uv run python ../../docs/security/examples/corporate_recipient_policy.py
uv run python ../../docs/security/examples/constructive_profile.py
uv run python ../../docs/security/examples/legacy_report_reader.py
uv run python ../../docs/security/examples/legacy_mail_queue.py
uv run python ../../docs/security/examples/resource_boundary.py
```

## Retrofitting legacy tools

The two legacy demos share [`legacy_tools.py`](legacy_tools.py), a representative
old implementation with no LangGraph security imports or decorators. The mail
queue is an in-memory fixture: neither demo sends email or requires API keys.
The file reader uses temporary files that are removed when the program exits.

The integration code leaves those function bodies unchanged:

1. Convert the original callable using `StructuredTool.from_function`.
2. Attach `effects(...)` metadata to that new tool object.
3. Supply operator-owned `DacOverrides` in `SecurityConfig`; the legacy author
   does not need to add `@dac` declarations.
4. Expose only the returned `guarded_tool` wrapper or a secured `ToolNode`.
5. Bind a principal created by the authenticated application using
   `with_principal`. Roles and scopes never come from model arguments.

| Legacy operation | Enforcement entry point | Allowed | Denied |
| --- | --- | --- | --- |
| `read_report(path)` | Direct `guarded_tool` invocation | Analyst with `reports:read` reading the configured report | Another file, or a caller missing the scope |
| `queue_mail(to, subject, body)` | `ToolNode` in a compiled graph | Employee with `mail:send` addressing `corp.example` | An external recipient, even though the employee has call permission |

Expected output from the report demo:

```text
before (direct): Revenue: 42 units
allowed: Revenue: 42 units
denied (other report): dac:arg:path
denied (missing scope): dac:scope
audit chain: valid
```

Expected output from the mail demo:

```text
allowed: queued for bob@corp.example
denied: external_recipient
outbox: 1 internal message; denied call made no delivery
audit chain: valid
```

Direct guarded calls raise `SecurityDeniedError`. Graph calls return an error
`ToolMessage`. Each demo asserts these outcomes; the mail demo also checks that
the denied call did not add a message to the legacy outbox. No LLM is needed to
exercise the same tool-call boundary used by an agent.

These programs demonstrate in-process decisions, mediation, and audit. They do
not confine the legacy implementation: it remains trusted, and direct calls to
the original function are outside the boundary. In particular, normalized file
authorization here is not a race-resistant filesystem sandbox. For untrusted
local Python tools, see the implemented [Linux host execution](../users/linux-host-execution.md)
path. Its current subset does not support network or service authority, so it
cannot sandbox a production mail sender.
