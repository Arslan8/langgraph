# Declare and authorize tools

Tool authors describe what a tool may do and propose its discretionary access
control. Operators may replace that DAC, but neither declarations nor profiles
prove what hostile code actually does.

## Describe effects and resources

Use `@effects` with every possible effect and identify arguments that name
protected resources:

```python
from langgraph.prebuilt.security import Effect, ResourceArg, effects

@effects(
    Effect.SEND,
    Effect.NETWORK,
    resources=[ResourceArg("to", "email", "email_domain", origin="remote")],
    sensitivity="sensitive",
    reversible=False,
)
def send_email(to: str, subject: str, body: str) -> str:
    """Send a message."""
    ...
```

Built-in normalizers include `realpath`, `domain`, `email_domain`,
`sql_statement_kind`, and `shell_argv0`. Policy consumes normalized values, not
raw string prefixes. `realpath` is for resources on the local host. Remote
resources must use syntax appropriate to the remote service; do not resolve a
remote path against the coordinator's filesystem.

If a descriptor is absent, the framework infers `EXEC`, critical sensitivity,
and irreversible behavior. This is a restrictive fallback, not useful policy
metadata.

## Declare author DAC

```python
from langgraph.prebuilt.security import dac

@dac(
    owner="analyst",
    grants={"analyst": "x", "manager": "x", "*": "-"},
    required_scopes={"email:send"},
    arg_grants={"to_domain": {"corp.example": "x", "*": "-"}},
)
def send_email(to: str, subject: str, body: str) -> str:
    ...
```

The call is allowed by DAC only when all of these hold:

- the user or one of its roles is the owner, has `x`, or matches fallback `*`;
- every required scope is present; and
- every applicable normalized argument grant is `x`.

DAC executes before mandatory modules. A DAC denial stops the chain, and no
module can convert it to an allow. An undeclared tool defaults to owner
`__operator__`, fallback deny, and required scope `tool:<name>`.

## Apply an operator override

An operator can replace a tool's DAC wholesale:

```python
from langgraph.prebuilt.security import DacOverrides, SecurityConfig, ToolDac

overrides = DacOverrides(
    {
        "send_email": ToolDac(
            owner="communications",
            grants={"communications": "x", "*": "-"},
            required_scopes=frozenset({"email:send"}),
            arg_grants={"to_domain": {"corp.example": "x", "*": "-"}},
        )
    }
)
security = SecurityConfig(dac_overrides=overrides)
```

Overrides are trusted configuration, equivalent to an operator changing file
permissions. Unknown tool names fail configuration, and an audit sink records
each applied override.

For constructive resource grants, use the frozen `.slp` grammar described in
[profiles](../profiles.md). The current runtime tool-call path uses `ToolDac`;
native enforcement of compiled grants is not yet wired into tool execution.

