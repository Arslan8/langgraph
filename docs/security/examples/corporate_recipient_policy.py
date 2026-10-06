"""Compose author DAC with a restrictive recipient policy module."""

from langgraph.prebuilt.security import (
    Decision,
    Effect,
    Principal,
    ResourceArg,
    SecurityConfig,
    SecurityDeniedError,
    SecurityModule,
    ToolCall,
    Verdict,
    dac,
    effects,
    guarded_tool,
    with_principal,
)


class CorporateRecipientsOnly(SecurityModule):
    """Forbid mail delivery outside the normalized corporate domain."""

    name = "corporate_recipients"

    def tool_call_permission(self, principal: Principal, call: ToolCall) -> Decision:
        if call.normalized.get("to_domain") != "corp.example":
            return Decision(Verdict.DENY, "external_recipient")
        return Decision(Verdict.ALLOW, "corporate_recipient")


def main() -> None:
    """Allow an internal recipient and reject an external one."""
    security = SecurityConfig(modules=[CorporateRecipientsOnly()])

    @guarded_tool(security=security)
    @dac(
        owner="messaging",
        grants={"employee": "x", "*": "-"},
        required_scopes={"mail:send"},
    )
    @effects(
        Effect.SEND,
        resources=[ResourceArg("to", "email", "email_domain", origin="remote")],
        reversible=False,
    )
    def send_mail(to: str, subject: str) -> str:
        """Return what the mock mail service would enqueue."""
        return f"queued {subject!r} for {to}"

    principal = Principal(
        "alice",
        frozenset({"employee"}),
        frozenset({"mail:send"}),
        "example-session",
    )
    config = with_principal({}, principal, modules=security.modules)

    allowed = send_mail.invoke(
        {"to": "bob@corp.example", "subject": "Quarterly report"},
        config=config,
    )
    assert allowed == "queued 'Quarterly report' for bob@corp.example"
    print(f"allowed: {allowed}")

    try:
        send_mail.invoke(
            {"to": "eve@outside.example", "subject": "Quarterly report"},
            config=config,
        )
    except SecurityDeniedError as exc:
        assert str(exc) == "external_recipient"
        print(f"denied: {exc}")
    else:
        raise AssertionError("external recipient unexpectedly allowed")


if __name__ == "__main__":
    main()
