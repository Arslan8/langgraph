"""Bind a principal and mediate a tool invoked outside `ToolNode`."""

from langgraph.prebuilt.security import (
    Effect,
    MemoryAuditSink,
    Principal,
    ResourceArg,
    SecurityConfig,
    dac,
    effects,
    guarded_tool,
    with_principal,
)


def main() -> None:
    """Run one allowed call and verify its tamper-evident audit chain."""
    audit = MemoryAuditSink()
    security = SecurityConfig(audit_sink=audit)

    @guarded_tool(security=security)
    @dac(
        owner="support",
        grants={"support": "x", "*": "-"},
        required_scopes={"records:read"},
        arg_grants={"record_id": {"case-123": "x", "*": "-"}},
    )
    @effects(Effect.READ, resources=[ResourceArg("record_id", "record")])
    def lookup_record(record_id: str) -> str:
        """Return a record from this example's in-memory fixture."""
        records = {"case-123": "replacement approved"}
        return records[record_id]

    principal = Principal(
        "alice",
        frozenset({"support"}),
        frozenset({"records:read"}),
        "example-session",
    )
    config = with_principal({}, principal, modules=security.modules)

    result = lookup_record.invoke({"record_id": "case-123"}, config=config)
    integrity, invalid_index = audit.verify()

    assert result == "replacement approved"
    assert (integrity, invalid_index) == (True, None)
    print(f"result: {result}")
    print(
        "audit:",
        [
            (record.stage, record.module, record.verdict.value)
            for record in audit.records()
        ],
    )


if __name__ == "__main__":
    main()
