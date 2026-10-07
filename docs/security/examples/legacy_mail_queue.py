"""Secure an unchanged legacy mail queue at a graph's ToolNode boundary."""

from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.tools import StructuredTool
from langgraph.graph import START, MessagesState, StateGraph
from legacy_tools import OUTBOX, queue_mail

from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    DacOverrides,
    Decision,
    Effect,
    MemoryAuditSink,
    Principal,
    ResourceArg,
    SecurityConfig,
    SecurityModule,
    ToolCall,
    ToolDac,
    Verdict,
    effects,
    with_principal,
)


class CorporateRecipientsOnly(SecurityModule):
    """Operator policy for this graph's mail tool."""

    name = "corporate_recipients"

    def tool_call_permission(self, principal: Principal, call: ToolCall) -> Decision:
        if call.tool.name == "queue_mail" and call.normalized.get("to_domain") != (
            "corp.example"
        ):
            return Decision(Verdict.DENY, "external_recipient")
        return Decision(Verdict.ALLOW, "corporate_recipient")


def main() -> None:
    """Check the graph response and actual outbox after each requested delivery."""
    OUTBOX.clear()
    # Before: queue_mail(to, subject, body) directly enqueues any recipient.
    # After: register this new adapter instead of exposing the original callable.
    adapted = StructuredTool.from_function(queue_mail)
    effects(
        Effect.SEND,
        resources=[ResourceArg("to", "email", "email_domain", origin="remote")],
        reversible=False,
    )(adapted)
    audit = MemoryAuditSink()
    security = SecurityConfig(
        modules=[CorporateRecipientsOnly()],
        audit_sink=audit,
        dac_overrides=DacOverrides(
            {
                "queue_mail": ToolDac(
                    owner="mail-service",
                    grants={"employee": "x", "*": "-"},
                    required_scopes=frozenset({"mail:send"}),
                )
            }
        ),
    )
    builder = StateGraph(MessagesState)
    builder.add_node("tools", ToolNode([adapted]))
    builder.add_edge(START, "tools")
    graph = builder.compile(security=security)
    alice = Principal(
        "alice", frozenset({"employee"}), frozenset({"mail:send"}), "mail"
    )
    config = with_principal({}, alice, modules=security.modules)

    # Fixed model-shaped requests make the demo deterministic; no model/API key.
    for index, recipient in enumerate(("bob@corp.example", "eve@outside.example")):
        result = graph.invoke(
            {
                "messages": [
                    AIMessage(
                        content="",
                        tool_calls=[
                            {
                                "name": "queue_mail",
                                "args": {
                                    "to": recipient,
                                    "subject": "Quarterly report",
                                    "body": "Revenue: 42 units",
                                },
                                "id": f"mail-{index}",
                            }
                        ],
                    )
                ]
            },
            config=config,
        )
        response = result["messages"][-1]
        assert isinstance(response, ToolMessage)
        if index == 0:
            assert response.status == "success"
            assert response.content == "queued for bob@corp.example"
            print(f"allowed: {response.content}")
        else:
            assert response.status == "error"
            assert "external_recipient" in str(response.content)
            print("denied: external_recipient")
        assert len(OUTBOX) == 1
        assert OUTBOX[0]["to"] == "bob@corp.example"

    assert audit.verify() == (True, None)
    print("outbox: 1 internal message; denied call made no delivery")
    print("audit chain: valid")


if __name__ == "__main__":
    main()
