"""Example 5: add a custom resource class and authorize its attributes.

Try these combinations:

- principal `alice`, record `alice-report`: allowed;
- principal `alice`, record `bob-plan`: denied;
- principal `bob`, record `bob-plan`: allowed; or
- either principal and an unknown record: denied.

The records are in memory so the example needs no database. In a real system,
the trusted label provider and tool would obtain records from the same trusted
database or broker.
"""

from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from langgraph.graph import START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    Effect,
    HostExecutionDenied,
    ObjectPolicyHostExecutor,
    Principal,
    ResourceArg,
    ToolCall,
    cedar_security,
    effects,
    with_principal,
)


RECORDS = {
    "alice-report": {
        "owner": "alice",
        "department": "finance",
        "value": "Quarterly revenue increased by 12%.",
    },
    "bob-plan": {
        "owner": "bob",
        "department": "engineering",
        "value": "Release candidate ships on Friday.",
    },
}

# This is the extension point. `record` is not built into slangGraph. Declaring
# it creates RecordItem entities and record::read / record::update Cedar actions.
# This demo requests only `read`, illustrating that a tool need not receive every
# operation its class supports.
CLASSES = """
class record {
  operations read update
  object item
  normalizer identity
  attrs owner department
  enforced_by trusted_tool
}
"""

MANIFEST = """
runs inprocess
record read @{record_id} need
returns sensitive
"""

# Call permission controls entry to the tool. Resource permission is narrower:
# each principal may read only a RecordItem carrying that principal's owner
# label. These labels come from the trusted provider below, not tool arguments.
POLICY = """
permit (
  principal == slangGraph::User::"alice",
  action == slangGraph::Action::"call",
  resource
);
permit (
  principal == slangGraph::User::"bob",
  action == slangGraph::Action::"call",
  resource
);

permit (
  principal == slangGraph::User::"alice",
  action == slangGraph::Action::"record::read",
  resource
) when {
  resource.owner == "alice"
};
permit (
  principal == slangGraph::User::"bob",
  action == slangGraph::Action::"record::read",
  resource
) when {
  resource.owner == "bob"
};
"""


def record_labels(
    _principal: Principal, call: ToolCall
) -> dict[tuple[str, str], dict[str, str]]:
    """Return trusted Cedar attributes for the requested canonical record."""
    record_id = str(call.normalized.get("record_id", call.args["record_id"]))
    record = RECORDS.get(record_id)
    if record is None:
        return {}
    return {
        ("record", record_id): {
            "owner": record["owner"],
            "department": record["department"],
        }
    }


@tool
@effects(
    Effect.READ,
    resources=[ResourceArg("record_id", "record")],
    sensitivity="sensitive",
)
def read_record(record_id: str) -> str:
    """Read one in-memory record."""
    return RECORDS[record_id]["value"]


security = cedar_security(
    read_record,
    classes=CLASSES,
    manifest=MANIFEST,
    policy=POLICY,
    labels=record_labels,
)

builder = StateGraph(MessagesState)
builder.add_node("tools", ToolNode([read_record]))
builder.add_edge(START, "tools")
graph = builder.compile(security=security)

principal_id = input("Principal ID (try alice or bob): ").strip()
if not principal_id:
    raise SystemExit("Principal ID cannot be empty")
record_id = input("Record ID [alice-report]: ").strip() or "alice-report"

principal = Principal(principal_id, frozenset(), frozenset(), "cli-session")
config = with_principal({}, principal, modules=security.modules)


def denial_message(reason: str) -> str:
    """Turn internal denial codes into a useful message for this demo."""
    reason = reason.removeprefix("Access denied by security: ").removeprefix(
        "object_policy:"
    )
    if reason.startswith("dac:envelope_call:"):
        return "Denied: this principal may not call read_record."
    if reason.startswith("dac:envelope:read_record:"):
        return "Denied: this principal may not read that record."
    return f"Denied by security policy: {reason}"


try:
    result = graph.invoke(
        {
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": "read_record",
                            "args": {"record_id": record_id},
                            "id": "call-1",
                        }
                    ],
                )
            ]
        },
        config=config,
    )
except HostExecutionDenied as exc:
    raise SystemExit(denial_message(str(exc))) from None

message = result["messages"][-1]
content = str(message.content)
if getattr(message, "status", None) == "error":
    raise SystemExit(denial_message(content)) from None

print(content)

# Review both the exact grant and the raw Cedar input bundle.
executor = security.host_executor
if isinstance(executor, ObjectPolicyHostExecutor):
    grants = executor.authorization_grants()
    if grants:
        print("Authorized grant:")
        for line in grants[-1].lines:
            attrs = ", ".join(f"{key}={value}" for key, value in line.attributes.items())
            print(
                f"  {line.class_name}::{line.operation} {line.selector} ({attrs})"
            )
    artifacts = executor.authorizer.authorization_artifacts()
    if artifacts:
        print(f"Cedar schema, entities, policies, and requests: {artifacts[-1]}")
