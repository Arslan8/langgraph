"""Example 4: derive and enforce a resource operation from a tool invocation.

The manifest maps `read_file(path)` to `fs::read` on the normalized path. Try:

- principal `alice` and the default path: allowed;
- principal `bob` and the default path: denied; or
- principal `alice` and another existing path: denied.

The tool is intentionally trusted and runs in process. Its effective permission
is the intersection of the Cedar-authorized grant and the coordinator's host
permission to read the same canonical file.
"""

import json
from pathlib import Path

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
    cedar_security,
    effects,
    with_principal,
)
from langgraph.prebuilt.security.inprocess import read_text

ALLOWED_PATH = str(Path(__file__).resolve())

# `fs` is a built-in class. The invocation argument is not merely data: the
# manifest maps it to a required operation, and the built-in `fs.realpath`
# normalizer canonicalizes @{path} before Cedar sees it.
MANIFEST = """
runs inprocess
fs read @{path} need
returns sensitive
"""

# There are two checks. The first permits Alice to enter this tool. The second
# permits fs::read only for the canonical path to this example file.
POLICY = f"""
permit (
  principal == slangGraph::User::"alice",
  action == slangGraph::Action::"call",
  resource
);

permit (
  principal == slangGraph::User::"alice",
  action == slangGraph::Action::"fs::read",
  resource
) when {{
  resource.selector == {json.dumps(ALLOWED_PATH)}
}};
"""


@tool
@effects(
    Effect.READ,
    resources=[ResourceArg("path", "path", "realpath")],
    sensitivity="sensitive",
)
def read_file(path: str) -> str:
    """Read a text file through the approved resource API."""
    return read_text(path)


# Passing the tool binds its internal identity. `classes=` is only needed when
# a plugin or power user introduces a new object class.
security = cedar_security(
    read_file,
    manifest=MANIFEST,
    policy=POLICY,
)

builder = StateGraph(MessagesState)
builder.add_node("tools", ToolNode([read_file]))
builder.add_edge(START, "tools")
graph = builder.compile(security=security)

# Demo only: production code derives the principal from authentication.
principal_id = input("Principal ID (try alice or bob): ").strip()
if not principal_id:
    raise SystemExit("Principal ID cannot be empty")

requested_path = input(f"Path [{ALLOWED_PATH}]: ").strip() or ALLOWED_PATH
principal = Principal(principal_id, frozenset(), frozenset(), "cli-session")
config = with_principal({}, principal, modules=security.modules)


def denial_message(reason: str) -> str:
    """Turn internal denial codes into useful CLI messages for this demo."""
    reason = reason.removeprefix("Access denied by security: ").removeprefix(
        "object_policy:"
    )
    if reason.startswith("invalid_object:fs:read:"):
        return "Denied: " + reason.removeprefix("invalid_object:fs:read:") + "."
    if reason.startswith("dac:envelope_call:"):
        return "Denied: this principal may not call read_file."
    if reason.startswith("dac:envelope:read_file:"):
        return "Denied: policy does not allow reading that path."
    return f"Denied by security policy: {reason}"


try:
    result = graph.invoke(
        {
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": "read_file",
                            "args": {"path": requested_path},
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

# Successful authorization exposes the exact grant for review.
executor = security.host_executor
if isinstance(executor, ObjectPolicyHostExecutor):
    grants = executor.authorization_grants()
    if grants:
        print("Authorized grant:")
        for line in grants[-1].lines:
            print(f"  {line.class_name}::{line.operation} {line.selector}")
    artifacts = executor.authorizer.authorization_artifacts()
    if artifacts:
        print(f"Cedar schema, entities, policies, and requests: {artifacts[-1]}")
