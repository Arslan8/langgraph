"""Framework discretionary access-control evaluation."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from langgraph.prebuilt.security.types import Decision, Principal, Tool, Verdict


def dac_check(
    principal: Principal, tool: Tool, normalized: Mapping[str, Any]
) -> Decision:
    """Evaluate the tool author's DAC before any security module runs.

    The check allows a call only when the principal is the owner or has an
    execute grant, holds every required scope, and passes every applicable
    normalized-argument grant. Reasons identify clauses but never values.
    """

    owner = tool.dac.owner
    owns_tool = principal.user_id == owner or owner in principal.roles
    grants = tool.dac.grants
    if principal.user_id in grants and principal.user_id != "*":
        granted = grants[principal.user_id] == "x"
    else:
        role_entries = [
            grants[role] for role in principal.roles if role != "*" and role in grants
        ]
        granted = "-" not in role_entries if role_entries else grants.get("*") == "x"
    if not (owns_tool or granted):
        return Decision(Verdict.DENY, "dac:grant")

    if not tool.dac.required_scopes.issubset(principal.scopes):
        return Decision(Verdict.DENY, "dac:scope")

    for arg_name, grants in tool.dac.arg_grants.items():
        if arg_name not in normalized:
            return Decision(Verdict.DENY, f"dac:arg_missing:{arg_name}")
        value_key = str(normalized[arg_name])
        if grants.get(value_key, grants.get("*", "-")) != "x":
            return Decision(Verdict.DENY, f"dac:arg:{arg_name}")

    return Decision(Verdict.ALLOW, "dac:allow")
