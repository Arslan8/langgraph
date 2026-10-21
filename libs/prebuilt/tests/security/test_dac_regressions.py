"""Execution regressions for explicit DAC gates and omitted arguments."""

from dataclasses import replace
from unittest.mock import Mock

import pytest
from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from langgraph.runtime import Runtime

from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    DacOverrides,
    Effect,
    Principal,
    ResourceArg,
    SecurityConfig,
    SecurityDeniedError,
    ToolDac,
    cedar_security,
    dac,
    effects,
    guarded_tool,
    with_principal,
)


def config():
    return with_principal(
        {"configurable": {"__pregel_runtime": Runtime()}},
        Principal("alice", frozenset(), frozenset(), "dac-regression"),
    )


def request(name, args):
    return {
        "messages": [
            AIMessage(
                content="", tool_calls=[{"name": name, "args": args, "id": "test"}]
            )
        ]
    }


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("guarded", [False, True])
async def test_omitted_default_cannot_bypass_argument_dac(asynchronous, guarded):
    executed = []

    @tool
    @dac(
        owner="owner", grants={"*": "x"}, arg_grants={"path": {"/safe": "x", "*": "-"}}
    )
    @effects(Effect.READ, resources=[ResourceArg("path", "file")])
    def reader(path: str = "/forbidden") -> str:
        """Return a path without reading a file."""
        executed.append(path)
        return path

    if guarded:
        target = guarded_tool(reader, security=SecurityConfig())
        # The guarded wrapper materializes its default before the security gate.
        with pytest.raises(SecurityDeniedError, match="dac:arg:path"):
            if asynchronous:
                await target.ainvoke({}, config=config())
            else:
                target.invoke({}, config=config())
        assert not executed
        if asynchronous:
            assert await target.ainvoke({"path": "/safe"}, config=config()) == "/safe"
        else:
            assert target.invoke({"path": "/safe"}, config=config()) == "/safe"
    else:
        target = ToolNode([reader], security=SecurityConfig())
        try:
            denied = (
                await target.ainvoke(request("reader", {}), config=config())
                if asynchronous
                else target.invoke(request("reader", {}), config=config())
            )
            assert "dac:arg_missing:path" in denied["messages"][-1].content
            assert not executed
            allowed = (
                await target.ainvoke(
                    request("reader", {"path": "/safe"}), config=config()
                )
                if asynchronous
                else target.invoke(
                    request("reader", {"path": "/safe"}), config=config()
                )
            )
            assert allowed["messages"][-1].content == "/safe"
        finally:
            target._security_stack.close()
    assert executed == ["/safe"]


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("restriction", ["grant", "scope", "argument"])
@pytest.mark.parametrize("origin", ["author", "override"])
async def test_external_dac_preserves_explicit_restrictions(
    asynchronous, restriction, origin
):
    policies = {
        "grant": ToolDac("owner", {"*": "-"}),
        "scope": ToolDac("owner", {"*": "x"}, frozenset({"required"})),
        "argument": ToolDac("owner", {"*": "x"}, arg_grants={"path": {"*": "-"}}),
    }
    policy = policies[restriction]

    @tool
    @effects(Effect.READ, resources=[ResourceArg("path", "file")])
    def reader(path: str) -> str:
        """Must not execute with a rejected DAC gate."""
        raise AssertionError("executed denied tool")

    if origin == "author":
        dac(
            owner=policy.owner,
            grants=policy.grants,
            required_scopes=policy.required_scopes,
            arg_grants=policy.arg_grants,
        )(reader)
    host = Mock()
    host.authorizes_dac = True
    security = SecurityConfig(
        host_executor=host,
        dac_overrides=DacOverrides({"reader": policy})
        if origin == "override"
        else None,
    )
    node = ToolNode([reader], security=security)
    try:
        result = (
            await node.ainvoke(request("reader", {"path": "/safe"}), config=config())
            if asynchronous
            else node.invoke(request("reader", {"path": "/safe"}), config=config())
        )
        assert result["messages"][-1].status == "error"
        host.invoke.assert_not_called()
        host.ainvoke.assert_not_called()
        assert node._security_tools_by_name["reader"].dac == policy
    finally:
        node._security_stack.close()


def test_cedar_helper_preserves_author_dac_and_operator_override():
    @tool
    @dac(owner="owner", grants={"*": "x"}, required_scopes=["required"])
    def reader(path: str) -> str:
        """Return fixture data."""
        return path

    security = cedar_security(
        reader,
        manifest="fs read @{path} need",
        policy="permit(principal, action, resource);",
    )
    assert security.dac_overrides["reader"].required_scopes == frozenset({"required"})
    override = ToolDac("owner", {"*": "-"})
    node = ToolNode(
        [reader],
        security=replace(security, dac_overrides=DacOverrides({"reader": override})),
    )
    try:
        assert node._security_tools_by_name["reader"].dac == override
    finally:
        node._security_stack.close()


def test_external_dac_can_replace_only_inferred_default():
    @tool
    def reader(path: str) -> str:
        """Return fixture data."""
        return path

    host = Mock()
    host.authorizes_dac = True
    node = ToolNode([reader], security=SecurityConfig(host_executor=host))
    try:
        assert node._security_tools_by_name["reader"].dac.grants == {"*": "x"}
        assert not node._security_tools_by_name["reader"].dac.required_scopes
    finally:
        node._security_stack.close()
