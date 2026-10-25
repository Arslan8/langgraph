"""Operator-owned mandatory policy for the entire Python runtime.

The controller, its configuration, callbacks, and installed Python code are
trusted. This is not a kernel LSM: arbitrary hostile code in that controller
requires OS isolation. Unsupported graph bodies fail closed under runtime MAC.
"""

from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from typing import Any
from weakref import WeakKeyDictionary

from langgraph._internal._runtime_policy import (
    install_runtime_policy,
    runtime_policy,
)

from langgraph.prebuilt.security.errors import SecurityConfigurationError

_graph_lock = RLock()
_graph_boundaries: WeakKeyDictionary[Any, tuple[Any, ...] | None] = WeakKeyDictionary()


def register_mac_boundary(graph: Any) -> None:
    """Record the actual mediated nodes at trusted SecurityConfig compilation."""
    from langgraph.prebuilt.security.placement import MediatedNode
    from langgraph.prebuilt.tool_node import ToolNode

    builder = graph.builder
    nodes = tuple(node.runnable for node in builder.nodes.values())
    supported = not any(builder.branches.values()) and all(
        type(node) is MediatedNode and type(node.runnable) is ToolNode for node in nodes
    )
    with _graph_lock:
        _graph_boundaries[graph] = (
            tuple(node.runnable for node in nodes) if supported else None
        )


@dataclass(frozen=True, slots=True)
class RuntimeMAC:
    """Immutable operator forbids shared by every graph, session, and tool."""

    forbids: str

    def __post_init__(self) -> None:
        from langgraph.prebuilt.security.object_policy import _require_policy_effect

        if not self.forbids.strip():
            raise ValueError("runtime MAC policy must not be empty")
        _require_policy_effect(self.forbids, "forbid")

    def check(self, target: Any) -> None:
        from langgraph.graph.state import CompiledStateGraph

        from langgraph.prebuilt.tool_node import ToolNode

        if type(target) is ToolNode:
            self._check_tool_node(target)
            return
        if type(target) is not CompiledStateGraph:
            raise SecurityConfigurationError("mac:unsupported_execution_boundary")
        with _graph_lock:
            if target not in _graph_boundaries:
                raise SecurityConfigurationError("mac:graph_requires_security")
            nodes = _graph_boundaries[target]
        if nodes is None:
            raise SecurityConfigurationError("mac:unconfined_graph_body")
        for node in nodes:
            self._check_tool_node(node)

    def _check_tool_node(self, node: Any) -> None:
        from langgraph.prebuilt.security.object_broker import ObjectBrokerDispatcher
        from langgraph.prebuilt.security.object_policy import (
            CedarObjectAuthorizer,
            ObjectPolicyHostExecutor,
            _TrustedInProcessDispatcher,
        )

        executor = node._security_host_executor
        if type(executor) is not ObjectPolicyHostExecutor:
            raise SecurityConfigurationError("mac:tool_requires_object_authorization")
        if type(executor.authorizer) is not CedarObjectAuthorizer:
            raise SecurityConfigurationError("mac:unsupported_authorizer")
        if executor.authorizer.enforcement_waivers:
            raise SecurityConfigurationError("mac:enforcement_waivers_forbidden")
        if type(executor.dispatcher) not in (
            ObjectBrokerDispatcher,
            _TrustedInProcessDispatcher,
        ):
            raise SecurityConfigurationError("mac:unsupported_dispatcher")
        if node._wrap_tool_call is not None or node._awrap_tool_call is not None:
            raise SecurityConfigurationError("mac:unconfined_tool_wrapper")


def install_mac_policy(forbids: str) -> None:
    """Install operator MAC once, before any graph or ToolNode executes.

    Used by standalone trusted bootstrap. Deployments can instead provision
    `mac.cedar` in `LANGGRAPH_MAC_DIR` (default `/etc/langgraph`), which is
    loaded automatically and takes precedence.
    Graph-local policies can add restrictions but cannot replace these forbids.
    Graphs without supported mediation are refused, including precompiled graphs,
    raw Pregel programs, arbitrary Python nodes, and direct unsecured ToolNodes.
    """
    install_runtime_policy(RuntimeMAC(forbids))


def runtime_mac_forbids() -> str:
    """Read the sealed operator policy at authorization time."""
    policy = runtime_policy()
    return policy.forbids if isinstance(policy, RuntimeMAC) else ""
