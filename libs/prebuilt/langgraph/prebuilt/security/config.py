"""Public configuration and compile-time setup for security mediation."""

from __future__ import annotations

import hashlib
import json
import secrets
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import Any

from langgraph.checkpoint.base import BaseCheckpointSaver

from langgraph.prebuilt.security.checkpoint_security import MediatedCheckpointer
from langgraph.prebuilt.security.descriptor import DacOverrides, _has_declared_dac
from langgraph.prebuilt.security.errors import SecurityConfigurationError
from langgraph.prebuilt.security.execution import HostToolExecutor
from langgraph.prebuilt.security.flow import SessionFlowPolicy
from langgraph.prebuilt.security.hooks import SecurityModule
from langgraph.prebuilt.security.host_boundary import (
    make_authorized_host_router,
    make_host_router,
)
from langgraph.prebuilt.security.object_manager import (
    ObjectManagerHost,
    ObjectManagerPolicy,
    ToolObjectDac,
)
from langgraph.prebuilt.security.observability import SecurityObserver
from langgraph.prebuilt.security.placement import (
    MediatedBranch,
    MediatedNode,
    NodeKind,
    NodeTrust,
    OutputMediator,
    PlacementSpec,
    UntrustedNodeHost,
    resolve_placement,
)
from langgraph.prebuilt.security.profile import ToolProfile
from langgraph.prebuilt.security.stack import SecurityStack
from langgraph.prebuilt.security.types import AuditRecord, AuditSink, Tool, Verdict


@dataclass(frozen=True, slots=True)
class SecurityConfig:
    """Configure restrictive modules, operator DACs, auditing, and identity rules."""

    modules: Sequence[SecurityModule] = ()
    dac_overrides: DacOverrides | None = None
    audit_sink: AuditSink | None = None
    observer: SecurityObserver | None = None
    policy_timeout_s: float = 2.0
    approval_ttl_s: float = 300.0
    require_principal: bool = True
    flow_policy: SessionFlowPolicy | None = None
    host_executor: HostToolExecutor | None = None
    object_dacs: Mapping[str, ToolObjectDac] = field(default_factory=dict)
    untrusted_node_host: UntrustedNodeHost | None = None
    output_destination: str = "caller"
    output_clearance: frozenset[str] = frozenset()
    checkpoint_key: bytes | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "modules", tuple(self.modules))
        object.__setattr__(
            self, "object_dacs", MappingProxyType(dict(self.object_dacs))
        )
        object.__setattr__(self, "output_clearance", frozenset(self.output_clearance))
        if not self.output_destination:
            raise ValueError("output_destination must be non-empty")
        if any(not item for item in self.output_clearance):
            raise ValueError("output_clearance labels must be non-empty")
        if self.untrusted_node_host is not None and not isinstance(
            self.untrusted_node_host, UntrustedNodeHost
        ):
            raise TypeError("untrusted_node_host must implement UntrustedNodeHost")
        if self.checkpoint_key is None:
            object.__setattr__(self, "checkpoint_key", secrets.token_bytes(32))
        elif not self.checkpoint_key:
            raise ValueError("checkpoint_key must be non-empty")
        if self.policy_timeout_s <= 0:
            raise ValueError("policy_timeout_s must be positive")
        if self.approval_ttl_s <= 0:
            raise ValueError("approval_ttl_s must be positive")
        if self.dac_overrides is not None and not isinstance(
            self.dac_overrides, DacOverrides
        ):
            raise TypeError("dac_overrides must be DacOverrides or None")
        if (
            self.host_executor is not None
            and self.flow_policy is not None
            and not self.flow_policy.store.persistent
        ):
            raise SecurityConfigurationError(
                "host execution with session flow requires a persistent flow store"
            )

    @property
    def can_escalate(self) -> bool:
        """Whether any configured module can request durable human approval."""
        return any(module.can_escalate for module in self.modules)

    def configure_graph(self, graph: Any, *, checkpointer: Any) -> Any:
        """Place every graph operation on the shared refusing router path."""
        if self.can_escalate and checkpointer in (None, False):
            raise ValueError(
                "security modules that can escalate require a checkpointer"
            )
        nodes = tuple(_find_tool_nodes(graph))
        known_tools = {name for node in nodes for name in node._security_tools_by_name}
        overrides = self.dac_overrides or DacOverrides()
        unknown = set(overrides).difference(known_tools)
        if unknown:
            names = ", ".join(sorted(unknown))
            raise ValueError(f"DAC overrides reference unknown tools: {names}")
        unknown_object_dacs = set(self.object_dacs).difference(known_tools)
        if unknown_object_dacs:
            names = ", ".join(sorted(unknown_object_dacs))
            raise ValueError(f"object DACs reference unknown tools: {names}")
        if self.flow_policy is not None:
            self.flow_policy.validate_tools(tuple(known_tools))
        if self.host_executor is not None:
            self.host_executor.validate_tools(tuple(known_tools))
        graph_tools = {
            name: tool
            for node in nodes
            for name, tool in node._security_tools_by_name.items()
        }
        object_host = ObjectManagerHost(
            checkpoint_key=self.checkpoint_key or b"",
            tools=graph_tools,
        )
        for node in nodes:
            self.configure_tool_node(
                node,
                validate_overrides=False,
                _object_host=object_host,
            )
        placement_stack = SecurityStack(
            self.modules,
            policy_timeout_s=self.policy_timeout_s,
            observer=self.observer,
            audit_sink=self.audit_sink,
            approval_ttl_s=self.approval_ttl_s,
        )
        placement_router = make_host_router(
            ObjectManagerPolicy(placement_stack, self.object_dacs), object_host
        )
        inprocess_tool_policy = any(
            getattr(module, "authorizes_inprocess_tools", False)
            for module in self.modules
        )
        for name, node_spec in graph.nodes.items():
            contains_tool_node = any(_find_tool_nodes(node_spec.runnable))
            try:
                placement = resolve_placement(
                    name, node_spec.runnable, node_spec.metadata
                )
            except ValueError as exc:
                placement_stack.close()
                raise SecurityConfigurationError(str(exc)) from exc
            if contains_tool_node and (
                self.host_executor is not None or inprocess_tool_policy
            ):
                placement = PlacementSpec(
                    name,
                    NodeTrust.TRUSTED,
                    NodeKind.STANDARD,
                    promoted=True,
                    promotion_reason=(
                        (
                            "reviewed ToolNode coordinator; tool bodies use host "
                            "execution"
                        )
                        if self.host_executor is not None
                        else "Cedar-authorized operator tool runs in process"
                    ),
                )
            if (
                placement.trust is NodeTrust.UNTRUSTED
                and self.untrusted_node_host is None
            ):
                placement_stack.close()
                raise SecurityConfigurationError(
                    f"untrusted node requires a separate-process host:{name}"
                )
            if placement.promoted:
                self._audit_node_promotion(placement)
            node_spec.runnable = MediatedNode(
                node_spec.runnable,
                placement,
                placement_router,
                untrusted_host=self.untrusted_node_host,
            )
        for source, branches in graph.branches.items():
            for branch_name, branch in tuple(branches.items()):
                placement_name = f"{source}:branch:{branch_name}"
                try:
                    placement = resolve_placement(placement_name, branch.path, None)
                except ValueError as exc:
                    placement_stack.close()
                    raise SecurityConfigurationError(str(exc)) from exc
                if (
                    placement.trust is NodeTrust.UNTRUSTED
                    and self.untrusted_node_host is None
                ):
                    placement_stack.close()
                    raise SecurityConfigurationError(
                        "untrusted branch requires a separate-process host:"
                        + placement_name
                    )
                branches[branch_name] = branch._replace(
                    path=MediatedBranch(
                        branch.path,
                        placement_name,
                        placement_router,
                        trust=placement.trust,
                        untrusted_host=self.untrusted_node_host,
                    )
                )
        if not all(
            isinstance(node_spec.runnable, MediatedNode)
            for node_spec in graph.nodes.values()
        ):
            placement_stack.close()
            raise SecurityConfigurationError("unplaceable graph node")
        if not all(
            isinstance(branch.path, MediatedBranch)
            for branches in graph.branches.values()
            for branch in branches.values()
        ):
            placement_stack.close()
            raise SecurityConfigurationError("unplaceable graph branch")
        graph._security_placement_stack = placement_stack
        graph._security_output_mediator = OutputMediator(
            placement_router,
            object_host,
            destination=self.output_destination,
            clearance=self.output_clearance,
        )
        graph._security_config = self
        if isinstance(checkpointer, MediatedCheckpointer):
            return checkpointer
        if isinstance(checkpointer, BaseCheckpointSaver):
            return MediatedCheckpointer(
                checkpointer, placement_router, self.checkpoint_key or b""
            )
        return checkpointer

    def configure_compiled_graph(self, graph: Any) -> None:
        """Install the graph's refusing output route on every stream emission."""
        builder = getattr(graph, "builder", None)
        mediator = getattr(builder, "_security_output_mediator", None)
        install = getattr(graph, "_set_output_filter", None)
        if mediator is None or not callable(install):
            raise SecurityConfigurationError("compiled graph lacks output placement")
        install(mediator, mediator.acall)
        from langgraph.prebuilt.security.mac import register_mac_boundary

        register_mac_boundary(graph)

    def configure_tool_node(
        self,
        node: Any,
        *,
        validate_overrides: bool = True,
        _object_host: ObjectManagerHost | None = None,
    ) -> None:
        """Apply this configuration to one ToolNode."""
        existing = getattr(node, "_security_config", None)
        if existing is self:
            return
        if existing is not None:
            raise SecurityConfigurationError(
                "a secured ToolNode cannot be reconfigured or downgraded"
            )
        overrides = self.dac_overrides or DacOverrides()
        unknown = set(overrides).difference(node._security_tools_by_name)
        if validate_overrides and unknown:
            names = ", ".join(sorted(unknown))
            raise ValueError(f"DAC overrides reference unknown tools: {names}")
        unknown_object_dacs = set(self.object_dacs).difference(
            node._security_tools_by_name
        )
        if validate_overrides and unknown_object_dacs:
            names = ", ".join(sorted(unknown_object_dacs))
            raise ValueError(f"object DACs reference unknown tools: {names}")
        if self.flow_policy is not None:
            self.flow_policy.validate_tools(tuple(node._security_tools_by_name))
        if self.host_executor is not None:
            self.host_executor.validate_tools(tuple(node._security_tools_by_name))
            injected = [
                name
                for name, args in node._injected_args.items()
                if args.state
                or args.store is not None
                or args.runtime is not None
                or args.all_injected_keys
            ]
            if injected:
                raise SecurityConfigurationError(
                    "host execution does not support injected tool arguments: "
                    + ", ".join(sorted(injected))
                )
        external_dac = bool(
            self.host_executor is not None
            and getattr(self.host_executor, "authorizes_dac", False)
        )
        stack = SecurityStack(
            self.modules,
            policy_timeout_s=self.policy_timeout_s,
            observer=self.observer,
            audit_sink=self.audit_sink,
            approval_ttl_s=self.approval_ttl_s,
        )
        try:
            object_dacs = dict(self.object_dacs)
            for name, security_tool in tuple(node._security_tools_by_name.items()):
                policy = overrides.get(name, security_tool.dac)
                if (
                    external_dac
                    and name not in overrides
                    and not _has_declared_dac(node.tools_by_name[name])
                ):
                    policy = replace(
                        policy,
                        grants={"*": "x"},
                        required_scopes=frozenset(),
                        arg_grants={},
                    )
                configured_tool = Tool(
                    name=security_tool.name,
                    dac=policy,
                    effects=security_tool.effects,
                    resources=security_tool.resources,
                    security=security_tool.security,
                )
                for module in stack.modules:
                    slot = configured_tool.security.allocate(module.name)
                    module.tool_alloc_security(configured_tool, slot)
                node._security_tools_by_name[name] = configured_tool
                node._dacs_by_name[name] = policy
                profile = overrides.profiles.get(name)
                if profile is not None and name not in object_dacs:
                    object_dacs[name] = ToolObjectDac(
                        profile.readable_channels,
                        profile.readable_store_keys,
                        profile.writable_store_keys,
                    )
                if name in overrides:
                    self._audit_override(
                        name,
                        overrides.profiles.get(name, policy),
                    )
            node._configure_security(
                stack,
                audit_sink=self.audit_sink,
                require_principal=self.require_principal,
                flow_policy=self.flow_policy,
                host_executor=self.host_executor,
                host_router=(
                    make_authorized_host_router(self.host_executor)
                    if self.host_executor is not None
                    else None
                ),
                object_router=make_host_router(
                    ObjectManagerPolicy(stack, object_dacs),
                    _object_host
                    or ObjectManagerHost(
                        checkpoint_key=self.checkpoint_key or b"",
                        tools=node._security_tools_by_name,
                    ),
                ),
                object_dacs=object_dacs,
            )
            node._security_config = self
        except BaseException:
            stack.close()
            raise

    def _audit_override(self, tool_name: str, policy: Any) -> None:
        if self.audit_sink is None:
            return
        payload = (
            policy.audit_payload()
            if isinstance(policy, ToolProfile)
            else {
                "arg_grants": {
                    key: dict(value) for key, value in policy.arg_grants.items()
                },
                "grants": dict(policy.grants),
                "owner": policy.owner,
                "required_scopes": sorted(policy.required_scopes),
            }
        )
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        self.audit_sink.write(
            AuditRecord(
                call_index=0,
                tool_name=tool_name,
                user_id="__operator__",
                args_hash=hashlib.sha256(encoded).hexdigest(),
                stage="compile",
                module="dac_override",
                verdict=Verdict.ALLOW,
                reason="operator_override",
            )
        )

    def _audit_node_promotion(self, placement: PlacementSpec) -> None:
        if self.audit_sink is None:
            return
        encoded = json.dumps(
            {
                "kind": placement.kind.value,
                "node": placement.name,
                "reason": placement.promotion_reason,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        self.audit_sink.write(
            AuditRecord(
                call_index=0,
                tool_name=placement.name,
                user_id="__operator__",
                args_hash=hashlib.sha256(encoded).hexdigest(),
                stage="compile",
                module="node_trust_override",
                verdict=Verdict.ALLOW,
                reason="operator_promotion",
            )
        )


def _find_tool_nodes(root: Any) -> Iterable[Any]:
    """Yield ToolNodes through builders, compiled graphs, and runnable wrappers."""
    from langgraph.prebuilt.tool_node import ToolNode

    stack: list[tuple[Any, int]] = [(root, 0)]
    visited: set[int] = set()
    while stack:
        current, depth = stack.pop()
        if current is None or depth > 12 or id(current) in visited:
            continue
        visited.add(id(current))
        if isinstance(current, ToolNode):
            yield current
            continue
        if isinstance(current, Mapping):
            stack.extend((child, depth + 1) for child in current.values())
            continue
        if isinstance(current, Sequence) and not isinstance(
            current, (str, bytes, bytearray)
        ):
            stack.extend((child, depth + 1) for child in current)
            continue
        for attribute in (
            "nodes",
            "bound",
            "func",
            "afunc",
            "runnable",
            "steps",
            "first",
            "middle",
            "last",
        ):
            child = getattr(current, attribute, None)
            if child is not None and child is not current:
                stack.append((child, depth + 1))
        closure = getattr(current, "__closure__", None)
        if closure:
            for cell in closure:
                try:
                    stack.append((cell.cell_contents, depth + 1))
                except ValueError:
                    continue
