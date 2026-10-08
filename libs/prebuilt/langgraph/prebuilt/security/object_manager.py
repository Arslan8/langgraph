"""Trusted handlers and DAC for framework objects routed through HostRouter."""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from threading import RLock
from types import MappingProxyType
from typing import Any

from langgraph.store.base import BaseStore, GetOp, ListNamespacesOp, PutOp, SearchOp

from langgraph.prebuilt.security.execution import (
    HostExecutionDenied,
    HostExecutionResult,
)
from langgraph.prebuilt.security.host_boundary import StackBoundaryPolicy, ToolOrigin
from langgraph.prebuilt.security.objects import (
    DispatchRequest,
    FrameworkRequest,
    LabeledValue,
    ModelInvocationRequest,
    OutputRequest,
    SecurityLabels,
    StateOperation,
    StateRequest,
    ToolRegistryRequest,
)
from langgraph.prebuilt.security.stack import SecurityStack
from langgraph.prebuilt.security.types import (
    Approval,
    Decision,
    PolicyConstraint,
    Principal,
    Tool,
    Verdict,
)


@dataclass(frozen=True, slots=True)
class ToolObjectDac:
    """Constructive state authority for one declared tool."""

    readable_channels: frozenset[str] = frozenset()
    readable_store_keys: frozenset[str] = frozenset()
    writable_store_keys: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        for values in (
            self.readable_channels,
            self.readable_store_keys,
            self.writable_store_keys,
        ):
            if any(not value for value in values):
                raise ValueError("object DAC resources must be non-empty")
        object.__setattr__(self, "readable_channels", frozenset(self.readable_channels))
        object.__setattr__(
            self, "readable_store_keys", frozenset(self.readable_store_keys)
        )
        object.__setattr__(
            self, "writable_store_keys", frozenset(self.writable_store_keys)
        )


class ObjectManagerPolicy(StackBoundaryPolicy):
    """Apply constructive object DAC before restrict-only module hooks."""

    def __init__(
        self,
        stack: SecurityStack,
        object_dacs: Mapping[str, ToolObjectDac] | None = None,
        *,
        transitions: frozenset[tuple[str, str]] = frozenset(),
    ) -> None:
        super().__init__(stack, transitions)
        object.__setattr__(
            self, "object_dacs", MappingProxyType(dict(object_dacs or {}))
        )

    def object_permission(self, principal: Principal, request: FrameworkRequest):
        denied = self._dac(request)
        if denied is not None:
            from langgraph.prebuilt.security.objects import ObjectAuthorization

            authorization = ObjectAuthorization(denied, request)
        else:
            authorization = self.stack.object_permission(principal, request)
        self.stack.record_object_decision(principal, request, authorization)
        return authorization

    async def aobject_permission(self, principal: Principal, request: FrameworkRequest):
        denied = self._dac(request)
        if denied is not None:
            from langgraph.prebuilt.security.objects import ObjectAuthorization

            authorization = ObjectAuthorization(denied, request)
        else:
            authorization = await self.stack.aobject_permission(principal, request)
        self.stack.record_object_decision(principal, request, authorization)
        return authorization

    def object_resume_permission(
        self, principal: Principal, request: FrameworkRequest, approval: Approval
    ):
        denied = self._dac(request)
        if denied is not None:
            from langgraph.prebuilt.security.objects import ObjectAuthorization

            authorization = ObjectAuthorization(denied, request)
        else:
            authorization = self.stack.object_resume_permission(
                principal, request, approval
            )
        self.stack.record_object_decision(principal, request, authorization)
        return authorization

    async def aobject_resume_permission(
        self, principal: Principal, request: FrameworkRequest, approval: Approval
    ):
        denied = self._dac(request)
        if denied is not None:
            from langgraph.prebuilt.security.objects import ObjectAuthorization

            authorization = ObjectAuthorization(denied, request)
        else:
            authorization = await self.stack.aobject_resume_permission(
                principal, request, approval
            )
        self.stack.record_object_decision(principal, request, authorization)
        return authorization

    def _dac(self, request: FrameworkRequest) -> Decision | None:
        if not isinstance(request, StateRequest) or not request.tool_name:
            return None
        profile = self.object_dacs.get(request.tool_name, ToolObjectDac())
        if request.operation is StateOperation.TOOL_READ:
            allowed = request.resource in profile.readable_channels
        elif request.operation is StateOperation.STORE_READ:
            allowed = request.resource in profile.readable_store_keys
        elif request.operation is StateOperation.STORE_WRITE:
            allowed = request.resource in profile.writable_store_keys
        else:
            return None
        if allowed:
            return None
        return Decision(Verdict.DENY, "dac:object_not_granted")


@dataclass(frozen=True, slots=True)
class StoreResource:
    """Owned and labeled persistent value."""

    owner_id: str
    value: Any = field(compare=False, repr=False)
    labels: SecurityLabels = SecurityLabels()


@dataclass(frozen=True, slots=True)
class CheckpointEnvelope:
    """Principal-bound checkpoint with an authenticated predecessor link."""

    checkpoint_id: str
    principal_id: str
    session_id: str
    sequence: int
    previous_hash: str
    payload: Any = field(compare=False, repr=False)
    digest: str = ""

    def __post_init__(self) -> None:
        if not self.checkpoint_id or not self.principal_id or not self.session_id:
            raise ValueError("checkpoint identity must be non-empty")
        if self.sequence < 0:
            raise ValueError("checkpoint sequence must be non-negative")


class ObjectManagerHost:
    """Trusted framework-object effects after HostRouter authorization."""

    def __init__(
        self,
        *,
        checkpoint_key: bytes,
        tools: Mapping[str, Tool] | None = None,
    ) -> None:
        if not checkpoint_key:
            raise ValueError("checkpoint_key must be non-empty")
        self._checkpoint_key = bytes(checkpoint_key)
        self._state: dict[tuple[str, str, str, str], LabeledValue] = {}
        self._store: dict[str, StoreResource] = {}
        self._tools: dict[str, Tool] = dict(tools or {})
        self._restored: dict[tuple[str, str], tuple[int, str]] = {}
        self._lock = RLock()

    def dispatch(self, principal: Principal, request: FrameworkRequest) -> object:
        """Apply exactly one already-authorized framework operation."""
        with self._lock:
            if isinstance(request, DispatchRequest):
                return request.child
            if isinstance(request, ToolRegistryRequest):
                exists = request.tool.name in self._tools
                if request.override != exists:
                    raise PermissionError("registry:override_mismatch")
                self._tools[request.tool.name] = request.tool
                return request.tool
            if isinstance(request, StateRequest):
                return self._state_operation(principal, request)
            if isinstance(request, ModelInvocationRequest):
                return request.context
            if isinstance(request, OutputRequest):
                if not request.labels.confidentiality.issubset(request.clearance):
                    raise PermissionError("output:clearance")
                return request.content
        raise TypeError("unknown framework request")

    async def adispatch(
        self, principal: Principal, request: FrameworkRequest
    ) -> object:
        return self.dispatch(principal, request)

    def origin_permission(
        self, origin: ToolOrigin, parent: Principal, child: Principal, call: Any
    ) -> Decision:
        return Decision(Verdict.DENY, "host:tool_execution_unavailable")

    async def aorigin_permission(
        self, origin: ToolOrigin, parent: Principal, child: Principal, call: Any
    ) -> Decision:
        return self.origin_permission(origin, parent, child, call)

    def invoke(
        self,
        principal: Principal,
        call: Any,
        constraints: Sequence[PolicyConstraint],
    ) -> HostExecutionResult:
        raise HostExecutionDenied("host:tool_execution_unavailable")

    async def ainvoke(
        self,
        principal: Principal,
        call: Any,
        constraints: Sequence[PolicyConstraint],
    ) -> HostExecutionResult:
        raise HostExecutionDenied("host:tool_execution_unavailable")

    def invoke_from(
        self,
        origin: ToolOrigin,
        parent: Principal,
        child: Principal,
        call: Any,
        tool_constraints: Sequence[PolicyConstraint],
        delegation_constraints: Sequence[PolicyConstraint],
        transition_constraints: Sequence[PolicyConstraint],
    ) -> HostExecutionResult:
        raise HostExecutionDenied("host:tool_execution_unavailable")

    async def ainvoke_from(
        self,
        origin: ToolOrigin,
        parent: Principal,
        child: Principal,
        call: Any,
        tool_constraints: Sequence[PolicyConstraint],
        delegation_constraints: Sequence[PolicyConstraint],
        transition_constraints: Sequence[PolicyConstraint],
    ) -> HostExecutionResult:
        raise HostExecutionDenied("host:tool_execution_unavailable")

    def _state_operation(self, principal: Principal, request: StateRequest) -> object:
        state_key = _state_key(principal, request)
        if request.operation is StateOperation.WRITE:
            self._state[state_key] = LabeledValue(
                request.resource, request.value, request.labels
            )
            return request.value
        if request.operation in (StateOperation.TOOL_READ, StateOperation.MODEL_READ):
            stored = self._state.get(state_key)
            if stored is None:
                return request.value
            if not isinstance(stored, LabeledValue):
                return stored
            if request.operation is StateOperation.MODEL_READ:
                return stored
            return stored.value
        if request.operation is StateOperation.STORE_WRITE:
            existing = self._store.get(request.resource)
            if existing is not None and existing.owner_id != principal.user_id:
                raise PermissionError("store:owner_mismatch")
            if request.owner_id != principal.user_id:
                raise PermissionError("store:owner_mismatch")
            self._store[request.resource] = StoreResource(
                principal.user_id, request.value, request.labels
            )
            return request.value
        if request.operation is StateOperation.STORE_READ:
            resource = self._store.get(request.resource)
            if resource is None:
                return None
            if resource.owner_id != principal.user_id:
                raise PermissionError("store:owner_mismatch")
            return resource.value
        if request.operation is StateOperation.RESTORE:
            if not isinstance(request.value, CheckpointEnvelope):
                raise PermissionError("checkpoint:malformed")
            self._verify_checkpoint(principal, request.value)
            return request.value.payload
        if request.operation in (
            StateOperation.CHECKPOINT_READ,
            StateOperation.CHECKPOINT_WRITE,
        ):
            return request.value
        raise PermissionError("state:unsupported_operation")

    def labels_for_output(self, principal: Principal, value: Any) -> SecurityLabels:
        """Join labels for state values present in one externally emitted item."""
        confidentiality: set[str] = set()
        integrities: set[str] = set()

        def visit(item: Any, key: str | None = None) -> None:
            if isinstance(item, LabeledValue):
                confidentiality.update(item.labels.confidentiality)
                integrities.add(item.labels.integrity)
                return
            if key is not None:
                stored = self._state.get(
                    (principal.user_id, principal.session_id, "", key)
                )
                if isinstance(stored, LabeledValue) and stored.value == item:
                    confidentiality.update(stored.labels.confidentiality)
                    integrities.add(stored.labels.integrity)
            if isinstance(item, Mapping):
                for child_key, child in item.items():
                    visit(child, str(child_key))
            elif isinstance(item, Sequence) and not isinstance(
                item, (str, bytes, bytearray)
            ):
                for child in item:
                    visit(child)

        with self._lock:
            visit(value)
        integrity = (
            "trusted" if not integrities or integrities == {"trusted"} else "low"
        )
        return SecurityLabels(frozenset(confidentiality), integrity)

    def _verify_checkpoint(
        self, principal: Principal, checkpoint: CheckpointEnvelope
    ) -> None:
        if (
            checkpoint.principal_id != principal.user_id
            or checkpoint.session_id != principal.session_id
        ):
            raise PermissionError("checkpoint:principal_mismatch")
        expected = _checkpoint_digest(self._checkpoint_key, checkpoint)
        if not checkpoint.digest or not hmac.compare_digest(
            checkpoint.digest, expected
        ):
            raise PermissionError("checkpoint:invalid_hash")
        key = (principal.user_id, principal.session_id)
        prior = self._restored.get(key)
        if prior is not None:
            sequence, digest = prior
            if checkpoint.sequence <= sequence:
                raise PermissionError("checkpoint:replay")
            if checkpoint.previous_hash != digest:
                raise PermissionError("checkpoint:broken_chain")
        elif checkpoint.sequence and not checkpoint.previous_hash:
            raise PermissionError("checkpoint:broken_chain")
        self._restored[key] = (checkpoint.sequence, checkpoint.digest)


def seal_checkpoint(
    checkpoint_key: bytes,
    *,
    checkpoint_id: str,
    principal: Principal,
    sequence: int,
    previous_hash: str,
    payload: Any,
) -> CheckpointEnvelope:
    """Create a canonical authenticated checkpoint envelope."""
    unsigned = CheckpointEnvelope(
        checkpoint_id,
        principal.user_id,
        principal.session_id,
        sequence,
        previous_hash,
        payload,
    )
    return CheckpointEnvelope(
        unsigned.checkpoint_id,
        unsigned.principal_id,
        unsigned.session_id,
        unsigned.sequence,
        unsigned.previous_hash,
        unsigned.payload,
        _checkpoint_digest(checkpoint_key, unsigned),
    )


def _checkpoint_digest(key: bytes, checkpoint: CheckpointEnvelope) -> str:
    encoded = json.dumps(
        {
            "checkpoint_id": checkpoint.checkpoint_id,
            "payload_hash": hashlib.sha256(
                json.dumps(
                    checkpoint.payload,
                    sort_keys=True,
                    default=repr,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest(),
            "previous_hash": checkpoint.previous_hash,
            "principal_id": checkpoint.principal_id,
            "sequence": checkpoint.sequence,
            "session_id": checkpoint.session_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hmac.new(key, encoded, hashlib.sha256).hexdigest()


class MediatedStore(BaseStore):
    """Exact-key store facade that authorizes every operation through HostRouter."""

    def __init__(
        self,
        store: BaseStore,
        *,
        router: Any,
        principal: Principal,
        tool_name: str,
    ) -> None:
        self._store = store
        self._router = router
        self._principal = principal
        self._tool_name = tool_name
        self.supports_ttl = store.supports_ttl
        self.ttl_config = store.ttl_config

    def batch(self, ops):
        operations = tuple(ops)
        effective = tuple(
            self._authorize(operation, asynchronous=False) for operation in operations
        )
        return self._store.batch(effective)

    async def abatch(self, ops):
        operations = tuple(ops)
        effective = [
            await self._authorize(operation, asynchronous=True)
            for operation in operations
        ]
        return await self._store.abatch(tuple(effective))

    def _authorize(self, operation: Any, *, asynchronous: bool):
        if isinstance(operation, GetOp):
            state_operation = StateOperation.STORE_READ
            resource = _store_resource(operation.namespace, operation.key)
            value = None
        elif isinstance(operation, PutOp):
            state_operation = StateOperation.STORE_WRITE
            resource = _store_resource(operation.namespace, operation.key)
            value = operation.value
        elif isinstance(operation, (SearchOp, ListNamespacesOp)):
            raise PermissionError("store:enumeration_not_granted")
        else:
            raise PermissionError("store:operation_not_granted")
        request = StateRequest(
            state_operation,
            resource,
            self._principal.user_id,
            tool_name=self._tool_name,
            value=value,
        )
        if asynchronous:
            return _aeffective_store_operation(
                operation, self._router.astate(self._principal, request)
            )
        return _effective_store_operation(
            operation,
            self._router.state(self._principal, request),
        )


def _effective_store_operation(operation: Any, routed: Any) -> Any:
    """Apply a narrowed write value; reads carry no value to transform."""
    if isinstance(operation, PutOp):
        return (
            operation if routed is operation.value else operation._replace(value=routed)
        )
    return operation


async def _aeffective_store_operation(operation: Any, routed: Any) -> Any:
    return _effective_store_operation(operation, await routed)


def _state_key(
    principal: Principal, request: StateRequest
) -> tuple[str, str, str, str]:
    graph_id = request.metadata.get("graph_id", "")
    if not isinstance(graph_id, str):
        raise PermissionError("state:invalid_graph_identity")
    return (principal.user_id, principal.session_id, graph_id, request.resource)


def _store_resource(namespace: tuple[str, ...], key: str) -> str:
    return "/".join((*namespace, str(key)))
