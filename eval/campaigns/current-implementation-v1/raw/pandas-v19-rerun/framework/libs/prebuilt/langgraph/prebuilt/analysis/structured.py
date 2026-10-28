"""A self-contained analysis session for explicitly emitted built-in events."""

from collections.abc import Set
from dataclasses import dataclass, field
from secrets import token_bytes
from typing import Self
from uuid import uuid4

from langgraph.prebuilt.analysis.access.authorization import AccessContext
from langgraph.prebuilt.analysis.access.client import AnalysisClient
from langgraph.prebuilt.analysis.access.subscriptions import NotificationHub
from langgraph.prebuilt.analysis.adapters.boundary import BoundaryAdapter
from langgraph.prebuilt.analysis.config import AnalysisConfig
from langgraph.prebuilt.analysis.contracts import AnalysisSnapshot, ValueRef
from langgraph.prebuilt.analysis.errors import ConfigurationError
from langgraph.prebuilt.analysis.events import BUILTIN_EVENTS, BuiltinEvent
from langgraph.prebuilt.analysis.provenance.checkpoint import CheckpointBinding
from langgraph.prebuilt.analysis.provenance.records import ValueRecord
from langgraph.prebuilt.analysis.provenance.store import MemoryProvenanceStore
from langgraph.prebuilt.analysis.registry import AnalyzerRegistration, Registry
from langgraph.prebuilt.analysis.runtime import AnalysisRuntime
from langgraph.prebuilt.analysis.serialization import canonical
from langgraph.prebuilt.security.object_manager import CheckpointEnvelope
from langgraph.prebuilt.security.objects import SecurityLabels
from langgraph.prebuilt.security.types import Principal


@dataclass(frozen=True)
class _LocalScope:
    tenant_id: str = field(default_factory=lambda: str(uuid4()))
    session_id: str = field(default_factory=lambda: str(uuid4()))
    run_id: str = field(default_factory=lambda: str(uuid4()))
    principal_id: str = field(default_factory=lambda: str(uuid4()))
    key: bytes = field(default_factory=lambda: token_bytes(32), repr=False)

    def principal(self) -> Principal:
        return Principal(self.principal_id, frozenset(), frozenset(), self.session_id)


@dataclass(frozen=True)
class LocalAnalysisCheckpoint:
    """Trusted in-process restore handle; keep it private like its signing key.

    The envelope is authenticated data. This handle also owns the independent
    local identity/key needed to restore it after the source session closes.
    Use CheckpointBinding for application-managed persistence and authentication.
    """

    envelope: CheckpointEnvelope = field(repr=False)
    _scope: _LocalScope = field(repr=False)
    _config: AnalysisConfig = field(repr=False)

    def restore(self, *, configuration: dict | None = None) -> "StructuredAnalysis":
        """Restore into a fresh local store, with no analyzers rerun or installed."""
        config = (
            self._config
            if configuration is None
            else AnalysisConfig(canonical(configuration), ())
        )
        restored = StructuredAnalysis.__new__(StructuredAnalysis)
        restored._initialize((), config, self._scope)
        try:
            CheckpointBinding(
                restored._store, self._scope.key, config.policy_version
            ).restore(self._scope.principal(), self.envelope)
        except BaseException:
            restored.close()
            raise
        return restored


class StructuredAnalysis:
    """Opt into standardized findings, provenance, and in-memory persistence.

    Generated identities provide local isolation, not authenticated identity.
    This does not automatically instrument tools, resources, or model calls.
    Use `AnalysisRuntime` for authenticated or persistent application integration.
    """

    def __init__(
        self, *listeners: AnalyzerRegistration, configuration: dict | None = None
    ) -> None:
        self._initialize(
            listeners, AnalysisConfig(canonical(configuration or {}), ()), _LocalScope()
        )

    def _initialize(
        self, listeners, config: AnalysisConfig, scope: _LocalScope
    ) -> None:
        registry = Registry(
            BUILTIN_EVENTS,
            listeners,
            producers=frozenset(spec.producer for spec in BUILTIN_EVENTS),
        )
        self._scope = scope
        self._closed = False
        self._notifications = NotificationHub()
        self._store = MemoryProvenanceStore()
        self._runtime = AnalysisRuntime(
            config,
            registry,
            self._store,
            tenant_id=scope.tenant_id,
            session_id=scope.session_id,
            run_id=scope.run_id,
            principal_id=scope.principal_id,
            notifications=self._notifications,
        )
        self._boundary = BoundaryAdapter(self._runtime)
        access = AccessContext(
            scope.principal_id,
            scope.tenant_id,
            frozenset({scope.session_id}),
            self._owns,
            lambda: not self._closed,
        )
        self._client = AnalysisClient(
            self._runtime.journal, access, self._notifications
        )

    def _owns(self, ref: ValueRef) -> bool:
        record = self._store.get(ref)
        return (record.tenant_id, record.session_id, record.run_id) == (
            self._scope.tenant_id,
            self._scope.session_id,
            self._scope.run_id,
        )

    @property
    def client(self) -> AnalysisClient:
        """Inspect only this local session. Access is revoked when it closes."""
        self._check_open()
        return self._client

    def checkpoint(self, *refs: ValueRef) -> LocalAnalysisCheckpoint:
        """Save values, ancestry and analysis metadata in an authenticated handle."""
        self._check_open()
        if not refs or not all(self._owns(ref) for ref in refs):
            raise ValueError("analysis:checkpoint_requires_owned_values")
        envelope = CheckpointBinding(
            self._store, self._scope.key, self._runtime.config.policy_version
        ).save(self._scope.principal(), refs, checkpoint_id=str(uuid4()))
        return LocalAnalysisCheckpoint(envelope, self._scope, self._runtime.config)

    def _check_open(self) -> None:
        if self._closed:
            raise RuntimeError("analysis:session_closed")

    def value(
        self,
        content: object,
        *,
        parents: tuple[ValueRef, ...] = (),
        confidentiality: Set[str] = frozenset(),
    ) -> ValueRef:
        """Track content with optional labels; parent labels propagate monotonically."""
        self._check_open()
        if not isinstance(confidentiality, Set) or any(
            not isinstance(item, str) for item in confidentiality
        ):
            raise ValueError("analysis:confidentiality_must_be_a_string_set")
        record = ValueRecord(
            self._scope.tenant_id,
            self._scope.session_id,
            self._scope.run_id,
            canonical(content).encode(),
            labels=SecurityLabels(frozenset(confidentiality), "low"),
        )
        return self._store.derive(parents, record, "derive" if parents else "admit")

    def emit(
        self, event: BuiltinEvent, refs: tuple[ValueRef, ...] = ()
    ) -> AnalysisSnapshot:
        """Run subscribed listeners; raise if required analysis is unavailable."""
        self._check_open()
        if not isinstance(event, BuiltinEvent):
            raise ConfigurationError("analysis:use_builtin_event")
        return self._boundary.before(event.value, refs)

    async def aemit(
        self, event: BuiltinEvent, refs: tuple[ValueRef, ...] = ()
    ) -> AnalysisSnapshot:
        """Asynchronously run subscribed listeners with the same failure rules."""
        self._check_open()
        if not isinstance(event, BuiltinEvent):
            raise ConfigurationError("analysis:use_builtin_event")
        return await self._boundary.abefore(event.value, refs)

    def close(self) -> None:
        """Release this session's executor and storage. Safe to repeat."""
        if not self._closed:
            self._closed = True
            self._runtime.close()
            self._store.close()

    def __enter__(self) -> Self:
        self._check_open()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
