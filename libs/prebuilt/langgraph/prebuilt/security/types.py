"""Graph-independent public types used by security modules."""

from __future__ import annotations

from _thread import RLock as _NativeRLock
from collections.abc import Iterator, Mapping, MutableMapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from threading import RLock
from types import MappingProxyType
from typing import Any, Protocol, runtime_checkable

from langgraph.prebuilt.security.descriptor import Effect, ResourceArg, ToolDac


class Slot(MutableMapping[str, Any]):
    """Small thread-safe mutable mapping owned by one security module."""

    __slots__ = ("_lock", "_values")

    def __init__(self, values: Mapping[str, Any] | None = None) -> None:
        self._values = dict(values or {})
        self._lock = RLock()

    def __getitem__(self, key: str) -> Any:
        with self._lock:
            return self._values[key]

    def __setitem__(self, key: str, value: Any) -> None:
        with self._lock:
            self._values[key] = value

    def __delitem__(self, key: str) -> None:
        with self._lock:
            del self._values[key]

    def __iter__(self) -> Iterator[str]:
        with self._lock:
            return iter(tuple(self._values))

    def __len__(self) -> int:
        with self._lock:
            return len(self._values)

    def snapshot(self) -> Mapping[str, Any]:
        """Return an immutable shallow snapshot of the slot."""
        with self._lock:
            return MappingProxyType(dict(self._values))

    def clone(self) -> Slot:
        """Return an independent slot initialized from this slot."""
        return Slot(self.snapshot())

    def put_if_absent(self, key: str, value: Any) -> bool:
        """Atomically store a value only when the key has not been used."""
        with self._lock:
            if key in self._values:
                return False
            self._values[key] = value
            return True


class Blobs(Mapping[str, Slot]):
    """Map security-module names to their private mutable slots."""

    __slots__ = ("_lock", "_slots")

    def __init__(self, values: Mapping[str, Slot | Mapping[str, Any]] | None = None):
        self._slots: dict[str, Slot] = {}
        self._lock = RLock()
        for name, value in (values or {}).items():
            self._slots[name] = value if isinstance(value, Slot) else Slot(value)

    def __getitem__(self, key: str) -> Slot:
        with self._lock:
            return self._slots[key]

    def __iter__(self) -> Iterator[str]:
        with self._lock:
            return iter(tuple(self._slots))

    def __len__(self) -> int:
        with self._lock:
            return len(self._slots)

    def allocate(self, module_name: str) -> Slot:
        """Return the named slot, allocating it exactly once if absent."""
        if not module_name:
            raise ValueError("module name must be non-empty")
        with self._lock:
            return self._slots.setdefault(module_name, Slot())

    def clone(self) -> Blobs:
        """Copy every module slot for an independent principal or tool."""
        with self._lock:
            return Blobs({name: slot.clone() for name, slot in self._slots.items()})


@dataclass(frozen=True, slots=True)
class Principal:
    """Authenticated identity and authority bound outside graph state."""

    user_id: str
    roles: frozenset[str]
    scopes: frozenset[str]
    session_id: str
    delegated_by: str | None = None
    security: Blobs = field(default_factory=Blobs, compare=False)

    def __post_init__(self) -> None:
        if not self.user_id or not self.session_id:
            raise ValueError("principal user_id and session_id must be non-empty")
        object.__setattr__(self, "roles", frozenset(self.roles))
        object.__setattr__(self, "scopes", frozenset(self.scopes))


def _validate_principal(principal: Principal) -> None:
    """Admit native identity/credential containers without running user protocols.

    Slot payload values belong to policy modules and remain opaque and mutable.
    This checks their native containers, not policy semantics or their contents.
    The control plane must preserve these shapes across later policy operations;
    validation is not a seal against concurrent mutation or class monkeypatching.
    """
    if type(principal) is not Principal:
        raise TypeError("invalid principal type")
    try:
        if (
            type(principal.user_id) is not str
            or type(principal.session_id) is not str
            or (
                principal.delegated_by is not None
                and type(principal.delegated_by) is not str
            )
        ):
            raise TypeError("invalid principal identity fields")
        if not principal.user_id or not principal.session_id:
            raise TypeError("invalid empty principal identity")
        for values in (principal.roles, principal.scopes):
            if type(values) is not frozenset:
                raise TypeError("invalid principal authority container")
            for value in values:
                if type(value) is not str:
                    raise TypeError("invalid principal authority value")

        security = principal.security
        if type(security) is not Blobs:
            raise TypeError("invalid principal credential container")
        if type(security._lock) is not _NativeRLock:
            raise TypeError("invalid principal credential lock")
        slots = security._slots
        if type(slots) is not dict:
            raise TypeError("invalid principal credential mapping")
        for name, slot in tuple(slots.items()):
            if type(name) is not str or type(slot) is not Slot:
                raise TypeError("invalid principal credential slot")
            if type(slot._lock) is not _NativeRLock:
                raise TypeError("invalid principal slot lock")
            contents = slot._values
            if type(contents) is not dict:
                raise TypeError("invalid principal slot mapping")
            for key, _ in tuple(contents.items()):
                if type(key) is not str:
                    raise TypeError("invalid principal slot key")
        return
    except AttributeError:
        pass
    # `from None` hides display but retains __context__ and its receiver.
    raise TypeError("invalid missing principal fields")


@dataclass(frozen=True, slots=True)
class Tool:
    """Security representation of an executable tool."""

    name: str
    dac: ToolDac
    effects: frozenset[Effect]
    resources: tuple[ResourceArg, ...]
    security: Blobs = field(default_factory=Blobs, compare=False)

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("tool name must be non-empty")
        object.__setattr__(self, "effects", frozenset(self.effects))
        object.__setattr__(self, "resources", tuple(self.resources))


class Verdict(str, Enum):
    """Possible outcomes of a security-policy hook."""

    ALLOW = "allow"
    DENY = "deny"
    TRANSFORM = "transform"
    REDACT = "redact"
    ESCALATE = "escalate"


class ExecutionOutcome(str, Enum):
    """Durable execution state recorded independently of an authorization verdict."""

    DENIED_BEFORE_DISPATCH = "denied_before_dispatch"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    INDETERMINATE = "indeterminate"


class SelectorMatch(str, Enum):
    """How a mandatory-policy predicate interprets its selector."""

    ANY = "any"
    EXACT = "exact"
    SUBTREE = "subtree"


@dataclass(frozen=True, slots=True)
class RulePredicate:
    """Bounded match over final-grant rules; it contains no policy source text.

    A subtree predicate may exempt canonical subtrees or exact paths below its
    selector. It then matches only the remaining difference, which lets a
    forbid-only module deny everything in a scope except listed resources.
    """

    domain: str | None = None
    operations: frozenset[str] = frozenset()
    selector: str | None = None
    selector_match: SelectorMatch = SelectorMatch.ANY
    conditions: Mapping[str, Any] = field(default_factory=dict)
    exempt_subtrees: frozenset[str] = frozenset()
    exempt_paths: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if self.domain is not None and not self.domain:
            raise ValueError("predicate domain must be non-empty when present")
        operations = frozenset(self.operations)
        if any(not operation for operation in operations):
            raise ValueError("predicate operations must be non-empty")
        if self.selector_match is not SelectorMatch.ANY and not self.selector:
            raise ValueError("exact and subtree predicates require a selector")
        if self.selector_match is SelectorMatch.ANY and self.selector is not None:
            raise ValueError("an ANY predicate cannot carry a selector")
        exempt_subtrees = frozenset(self.exempt_subtrees)
        exempt_paths = frozenset(self.exempt_paths)
        if (exempt_subtrees or exempt_paths) and (
            self.selector_match is not SelectorMatch.SUBTREE
        ):
            raise ValueError("exemptions are valid only for subtree predicates")
        if (
            len(operations) > 32
            or len(self.conditions) > 32
            or len(exempt_subtrees) + len(exempt_paths) > 32
        ):
            raise ValueError("predicate exceeds the bounded complexity limit")
        object.__setattr__(self, "operations", operations)
        object.__setattr__(self, "exempt_subtrees", exempt_subtrees)
        object.__setattr__(self, "exempt_paths", exempt_paths)
        object.__setattr__(self, "conditions", MappingProxyType(dict(self.conditions)))


@dataclass(frozen=True, slots=True)
class ForbidConstraint:
    """Typed restriction over one class of grant rules."""

    constraint_id: str
    predicate: RulePredicate
    reason: str
    module: str = ""

    def __post_init__(self) -> None:
        if not self.constraint_id or not self.reason:
            raise ValueError("constraint identity and reason must be non-empty")


@dataclass(frozen=True, slots=True)
class ForbidCombination:
    """Reject authority combinations even when each rule is valid alone."""

    constraint_id: str
    terms: tuple[RulePredicate, ...]
    reason: str
    module: str = ""

    def __post_init__(self) -> None:
        terms = tuple(self.terms)
        if not self.constraint_id or not self.reason:
            raise ValueError("constraint identity and reason must be non-empty")
        if len(terms) < 2 or len(terms) > 16:
            raise ValueError("combinations require between two and sixteen terms")
        object.__setattr__(self, "terms", terms)


PolicyConstraint = ForbidConstraint | ForbidCombination


@dataclass(frozen=True, slots=True)
class EscalationRequest:
    """Redacted human-approval request emitted by a policy module."""

    request_id: str
    reason: str
    tool_name: str
    call_id: str
    metadata: Mapping[str, Any] = field(default_factory=dict)
    subject_digest: str = ""
    expires_at: float | None = None

    def __post_init__(self) -> None:
        if not all((self.request_id, self.reason, self.tool_name, self.call_id)):
            raise ValueError("escalation identifiers and reason must be non-empty")
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))
        if self.expires_at is not None and self.expires_at <= 0:
            raise ValueError("escalation expiry must be positive")

    def to_payload(self) -> Mapping[str, Any]:
        """Return the argument-free payload passed to LangGraph `interrupt()`."""
        return MappingProxyType(
            {
                "type": "security_approval",
                "request_id": self.request_id,
                "reason": self.reason,
                "tool_name": self.tool_name,
                "call_id": self.call_id,
                "metadata": dict(self.metadata),
                "subject_digest": self.subject_digest,
                "expires_at": self.expires_at,
            }
        )


@dataclass(frozen=True, slots=True)
class Approval:
    """Human response to an `EscalationRequest`."""

    request_id: str
    approved: bool
    approver: str
    reason: str = ""
    subject_digest: str = ""

    def __post_init__(self) -> None:
        if not self.request_id or not self.approver:
            raise ValueError("approval request_id and approver must be non-empty")


@dataclass(frozen=True, slots=True, init=False, eq=False)
class _DecisionArguments(Mapping[str, Any]):
    """Read-only native-key snapshot; policy payload values remain opaque.

    The tuple representation makes backing storage inspectable without invoking
    a caller-supplied mapping. Admission rechecks it because frozen records can
    still be forged or changed through privileged Python operations.
    """

    _items: tuple[tuple[str, Any], ...]

    def __init__(self, value: Mapping[str, Any]) -> None:
        copied = _decision_arguments(value)
        object.__setattr__(self, "_items", tuple(copied.items()))

    def __getitem__(self, key: str) -> Any:
        if type(key) is not str:
            raise TypeError("decision argument keys must be plain strings")
        return _decision_arguments(self)[key]

    def __iter__(self) -> Iterator[str]:
        return iter(_decision_arguments(self))

    def __len__(self) -> int:
        return len(_decision_arguments(self))


def _decision_arguments(value: Any) -> dict[str, Any]:
    """Return native argument storage without executing mapping/key protocols.

    Only exact dictionaries or this module's exact tuple-backed record are
    admitted. A mapping proxy alone cannot establish its backing mapping's type.
    Values are neither interpreted nor copied; their later use needs its own
    policy and data admission. Stable module bindings remain a control-plane
    premise, independently of these checked transport shapes.
    """
    if type(value) is dict:
        pairs = tuple(value.items())
    elif type(value) is _DecisionArguments:
        try:
            pairs = value._items
        except AttributeError:
            raise TypeError("decision argument storage is missing") from None
    else:
        raise TypeError(
            "decision arguments require a plain dictionary or native record"
        )
    if type(pairs) is not tuple:
        raise TypeError("decision argument storage must be a plain tuple")
    copied = {}
    for pair in pairs:
        if type(pair) is not tuple or len(pair) != 2:
            raise TypeError("decision argument entries must be plain pairs")
        key, item = pair
        if type(key) is not str:
            raise TypeError("decision argument keys must be plain strings")
        if key in copied:
            raise TypeError("decision argument keys must be unique")
        copied[key] = item
    return copied


@dataclass(frozen=True, slots=True)
class Decision:
    """One policy hook's verdict and optional transform or escalation."""

    verdict: Verdict
    reason: str
    new_args: Mapping[str, Any] | None = None
    escalation: EscalationRequest | None = None
    constraints: tuple[PolicyConstraint, ...] = ()

    def __post_init__(self) -> None:
        if not self.reason:
            raise ValueError("decision reason must be non-empty")
        constraints = tuple(self.constraints)
        object.__setattr__(self, "constraints", constraints)
        if self.verdict is Verdict.TRANSFORM:
            if self.new_args is None or self.escalation is not None or constraints:
                raise ValueError(
                    "TRANSFORM requires new_args and forbids escalation or constraints"
                )
            object.__setattr__(self, "new_args", _DecisionArguments(self.new_args))
        elif self.verdict is Verdict.REDACT:
            if self.new_args is None or self.escalation is not None or constraints:
                raise ValueError(
                    "REDACT requires new_args and forbids escalation or constraints"
                )
            object.__setattr__(self, "new_args", _DecisionArguments(self.new_args))
        elif self.verdict is Verdict.ESCALATE:
            if self.escalation is None or self.new_args is not None or constraints:
                raise ValueError(
                    "ESCALATE requires escalation and forbids new_args or constraints"
                )
        elif self.new_args is not None or self.escalation is not None:
            raise ValueError("ALLOW and DENY cannot carry transform or escalation data")
        elif self.verdict is Verdict.DENY and constraints:
            raise ValueError("DENY cannot carry constraints")


@dataclass(frozen=True, slots=True)
class AuditRecord:
    """Hash-chainable record of one security enforcement stage."""

    call_index: int
    tool_name: str
    user_id: str
    args_hash: str
    stage: str
    module: str
    verdict: Verdict
    reason: str
    prev_hash: str = ""
    hash: str = ""
    session_id: str = ""
    outcome: ExecutionOutcome | None = None

    def __post_init__(self) -> None:
        if self.call_index < 0:
            raise ValueError("audit call_index must be non-negative")
        if not self.tool_name or not self.user_id or not self.stage:
            raise ValueError("audit tool, user, and stage must be non-empty")


@dataclass(frozen=True, slots=True)
class AuditSeal:
    """Externally witnessable commitment to one retained audit-chain head."""

    stream_id: str
    record_count: int
    chain_head: str
    issued_at: float
    signature: str

    def __post_init__(self) -> None:
        if not self.stream_id or not self.signature:
            raise ValueError("audit seal stream and signature must be non-empty")
        if self.record_count < 0 or self.issued_at <= 0:
            raise ValueError("audit seal count and issuance time are invalid")
        if self.record_count and not self.chain_head:
            raise ValueError("a non-empty audit seal requires a chain head")


@runtime_checkable
class AuditWitness(Protocol):
    """External signer/verifier for durable audit-chain commitments."""

    def sign(self, payload: bytes) -> str:
        """Sign a canonical audit-seal payload."""
        ...

    def verify(self, payload: bytes, signature: str) -> bool:
        """Verify a canonical audit-seal payload against a trust anchor."""
        ...


@runtime_checkable
class AuditSink(Protocol):
    """Storage protocol implemented by security audit sinks."""

    def write(self, record: AuditRecord) -> AuditRecord:
        """Persist a record and return its finalized hash-chain form."""
        ...

    def records(self) -> Sequence[AuditRecord]:
        """Return records in append order."""
        ...

    def verify(self) -> tuple[bool, int | None]:
        """Return integrity status and the first invalid record index."""
        ...

    def seal(self, witness: AuditWitness) -> AuditSeal:
        """Return an externally retainable commitment to the current chain."""
        ...

    def verify_seal(self, seal: AuditSeal, witness: AuditWitness) -> bool:
        """Verify chain integrity, retained length, head, stream, and signature."""
        ...


@dataclass(frozen=True, slots=True)
class ToolCall:
    """Normalized security request for one physical tool execution."""

    tool: Tool
    args: Mapping[str, Any]
    normalized: Mapping[str, Any]
    call_id: str
    call_index: int
    history: Sequence[AuditRecord] = ()
    execution_binding: Mapping[str, Any] = field(default_factory=dict)
    analysis_snapshot: Any = field(default=None, compare=False, repr=False)

    def __post_init__(self) -> None:
        if not self.call_id or self.call_index < 0:
            raise ValueError("tool call id must be non-empty and index non-negative")
        object.__setattr__(self, "args", MappingProxyType(dict(self.args)))
        object.__setattr__(self, "normalized", MappingProxyType(dict(self.normalized)))
        object.__setattr__(self, "history", tuple(self.history))
        object.__setattr__(
            self, "execution_binding", MappingProxyType(dict(self.execution_binding))
        )
