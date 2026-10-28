"""Bounded admission of output data and explicit framework record projections.

This validates and traverses existing values; it does not detach the payload,
authenticate label provenance, seal concurrent mutation, or prove source/runtime
bindings. Integration must admit before label collection/analysis and re-admit
each effective policy result. Privileged controller mutation remains outside this
contract. There is no generic object, mapping, dataclass or serializer fallback.
"""

from __future__ import annotations

import hashlib
import json
import math
from types import GetSetDescriptorType, MemberDescriptorType
from uuid import UUID, SafeUUID

from langchain_core.agents import AgentAction, AgentActionMessageLog, AgentFinish
from langchain_core.documents import Document
from langchain_core.messages import (
    AIMessage,
    AIMessageChunk,
    BaseMessage,
    BaseMessageChunk,
    ChatMessage,
    ChatMessageChunk,
    FunctionMessage,
    FunctionMessageChunk,
    HumanMessage,
    HumanMessageChunk,
    RemoveMessage,
    SystemMessage,
    SystemMessageChunk,
    ToolMessage,
    ToolMessageChunk,
)
from langchain_core.messages.base import TextAccessor
from langchain_core.outputs import (
    ChatGeneration,
    ChatGenerationChunk,
    ChatResult,
    Generation,
    GenerationChunk,
    LLMResult,
    RunInfo,
)
from langchain_core.prompt_values import (
    ChatPromptValue,
    ChatPromptValueConcrete,
    StringPromptValue,
)
from langgraph.callbacks import GraphInterruptEvent, GraphResumeEvent
from langgraph.types import (
    Command,
    Interrupt,
    PregelTask,
    Send,
    StateSnapshot,
    TimeoutPolicy,
)
from pydantic import BaseModel

from langgraph.prebuilt.security.objects import (
    LabeledValue,
    OutputRequest,
    SecurityLabels,
)


class OutputDataError(PermissionError):
    """Unsupported output data; diagnostic arguments omit candidate payloads.

    Exception tracebacks and inherited caller context are not sanitized here.
    """


def _native_descriptor(owner: type, name: str):
    """Capture one native field without invoking a foreign class protocol.

    The native metaclass descriptor returns actual class storage even when a
    custom metaclass overrides attribute access. Captured fields remain native
    if the public class attribute is later replaced. This does not seal module
    bindings against privileged controller mutation.
    """
    if not issubclass(type(owner), type) or type(name) is not str or not name:
        raise OutputDataError("output_data:invalid_layout")
    namespace = type.__dict__["__dict__"].__get__(owner)
    pairs = tuple(namespace.items())
    for key, _ in pairs:
        if type(key) is not str:
            raise OutputDataError("output_data:invalid_layout")
    descriptor = None
    for key, item in pairs:
        if key == name:
            descriptor = item
    if (
        type(descriptor) is not MemberDescriptorType
        and type(descriptor) is not GetSetDescriptorType
    ):
        raise OutputDataError("output_data:invalid_layout")
    descriptor_name = descriptor.__name__
    if (
        descriptor.__objclass__ is not owner
        or type(descriptor_name) is not str
        or descriptor_name != name
    ):
        raise OutputDataError("output_data:invalid_layout")
    return descriptor


_MESSAGE = ("content", "additional_kwargs", "response_metadata", "type", "name", "id")
_AI = _MESSAGE + ("tool_calls", "invalid_tool_calls", "usage_metadata")
_GENERATION = ("text", "generation_info", "type")
# Identity comparisons, not class hashing/equality, select these reviewed types.
_MODELS = (
    (BaseMessage, "BaseMessage", _MESSAGE),
    (BaseMessageChunk, "BaseMessageChunk", _MESSAGE),
    (AIMessage, "AIMessage", _AI),
    (AIMessageChunk, "AIMessageChunk", _AI + ("tool_call_chunks", "chunk_position")),
    (HumanMessage, "HumanMessage", _MESSAGE),
    (HumanMessageChunk, "HumanMessageChunk", _MESSAGE),
    (SystemMessage, "SystemMessage", _MESSAGE),
    (SystemMessageChunk, "SystemMessageChunk", _MESSAGE),
    (FunctionMessage, "FunctionMessage", _MESSAGE),
    (FunctionMessageChunk, "FunctionMessageChunk", _MESSAGE),
    (ChatMessage, "ChatMessage", _MESSAGE + ("role",)),
    (ChatMessageChunk, "ChatMessageChunk", _MESSAGE + ("role",)),
    (ToolMessage, "ToolMessage", _MESSAGE + ("tool_call_id", "artifact", "status")),
    (
        ToolMessageChunk,
        "ToolMessageChunk",
        _MESSAGE + ("tool_call_id", "artifact", "status"),
    ),
    (RemoveMessage, "RemoveMessage", _MESSAGE),
    (Generation, "Generation", _GENERATION),
    (GenerationChunk, "GenerationChunk", _GENERATION),
    (ChatGeneration, "ChatGeneration", _GENERATION + ("message",)),
    (ChatGenerationChunk, "ChatGenerationChunk", _GENERATION + ("message",)),
    (LLMResult, "LLMResult", ("generations", "llm_output", "run", "type")),
    (ChatResult, "ChatResult", ("generations", "llm_output")),
    (RunInfo, "RunInfo", ("run_id",)),
    (AgentAction, "AgentAction", ("tool", "tool_input", "log", "type")),
    (
        AgentActionMessageLog,
        "AgentActionMessageLog",
        ("tool", "tool_input", "log", "type", "message_log"),
    ),
    (AgentFinish, "AgentFinish", ("return_values", "log", "type")),
    (Document, "Document", ("id", "metadata", "page_content", "type")),
    (StringPromptValue, "StringPromptValue", ("text", "type")),
    (ChatPromptValue, "ChatPromptValue", ("messages",)),
    (ChatPromptValueConcrete, "ChatPromptValueConcrete", ("messages", "type")),
)
_EVENTS = (
    (
        GraphInterruptEvent,
        "GraphInterruptEvent",
        ("run_id", "status", "checkpoint_id", "checkpoint_ns", "interrupts"),
    ),
    (
        GraphResumeEvent,
        "GraphResumeEvent",
        ("run_id", "status", "checkpoint_id", "checkpoint_ns"),
    ),
)
_TUPLE_RECORDS = (
    (
        StateSnapshot,
        "StateSnapshot",
        (
            "values",
            "next",
            "config",
            "metadata",
            "created_at",
            "parent_config",
            "tasks",
            "interrupts",
        ),
    ),
    (
        PregelTask,
        "PregelTask",
        ("id", "name", "path", "error", "interrupts", "state", "result"),
    ),
)
_PLAIN_ERRORS = (
    BaseException,
    Exception,
    RuntimeError,
    ValueError,
    TypeError,
    AssertionError,
    LookupError,
    IndexError,
    KeyError,
    ArithmeticError,
    ZeroDivisionError,
    OverflowError,
    NotImplementedError,
)
_LABEL_SLOTS = tuple(
    _native_descriptor(SecurityLabels, name)
    for name in ("confidentiality", "integrity")
)
_VALUE_SLOTS = tuple(
    _native_descriptor(LabeledValue, name) for name in ("name", "value", "labels")
)
_INTERRUPT_SLOTS = tuple(
    _native_descriptor(Interrupt, name) for name in ("value", "id", "response_schema")
)
_REQUEST_SLOTS = tuple(
    _native_descriptor(OutputRequest, name)
    for name in ("destination", "content", "labels", "clearance", "output_id")
)
_SLOT_RECORDS = tuple(
    (cls, tag, names, tuple(_native_descriptor(cls, name) for name in names))
    for cls, tag, names in (
        (Command, "Command", ("graph", "update", "resume", "goto")),
        (Send, "Send", ("node", "arg", "timeout")),
        (TimeoutPolicy, "TimeoutPolicy", ("run_timeout", "idle_timeout", "refresh_on")),
    )
)
_MODEL_EXTRA = _native_descriptor(BaseModel, "__pydantic_extra__")
_MODEL_PRIVATE = _native_descriptor(BaseModel, "__pydantic_private__")
_MODEL_FIELDS_SET = _native_descriptor(BaseModel, "__pydantic_fields_set__")
_ERROR_ARGS = _native_descriptor(BaseException, "args")
_ERROR_TRACE = _native_descriptor(BaseException, "__traceback__")
_ERROR_CAUSE = _native_descriptor(BaseException, "__cause__")
_ERROR_CONTEXT = _native_descriptor(BaseException, "__context__")


class _Walker:
    def __init__(self, max_depth: int, max_nodes: int, max_bytes: int):
        for limit in (max_depth, max_nodes, max_bytes):
            if type(limit) is not int or limit <= 0:
                raise ValueError("output_data:invalid_budget")
        self.depth = max_depth
        self.nodes = max_nodes
        self.bytes = max_bytes
        self.active: set[int] = set()
        self.confidentiality: set[str] = set()
        self.low_integrity = False
        self.channels: dict[str, tuple] = {}

    def charge(self, amount: int = 0) -> None:
        self.nodes -= 1
        self.bytes -= amount
        if self.nodes < 0 or self.bytes < 0:
            raise OutputDataError("output_data:budget")

    def string(self, value: object, *, nonempty: bool = False) -> str:
        if type(value) is not str or (nonempty and not value):
            raise OutputDataError("output_data:string_required")
        self.charge(4 * len(value))
        return value

    def pairs(self, value: object) -> tuple:
        if type(value) is not dict:
            raise OutputDataError("output_data:native_dictionary_required")
        if len(value) > self.nodes:
            raise OutputDataError("output_data:budget")
        # No lookup, hashing, equality, or copying before every key is checked.
        pairs = tuple(dict.items(value))
        for key, _ in pairs:
            if type(key) is not str:
                raise OutputDataError("output_data:string_key_required")
        return pairs

    def string_set(self, value: object, *, mutable: bool = False) -> list:
        expected = set if mutable else frozenset
        if type(value) is not expected:
            raise OutputDataError("output_data:native_string_set_required")
        if len(value) > self.nodes:
            raise OutputDataError("output_data:budget")
        snapshot = tuple(value)
        for item in snapshot:
            self.string(item, nonempty=True)
        return sorted(snapshot)

    def labels(self, value: object, *, collect: bool = True) -> list:
        if type(value) is not SecurityLabels:
            raise OutputDataError("output_data:labels_required")
        confidentiality, integrity = (slot.__get__(value) for slot in _LABEL_SLOTS)
        compartments = self.string_set(confidentiality)
        self.string(integrity, nonempty=True)
        if collect:
            self.confidentiality.update(compartments)
            self.low_integrity |= integrity != "trusted"
        return ["SecurityLabels", compartments, integrity]

    def channel_labels(self, value: object) -> None:
        for key, labels in self.pairs(value):
            self.string(key, nonempty=True)
            _, compartments, integrity = self.labels(labels, collect=False)
            self.channels[key] = (compartments, integrity)

    def record(self, tag: str, names: tuple, values: tuple, depth: int) -> list:
        return [
            tag,
            [[name, self.walk(value, depth + 1)] for name, value in zip(names, values)],
        ]

    def walk(self, value: object, depth: int = 0) -> list:
        if depth > self.depth:
            raise OutputDataError("output_data:depth")
        kind = type(value)
        self.charge()
        if value is None:
            return ["none"]
        if kind is str:
            return ["str", self.string(value)]
        if kind is bool:
            return ["bool", value]
        if kind is int:
            self.charge((int.bit_length(value) + 7) // 8)
            return ["int", hex(value)]
        if kind is float:
            if not math.isfinite(value):
                raise OutputDataError("output_data:nonfinite_float")
            return ["float", float.hex(value)]
        if kind is bytes:
            self.charge(len(value))
            return ["bytes", bytes.hex(value)]
        identity = id(value)
        if identity in self.active:
            raise OutputDataError("output_data:cycle")
        self.active.add(identity)
        try:
            return self.compound(value, kind, depth)
        finally:
            self.active.remove(identity)

    def compound(self, value: object, kind: type, depth: int) -> list:
        if kind is TextAccessor:
            # This exact library compatibility record has no instance storage.
            # Invoke the native string projection, never its callable wrapper.
            return ["TextAccessor", self.string(str.__str__(value))]
        if kind is dict:
            pairs = self.pairs(value)
            for key, _ in pairs:
                inherited = self.channels.get(key)
                if inherited is not None:
                    self.confidentiality.update(inherited[0])
                    self.low_integrity |= inherited[1] != "trusted"
            return [
                "dict",
                [
                    [self.string(key), self.walk(child, depth + 1)]
                    for key, child in pairs
                ],
            ]
        if kind is tuple or kind is list:
            if len(value) > self.nodes:
                raise OutputDataError("output_data:budget")
            snapshot = tuple(value)
            return [
                "tuple" if kind is tuple else "list",
                [self.walk(child, depth + 1) for child in snapshot],
            ]
        if kind is SecurityLabels:
            return self.labels(value)
        if kind is LabeledValue:
            name, content, labels = (slot.__get__(value) for slot in _VALUE_SLOTS)
            self.string(name, nonempty=True)
            label_data = self.labels(labels)
            return ["LabeledValue", name, self.walk(content, depth + 1), label_data]
        if kind is Interrupt:
            content, identifier, schema = (
                slot.__get__(value) for slot in _INTERRUPT_SLOTS
            )
            self.string(identifier, nonempty=True)
            if schema is not None and type(schema) is not dict:
                raise OutputDataError("output_data:interrupt_schema")
            return self.record(
                "Interrupt",
                ("value", "id", "response_schema"),
                (content, identifier, schema),
                depth,
            )
        if kind is UUID:
            number = object.__getattribute__(value, "int")
            safe = object.__getattribute__(value, "is_safe")
            if type(number) is not int or not 0 <= number < (1 << 128):
                raise OutputDataError("output_data:uuid")
            if safe is SafeUUID.safe:
                tag = "safe"
            elif safe is SafeUUID.unsafe:
                tag = "unsafe"
            elif safe is SafeUUID.unknown:
                tag = "unknown"
            else:
                raise OutputDataError("output_data:uuid")
            return ["UUID", hex(number), tag]
        for expected, tag, names, slots in _SLOT_RECORDS:
            if kind is expected:
                if kind is Command and self.pairs(
                    object.__getattribute__(value, "__dict__")
                ):
                    raise OutputDataError("output_data:record_shape")
                return self.record(
                    tag, names, tuple(slot.__get__(value) for slot in slots), depth
                )
        for expected, tag, names in _TUPLE_RECORDS:
            if kind is expected:
                if tuple.__len__(value) != len(names):
                    raise OutputDataError("output_data:record_shape")
                return self.record(
                    tag,
                    names,
                    tuple(tuple.__getitem__(value, i) for i in range(len(names))),
                    depth,
                )
        for expected, tag, names in _EVENTS:
            if kind is expected:
                fields = self.fields(value, names)
                return self.record(tag, names, fields, depth)
        for expected, tag, names in _MODELS:
            if kind is expected:
                fields = self.fields(value, names)
                extra = _MODEL_EXTRA.__get__(value)
                private = _MODEL_PRIVATE.__get__(value)
                field_set = self.string_set(
                    _MODEL_FIELDS_SET.__get__(value), mutable=True
                )
                if extra is not None and type(extra) is not dict:
                    raise OutputDataError("output_data:model_extra")
                if private is not None and type(private) is not dict:
                    raise OutputDataError("output_data:model_private")
                return [
                    self.record(tag, names, fields, depth),
                    ["extra", self.walk(extra, depth + 1)],
                    ["private", self.walk(private, depth + 1)],
                    ["fields_set", field_set],
                ]
        for expected in _PLAIN_ERRORS:
            if kind is expected:
                if (
                    _ERROR_TRACE.__get__(value) is not None
                    or _ERROR_CAUSE.__get__(value) is not None
                    or _ERROR_CONTEXT.__get__(value) is not None
                    or self.pairs(object.__getattribute__(value, "__dict__"))
                ):
                    raise OutputDataError("output_data:live_exception")
                return [
                    "exception",
                    expected.__name__,
                    self.walk(_ERROR_ARGS.__get__(value), depth + 1),
                ]
        raise OutputDataError("output_data:unsupported_type")

    def fields(self, value: object, names: tuple) -> tuple:
        fields = self.pairs(object.__getattribute__(value, "__dict__"))
        # All keys are exact strings before this local dictionary is constructed.
        copied = dict(fields)
        if len(copied) != len(names) or any(name not in copied for name in names):
            raise OutputDataError("output_data:record_shape")
        return tuple(copied[name] for name in names)


def _walk(value, max_depth, max_nodes, max_bytes):
    walker = _Walker(max_depth, max_nodes, max_bytes)
    projection = walker.walk(value)
    return walker, projection


def validate_security_labels(value: object) -> SecurityLabels:
    """Validate exact native label fields without invoking candidate protocols."""
    try:
        _Walker(64, 100_000, 16 * 1024 * 1024).labels(value)
        return value
    except (AttributeError, RecursionError, RuntimeError):
        pass
    raise OutputDataError("output_data:invalid_layout")


def validate_output_data(
    value: object,
    *,
    max_depth: int = 64,
    max_nodes: int = 100_000,
    max_bytes: int = 16 * 1024 * 1024,
    channel_labels: dict[str, SecurityLabels] | None = None,
) -> SecurityLabels:
    """Validate bounded output and join every explicitly carried nested label.

    String accounting uses four bytes per code point as a conservative bound.
    Matching native dictionary keys conservatively inherit supplied channel
    labels without comparing values. This returns labels, not a detached
    payload or a provenance certificate.
    """
    try:
        walker = _Walker(max_depth, max_nodes, max_bytes)
        if channel_labels is not None:
            walker.channel_labels(channel_labels)
        walker.walk(value)
        return SecurityLabels(
            frozenset(walker.confidentiality),
            "low" if walker.low_integrity else "trusted",
        )
    except (AttributeError, RecursionError, RuntimeError):
        pass
    raise OutputDataError("output_data:invalid_layout")


def output_data_digest(
    value: object,
    *,
    max_depth: int = 64,
    max_nodes: int = 100_000,
    max_bytes: int = 16 * 1024 * 1024,
) -> str:
    """Digest the same validated, tagged projection; not a mutation seal.

    Dictionary insertion order is bound. Labels and native model field sets are
    sorted. All declared fields, extras and private data are included; no object
    serializer, representation, equality or arbitrary conversion is invoked.
    """
    try:
        _, projection = _walk(value, max_depth, max_nodes, max_bytes)
        encoded = json.dumps(
            projection, ensure_ascii=True, separators=(",", ":")
        ).encode("ascii")
        return hashlib.sha256(b"slanggraph-output-data-v1\x00" + encoded).hexdigest()
    except (AttributeError, RecursionError, RuntimeError):
        pass
    raise OutputDataError("output_data:invalid_layout")


def validate_output_request(value: object) -> None:
    """Validate effective output shape, excluding private analysis provenance.

    The request remains the original object. Its analysis_snapshot must be
    separately supplied/admitted by the analysis subsystem. This does not
    authorize the principal, destination, content, or declassification.
    """
    try:
        _validate_output_request(value)
        return
    except (AttributeError, RecursionError, RuntimeError):
        pass
    # Missing native slots can attach the original object to AttributeError.
    # Raising outside its handler discards that local exception context. An
    # active caller exception and traceback frames can still retain objects.
    raise OutputDataError("output_data:invalid_layout")


def _validate_output_request(value: object) -> None:
    if type(value) is not OutputRequest:
        raise OutputDataError("output_data:request_required")
    destination, content, labels, clearance, output_id = (
        slot.__get__(value) for slot in _REQUEST_SLOTS
    )
    walker = _Walker(64, 100_000, 16 * 1024 * 1024)
    walker.string(destination, nonempty=True)
    walker.string(output_id, nonempty=True)
    walker.labels(labels)
    walker.string_set(clearance)
    walker.walk(content)
    confidentiality, integrity = (slot.__get__(labels) for slot in _LABEL_SLOTS)
    if not walker.confidentiality.issubset(confidentiality):
        raise OutputDataError("output_data:payload_confidentiality")
    if walker.low_integrity and integrity == "trusted":
        raise OutputDataError("output_data:payload_integrity")
