"""Open namespaced event catalog. Registration is not instrumentation."""

from dataclasses import dataclass
from enum import Enum

from langgraph.prebuilt.analysis.contracts import AnalysisEvent, Phase
from langgraph.prebuilt.analysis.errors import ConfigurationError


class BuiltinEvent(str, Enum):
    """Supported runtime events. Values retain the stable serialized names."""

    INPUT_ADMIT = "input.admit"
    MODEL_REQUEST = "model.request"
    MODEL_RESPONSE = "model.response"
    TOOL_PROPOSE = "tool.propose"
    TOOL_PREPARE = "tool.prepare"
    TOOL_DISPATCH = "tool.dispatch"
    TOOL_RESULT = "tool.result"
    TOOL_ERROR = "tool.error"
    RETRIEVAL_REQUEST = "retrieval.request"
    RETRIEVAL_RESULT = "retrieval.result"
    OUTPUT_EMIT = "output.emit"
    CONTEXT_BEFORE = "context.transform.before"
    CONTEXT_AFTER = "context.transform.after"
    RESOURCE_READ = "resource.read"
    RESOURCE_WRITE = "resource.write"
    RESOURCE_SEND = "resource.send"
    STATE_READ = "state.read"
    STATE_WRITE = "state.write"
    STORE_READ = "state.store.read"
    STORE_WRITE = "state.store.write"
    CHECKPOINT_SAVE = "state.checkpoint.save"
    CHECKPOINT_RESTORE = "state.checkpoint.restore"
    CHILD_START = "dispatch.child.start"
    CHILD_RETURN = "dispatch.child.return"
    BRANCH_MERGE = "dispatch.branch.merge"


# Stable string aliases used by existing boundary adapters and serialized records.
INPUT_ADMIT = BuiltinEvent.INPUT_ADMIT.value
MODEL_REQUEST = BuiltinEvent.MODEL_REQUEST.value
MODEL_RESPONSE = BuiltinEvent.MODEL_RESPONSE.value
TOOL_PROPOSE = BuiltinEvent.TOOL_PROPOSE.value
TOOL_PREPARE = BuiltinEvent.TOOL_PREPARE.value
TOOL_DISPATCH = BuiltinEvent.TOOL_DISPATCH.value
TOOL_RESULT = BuiltinEvent.TOOL_RESULT.value
TOOL_ERROR = BuiltinEvent.TOOL_ERROR.value
RETRIEVAL_REQUEST = BuiltinEvent.RETRIEVAL_REQUEST.value
RETRIEVAL_RESULT = BuiltinEvent.RETRIEVAL_RESULT.value
OUTPUT_EMIT = BuiltinEvent.OUTPUT_EMIT.value
CONTEXT_BEFORE = BuiltinEvent.CONTEXT_BEFORE.value
CONTEXT_AFTER = BuiltinEvent.CONTEXT_AFTER.value
RESOURCE_READ = BuiltinEvent.RESOURCE_READ.value
RESOURCE_WRITE = BuiltinEvent.RESOURCE_WRITE.value
RESOURCE_SEND = BuiltinEvent.RESOURCE_SEND.value
STATE_READ = BuiltinEvent.STATE_READ.value
STATE_WRITE = BuiltinEvent.STATE_WRITE.value
STORE_READ = BuiltinEvent.STORE_READ.value
STORE_WRITE = BuiltinEvent.STORE_WRITE.value
CHECKPOINT_SAVE = BuiltinEvent.CHECKPOINT_SAVE.value
CHECKPOINT_RESTORE = BuiltinEvent.CHECKPOINT_RESTORE.value
CHILD_START = BuiltinEvent.CHILD_START.value
CHILD_RETURN = BuiltinEvent.CHILD_RETURN.value
BRANCH_MERGE = BuiltinEvent.BRANCH_MERGE.value


@dataclass(frozen=True, slots=True)
class EventSpec:
    name: str
    phase: Phase
    producer: str
    barrier: bool
    schema: type[AnalysisEvent] = AnalysisEvent
    schema_version: int = 1

    def __post_init__(self) -> None:
        if not self.producer or "." not in self.name:
            raise ConfigurationError("analysis:invalid_event_spec")
        if self.phase not in ("before", "after") or self.schema_version != 1:
            raise ConfigurationError("analysis:unknown_schema")
        if not issubclass(self.schema, AnalysisEvent):
            raise ConfigurationError("analysis:incompatible_schema")


BUILTIN_EVENTS = tuple(
    EventSpec(name, phase, producer, True)
    for producer, names, phase in (
        ("input", (INPUT_ADMIT,), "before"),
        ("model", (MODEL_REQUEST,), "before"),
        ("model", (MODEL_RESPONSE,), "after"),
        ("tools", (TOOL_PROPOSE, TOOL_PREPARE, TOOL_DISPATCH), "before"),
        ("tools", (TOOL_RESULT, TOOL_ERROR), "after"),
        ("retrieval", (RETRIEVAL_REQUEST,), "before"),
        ("retrieval", (RETRIEVAL_RESULT,), "after"),
        ("context", (CONTEXT_BEFORE,), "before"),
        ("context", (CONTEXT_AFTER,), "after"),
        ("resource", (RESOURCE_READ, RESOURCE_WRITE, RESOURCE_SEND), "before"),
        (
            "state",
            (
                STATE_READ,
                STATE_WRITE,
                STORE_READ,
                STORE_WRITE,
                CHECKPOINT_SAVE,
                CHECKPOINT_RESTORE,
            ),
            "before",
        ),
        ("dispatch", (CHILD_START,), "before"),
        ("dispatch", (CHILD_RETURN, BRANCH_MERGE), "after"),
        ("output", (OUTPUT_EMIT,), "before"),
    )
    for name in names
)
