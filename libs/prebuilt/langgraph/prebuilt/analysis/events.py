"""Open namespaced event catalog. Registration is not instrumentation."""

from dataclasses import dataclass

from langgraph.prebuilt.analysis.contracts import AnalysisEvent, Phase
from langgraph.prebuilt.analysis.errors import ConfigurationError

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
