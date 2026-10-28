"""Tool proposal/result instrumentation; physical effects use existing dispatch."""

from langgraph.prebuilt.analysis.adapters.boundary import BoundaryAdapter
from langgraph.prebuilt.analysis.events import (
    TOOL_DISPATCH,
    TOOL_ERROR,
    TOOL_PREPARE,
    TOOL_PROPOSE,
    TOOL_RESULT,
)


class ToolAdapter(BoundaryAdapter):
    def propose(self, name, arguments, context_refs=()):
        ref = self.value(
            {"name": name, "arguments": arguments}, context_refs, TOOL_PROPOSE
        )
        self.before(TOOL_PROPOSE, (ref,))
        return ref

    def prepare(self, proposal, arguments, injected_refs=()):
        ref = self.value(arguments, (proposal, *injected_refs), TOOL_PREPARE)
        self.before(TOOL_PREPARE, (ref,))
        return ref

    def dispatch(self, refs, *, destination, invocation_id, attempt_id, metadata):
        return self.before(
            TOOL_DISPATCH,
            refs,
            destination=destination,
            invocation_id=invocation_id,
            attempt_id=attempt_id,
            metadata=metadata,
        )

    def result(self, content, refs):
        ref = self.value(content, refs, TOOL_RESULT)
        self.before(TOOL_RESULT, (ref,))
        return ref

    def error(self, category, refs):
        # Caller supplies a bounded category, never an untrusted exception string.
        if category not in (
            "execution_failed",
            "denied",
            "cancelled",
            "invalid_output",
        ):
            raise ValueError("analysis:invalid_error_category")
        ref = self.value({"category": category}, refs, TOOL_ERROR)
        self.before(TOOL_ERROR, (ref,))
        return ref
