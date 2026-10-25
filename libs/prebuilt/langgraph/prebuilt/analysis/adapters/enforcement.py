"""Composition adapter for the existing security stack, never an authorizer."""

from dataclasses import replace

from langgraph.prebuilt.analysis.adapters.boundary import BoundaryAdapter
from langgraph.prebuilt.analysis.contracts import AnalysisSnapshot
from langgraph.prebuilt.analysis.errors import AnalysisUnavailable
from langgraph.prebuilt.analysis.events import (
    TOOL_DISPATCH,
    TOOL_PREPARE,
    TOOL_PROPOSE,
    TOOL_RESULT,
)
from langgraph.prebuilt.analysis.runtime import AnalysisRuntime
from langgraph.prebuilt.analysis.serialization import freeze
from langgraph.prebuilt.security.modules.analysis_gate import request_binding
from langgraph.prebuilt.security.types import Principal, ToolCall


class EnforcementAdapter(BoundaryAdapter):
    def __init__(self, runtime: AnalysisRuntime):
        super().__init__(runtime)

    def context_refs(self):
        return self.runtime.store.run_refs(self.runtime.tenant_id, self.runtime.run_id)

    def prepare(self, principal: Principal, call: ToolCall) -> ToolCall:
        if (principal.user_id, principal.session_id) != (
            self.runtime.principal_id,
            self.runtime.session_id,
        ):
            raise AnalysisUnavailable("analysis:principal_mismatch")
        # Copy/freeze before plugin inspection, normalizers and physical dispatch.
        call = replace(
            call,
            args=freeze(call.args),
            normalized=freeze(call.normalized),
            analysis_snapshot=None,
        )
        ref = self.value(
            {"tool": call.tool.name, "args": call.args},
            self.context_refs(),
            TOOL_PROPOSE,
        )
        self.before(
            TOOL_PROPOSE,
            (ref,),
            invocation_id=call.call_id,
            attempt_id=str(call.call_index),
        )
        self.before(
            TOOL_PREPARE,
            (ref,),
            invocation_id=call.call_id,
            attempt_id=str(call.call_index),
        )
        return call

    def snapshot(self, principal: Principal, call: ToolCall) -> AnalysisSnapshot:
        ref = self.value(
            {"tool": call.tool.name, "args": call.args, "normalized": call.normalized},
            self.context_refs(),
            TOOL_DISPATCH,
        )
        event = self.event(
            TOOL_DISPATCH,
            (ref,),
            destination=call.tool.name,
            invocation_id=call.call_id,
            attempt_id=str(call.call_index),
            metadata={"request_binding": request_binding(principal, call)},
        )
        return self.runtime.process(event)

    async def asnapshot(self, principal: Principal, call: ToolCall) -> AnalysisSnapshot:
        ref = self.value(
            {"tool": call.tool.name, "args": call.args, "normalized": call.normalized},
            self.context_refs(),
            TOOL_DISPATCH,
        )
        event = self.event(
            TOOL_DISPATCH,
            (ref,),
            destination=call.tool.name,
            invocation_id=call.call_id,
            attempt_id=str(call.call_index),
            metadata={"request_binding": request_binding(principal, call)},
        )
        return await self.runtime.aprocess(event)

    def result(self, result, call: ToolCall):
        content = (
            result.model_dump(mode="json") if hasattr(result, "model_dump") else result
        )
        ref = self.value(content, self.context_refs(), TOOL_RESULT)
        self.before(
            TOOL_RESULT,
            (ref,),
            invocation_id=call.call_id,
            attempt_id=str(call.call_index),
        )
        return result

    async def aresult(self, result, call: ToolCall):
        content = (
            result.model_dump(mode="json") if hasattr(result, "model_dump") else result
        )
        ref = self.value(content, self.context_refs(), TOOL_RESULT)
        await self.abefore(
            TOOL_RESULT,
            (ref,),
            invocation_id=call.call_id,
            attempt_id=str(call.call_index),
        )
        return result
