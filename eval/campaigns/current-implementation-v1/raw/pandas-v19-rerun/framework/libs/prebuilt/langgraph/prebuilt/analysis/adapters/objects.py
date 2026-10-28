"""Translate existing object-manager requests without replacing authorization."""

from langgraph.prebuilt.analysis.adapters.agent import message_data
from langgraph.prebuilt.analysis.adapters.boundary import BoundaryAdapter
from langgraph.prebuilt.security.objects import (
    ModelInvocationRequest,
    OutputRequest,
    StateRequest,
)


class ObjectAdapter(BoundaryAdapter):
    def event_for(self, principal, request):
        if (
            principal.user_id != self.runtime.principal_id
            or principal.session_id != self.runtime.session_id
        ):
            raise PermissionError("analysis:principal_mismatch")
        refs = self.runtime.influence_refs()
        destination = ""
        if isinstance(request, OutputRequest):
            name, destination = "output.emit", request.destination
            content = message_data(request.content)
        elif isinstance(request, ModelInvocationRequest):
            # Pre-assembly view; the agent adapter separately observes final messages.
            name, destination = "context.transform.before", request.model
            content = [message_data(item.value) for item in request.context]
        elif isinstance(request, StateRequest):
            name = {
                "write": "state.write",
                "restore": "state.checkpoint.restore",
                "tool_read": "state.read",
                "model_read": "state.read",
                "store_read": "state.store.read",
                "store_write": "state.store.write",
                "checkpoint_read": "state.checkpoint.restore",
                "checkpoint_write": "state.checkpoint.save",
            }[request.operation.value]
            content = {
                "resource": request.resource,
                "operation": request.operation.value,
            }
        else:
            return None
        ref = self.value(content, refs, name)
        return self.event(name, (ref,), destination=destination)

    def snapshot(self, principal, request):
        event = self.event_for(principal, request)
        if event is None:
            return None
        return self.runtime.process(event)

    async def asnapshot(self, principal, request):
        event = self.event_for(principal, request)
        if event is None:
            return None
        return await self.runtime.aprocess(event)
