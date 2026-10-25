"""Mandatory prebuilt-agent barriers outside application model hooks."""

from uuid import uuid4

from langchain_core.runnables import RunnableLambda
from langgraph.prebuilt.security.binding import principal_from

from langgraph.prebuilt.analysis.adapters.boundary import BoundaryAdapter
from langgraph.prebuilt.analysis.events import (
    INPUT_ADMIT,
    MODEL_REQUEST,
    MODEL_RESPONSE,
)
from langgraph.prebuilt.security.objects import LabeledValue, ModelInvocationRequest


def message_data(value):
    if hasattr(value, "to_messages"):
        value = value.to_messages()
    if isinstance(value, (list, tuple)):
        return [message_data(item) for item in value]
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    return value


class AgentAdapter(BoundaryAdapter):
    def refs(self):
        return self.runtime.store.run_refs(self.runtime.tenant_id, self.runtime.run_id)

    def admit(self, messages):
        # Whole history preserves multi-turn referents; no text-based identity reuse.
        ref = self.value(message_data(messages), self.refs(), INPUT_ADMIT)
        self.before(INPUT_ADMIT, (ref,))

    async def aadmit(self, messages):
        ref = self.value(message_data(messages), self.refs(), INPUT_ADMIT)
        await self.abefore(INPUT_ADMIT, (ref,))

    def wrap(self, model, *, tool_schemas, destination, object_router=None):
        def request(messages, config):
            ref = self.value(
                {"messages": message_data(messages), "tools": tool_schemas},
                self.refs(),
                MODEL_REQUEST,
            )
            self.before(MODEL_REQUEST, (ref,), destination=destination)
            if object_router is not None:
                object_router.model_invoke(
                    principal_from(config),
                    ModelInvocationRequest(
                        destination,
                        (LabeledValue("final-request", messages),),
                        str(uuid4()),
                    ),
                )
            return messages

        async def arequest(messages, config):
            ref = self.value(
                {"messages": message_data(messages), "tools": tool_schemas},
                self.refs(),
                MODEL_REQUEST,
            )
            await self.abefore(MODEL_REQUEST, (ref,), destination=destination)
            if object_router is not None:
                await object_router.amodel_invoke(
                    principal_from(config),
                    ModelInvocationRequest(
                        destination,
                        (LabeledValue("final-request", messages),),
                        str(uuid4()),
                    ),
                )
            return messages

        def response(result):
            ref = self.value(message_data(result), self.refs(), MODEL_RESPONSE)
            self.before(MODEL_RESPONSE, (ref,))
            return result

        async def aresponse(result):
            ref = self.value(message_data(result), self.refs(), MODEL_RESPONSE)
            await self.abefore(MODEL_RESPONSE, (ref,))
            return result

        return (
            RunnableLambda(request, afunc=arequest)
            | model
            | RunnableLambda(response, afunc=aresponse)
        )
