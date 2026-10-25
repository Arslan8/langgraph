"""Mandatory prebuilt-agent barriers outside application model hooks."""

from collections.abc import Mapping
from uuid import uuid4

from langchain_core.runnables import RunnableLambda
from langgraph.types import Command

from langgraph.prebuilt.analysis.adapters.boundary import BoundaryAdapter
from langgraph.prebuilt.analysis.events import (
    INPUT_ADMIT,
    MODEL_REQUEST,
    MODEL_RESPONSE,
)
from langgraph.prebuilt.security.binding import principal_from
from langgraph.prebuilt.security.objects import LabeledValue, ModelInvocationRequest


def message_data(value):
    if isinstance(value, Command):
        return {
            "resume": message_data(value.resume),
            "update": message_data(value.update),
            "goto": message_data(value.goto),
        }
    if hasattr(value, "to_messages"):
        value = value.to_messages()
    if isinstance(value, Mapping):
        return {key: message_data(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [message_data(item) for item in value]
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    return value


class AgentAdapter(BoundaryAdapter):
    def input_guard(self, value, config):
        principal = principal_from(config)
        if principal is None or (principal.user_id, principal.session_id) != (
            self.runtime.principal_id,
            self.runtime.session_id,
        ):
            raise PermissionError("analysis:principal_mismatch")
        if value is not None:
            self.admit(value)

    async def ainput_guard(self, value, config):
        principal = principal_from(config)
        if principal is None or (principal.user_id, principal.session_id) != (
            self.runtime.principal_id,
            self.runtime.session_id,
        ):
            raise PermissionError("analysis:principal_mismatch")
        if value is not None:
            await self.aadmit(value)

    def refs(self):
        return self.runtime.store.run_refs(self.runtime.tenant_id, self.runtime.run_id)

    def admit(self, messages):
        # Whole history preserves multi-turn referents; no text-based identity reuse.
        ref = self.value(message_data(messages), self.refs(), INPUT_ADMIT)
        self.before(INPUT_ADMIT, (ref,))

    async def aadmit(self, messages):
        ref = self.value(message_data(messages), self.refs(), INPUT_ADMIT)
        await self.abefore(INPUT_ADMIT, (ref,))

    def wrap(
        self, model, *, tool_schemas, destination, object_router=None, flow_policy=None
    ):
        def request(messages, config):
            ref = self.value(
                {"messages": message_data(messages), "tools": tool_schemas},
                self.refs(),
                MODEL_REQUEST,
            )
            self.before(MODEL_REQUEST, (ref,), destination=destination)
            if object_router is not None:
                (
                    object_router() if callable(object_router) else object_router
                ).model_invoke(
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
                await (
                    object_router() if callable(object_router) else object_router
                ).amodel_invoke(
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

        def invoke_provider(messages, config):
            if flow_policy is None:
                return model.invoke(messages, config)
            with flow_policy.guard_operation(principal_from(config), destination):
                return model.invoke(messages, config)

        async def ainvoke_provider(messages, config):
            if flow_policy is None:
                return await model.ainvoke(messages, config)
            with flow_policy.guard_operation(principal_from(config), destination):
                return await model.ainvoke(messages, config)

        return (
            RunnableLambda(request, afunc=arequest)
            | RunnableLambda(invoke_provider, afunc=ainvoke_provider)
            | RunnableLambda(response, afunc=aresponse)
        )
