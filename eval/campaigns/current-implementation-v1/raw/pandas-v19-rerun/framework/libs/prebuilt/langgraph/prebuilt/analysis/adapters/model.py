"""Final-request adapter. Responses inherit every submitted context reference."""

from langgraph.prebuilt.analysis.adapters.boundary import BoundaryAdapter
from langgraph.prebuilt.analysis.contracts import ValueRef
from langgraph.prebuilt.analysis.events import MODEL_REQUEST, MODEL_RESPONSE


class ModelAdapter(BoundaryAdapter):
    def invoke(
        self,
        model,
        messages,
        *,
        refs: tuple[ValueRef, ...],
        destination: str,
        config=None,
    ):
        return self.call(
            MODEL_REQUEST,
            MODEL_RESPONSE,
            refs,
            lambda: model.invoke(messages, config),
            lambda response: (
                response.model_dump(mode="json")
                if hasattr(response, "model_dump")
                else response
            ),
            destination=destination,
        )

    async def ainvoke(
        self,
        model,
        messages,
        *,
        refs: tuple[ValueRef, ...],
        destination: str,
        config=None,
    ):
        return await self.acall(
            MODEL_REQUEST,
            MODEL_RESPONSE,
            refs,
            lambda: model.ainvoke(messages, config),
            lambda response: (
                response.model_dump(mode="json")
                if hasattr(response, "model_dump")
                else response
            ),
            destination=destination,
        )
