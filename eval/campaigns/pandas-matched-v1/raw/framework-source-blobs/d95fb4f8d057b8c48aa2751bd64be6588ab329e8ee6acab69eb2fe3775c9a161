"""Explicit retrieval and transform adapters including chunk admission."""

from langgraph.prebuilt.analysis.adapters.boundary import BoundaryAdapter
from langgraph.prebuilt.analysis.events import (
    CONTEXT_AFTER,
    CONTEXT_BEFORE,
    RETRIEVAL_REQUEST,
    RETRIEVAL_RESULT,
)


class RetrievalAdapter(BoundaryAdapter):
    def request(self, refs, destination):
        return self.before(RETRIEVAL_REQUEST, refs, destination=destination)

    def admit_chunk(self, content, query_refs=()):
        ref = self.value(content, query_refs, RETRIEVAL_RESULT)
        self.before(RETRIEVAL_RESULT, (ref,))
        return ref

    async def aadmit_chunk(self, content, query_refs=()):
        ref = self.value(content, query_refs, RETRIEVAL_RESULT)
        await self.abefore(RETRIEVAL_RESULT, (ref,))
        return ref


class TransformAdapter(BoundaryAdapter):
    def transform(self, refs, operation, encode=lambda result: result):
        return self.call(CONTEXT_BEFORE, CONTEXT_AFTER, refs, operation, encode)

    async def atransform(self, refs, operation, encode=lambda result: result):
        return await self.acall(CONTEXT_BEFORE, CONTEXT_AFTER, refs, operation, encode)
