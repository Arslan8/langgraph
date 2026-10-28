"""Per-release barriers for stream chunks, direct returns, errors and artifacts."""

from langgraph.prebuilt.analysis.adapters.boundary import BoundaryAdapter
from langgraph.prebuilt.analysis.events import OUTPUT_EMIT


class OutputAdapter(BoundaryAdapter):
    def emit(self, refs, destination, release):
        self.before(OUTPUT_EMIT, refs, destination=destination)
        return release()

    async def aemit(self, refs, destination, release):
        await self.abefore(OUTPUT_EMIT, refs, destination=destination)
        return await release()
