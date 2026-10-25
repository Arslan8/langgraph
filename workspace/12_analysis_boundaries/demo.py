"""Demo 12: execution boundaries."""

from langgraph.prebuilt.analysis import (
    BUILTIN_EVENTS,
    AnalysisConfig,
    AnalysisResult,
    AnalysisRuntime,
    AnalyzerRegistration,
    Registry,
)
from langgraph.prebuilt.analysis.adapters.boundary import BoundaryAdapter
from langgraph.prebuilt.analysis.provenance.store import MemoryProvenanceStore


class EventRecorder:
    def __init__(self, steps):
        self.steps = steps

    def analyze(self, event, context):
        self.steps.append(event.event_name)
        return AnalysisResult()

    async def aanalyze(self, event, context):
        return self.analyze(event, context)


def main():
    steps = []
    registrations = (
        AnalyzerRegistration(
            "recorder",
            "1",
            EventRecorder(steps),
            ("model.request", "model.response"),
        ),
    )
    store = MemoryProvenanceStore()
    registry = Registry(
        BUILTIN_EVENTS,
        registrations,
        producers=frozenset(spec.producer for spec in BUILTIN_EVENTS),
    )
    runtime = AnalysisRuntime(
        AnalysisConfig("{}", ()),
        registry,
        store,
        tenant_id="demo",
        session_id="session",
        run_id="lesson",
        principal_id="owner",
    )
    boundary = BoundaryAdapter(runtime)
    try:
        prompt = boundary.value("Say hello")

        def local_model():
            steps.append("model executes")
            return "Hello"

        result, response = boundary.call(
            "model.request",
            "model.response",
            (prompt,),
            local_model,
            lambda text: text,
        )
        assert steps == ["model.request", "model executes", "model.response"]
        assert result == "Hello"
        assert prompt in store.ancestors(response)
        print(" -> ".join(steps))
        print("Response: Hello")
    finally:
        runtime.close()
        store.close()


if __name__ == "__main__":
    main()
