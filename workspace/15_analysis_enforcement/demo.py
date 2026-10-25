"""Demo 15: analysis enforcement."""

from langgraph.prebuilt.analysis import (
    BUILTIN_EVENTS,
    AnalysisConfig,
    AnalysisResult,
    AnalysisRuntime,
    AnalyzerRegistration,
    Registry,
)
from langgraph.prebuilt.analysis.provenance.store import MemoryProvenanceStore
from langgraph.prebuilt.security import (
    Principal,
    SecurityConfig,
    SecurityDeniedError,
    dac,
    guarded_tool,
    with_principal,
)
from langgraph.prebuilt.security.modules.analysis_gate import AnalysisGate


class AvailabilityCheck:
    def __init__(self, available):
        self.available = available

    def analyze(self, event, context):
        if not self.available:
            raise RuntimeError("Teaching analyzer is unavailable")
        return AnalysisResult()

    async def aanalyze(self, event, context):
        return self.analyze(event, context)


def run_case(available):
    registrations = (
        AnalyzerRegistration(
            "availability",
            "1",
            AvailabilityCheck(available),
            ("tool.dispatch",),
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
    effects = []
    security = SecurityConfig(
        modules=(AnalysisGate(runtime.config.policy_version),),
        analysis=runtime,
    )

    @guarded_tool(security=security)
    @dac(owner="user", grants={"user": "x"})
    def record(message: str) -> str:
        """Record one message in this process."""
        effects.append(message)
        return message

    try:
        principal = Principal("owner", frozenset({"user"}), frozenset(), "session")
        denied = False
        try:
            record.invoke({"message": "hello"}, with_principal({}, principal))
        except SecurityDeniedError:
            denied = True
        assert denied is (not available)
        assert effects == (["hello"] if available else [])
        label = "complete" if available else "unavailable"
        print(f"Required analysis {label}: {len(effects)} tool effect(s)")
    finally:
        runtime.close()
        store.close()


def main():
    run_case(True)
    run_case(False)


if __name__ == "__main__":
    main()
