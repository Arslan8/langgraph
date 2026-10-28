"""The local entry point keeps listener wiring and isolation intact."""

from dataclasses import replace

import pytest

from langgraph.prebuilt.analysis import (
    AnalysisQuery,
    AnalysisResult,
    AnalyzerRegistration,
    BuiltinEvent,
    StructuredAnalysis,
)
from langgraph.prebuilt.analysis.errors import (
    AccessDenied,
    AnalysisUnavailable,
    ConfigurationError,
)


class Listener:
    def analyze(self, event, context):
        return AnalysisResult(findings=(context.finding(code="example.seen"),))

    async def aanalyze(self, event, context):
        return self.analyze(event, context)


def listener():
    return AnalyzerRegistration(analyzer=Listener(), events={BuiltinEvent.INPUT_ADMIT})


def test_local_listener_and_cleanup():
    with StructuredAnalysis(listener()) as analysis:
        document = analysis.value("report")
        snapshot = analysis.emit(BuiltinEvent.INPUT_ADMIT, (document,))
        assert snapshot.findings[0].subject_refs == (document,)
        assert snapshot.findings[0].code == "example.seen"
        later = analysis.emit(BuiltinEvent.MODEL_REQUEST, (document,))
        assert later.findings == snapshot.findings  # No new callback finding.
        with pytest.raises(ConfigurationError, match="use_builtin_event"):
            analysis.emit("input.admit")
    analysis.close()
    with pytest.raises(RuntimeError, match="session_closed"):
        analysis.value("closed")


@pytest.mark.asyncio
async def test_async_listener():
    with StructuredAnalysis(listener()) as analysis:
        document = analysis.value("report")
        snapshot = await analysis.aemit(BuiltinEvent.INPUT_ADMIT, (document,))
        assert snapshot.findings[0].subject_refs == (document,)


def test_local_sessions_are_isolated():
    with (
        StructuredAnalysis(listener()) as first,
        StructuredAnalysis(listener()) as second,
    ):
        assert first._runtime.tenant_id != second._runtime.tenant_id
        ref = first.value("private")
        with pytest.raises((KeyError, AnalysisUnavailable)):
            second.emit(BuiltinEvent.INPUT_ADMIT, (ref,))


def test_required_failure_is_not_a_clean_result():
    class Failing(Listener):
        def analyze(self, event, context):
            raise ValueError("failed")

    registration = AnalyzerRegistration(
        analyzer=Failing(), events={BuiltinEvent.INPUT_ADMIT}
    )
    with StructuredAnalysis(registration) as analysis:
        with pytest.raises(AnalysisUnavailable, match="required_unavailable"):
            analysis.emit(BuiltinEvent.INPUT_ADMIT)


def test_context_manager_closes_on_exception():
    with pytest.raises(ValueError), StructuredAnalysis() as analysis:
        raise ValueError("caller failed")
    with pytest.raises(RuntimeError, match="session_closed"):
        analysis.emit(BuiltinEvent.INPUT_ADMIT)


@pytest.mark.parametrize("result", [None, {"private_format": "ok"}])
@pytest.mark.asyncio
async def test_structured_consumer_rejects_nonstandard_results(result):
    class PrivateListener:
        def analyze(self, event, context):
            return result

        async def aanalyze(self, event, context):
            return result

    registration = AnalyzerRegistration(
        analyzer=PrivateListener(), events={BuiltinEvent.INPUT_ADMIT}
    )
    with StructuredAnalysis(registration) as analysis:
        with pytest.raises(AnalysisUnavailable, match="required_unavailable"):
            analysis.emit(BuiltinEvent.INPUT_ADMIT)
        with pytest.raises(AnalysisUnavailable, match="required_unavailable"):
            await analysis.aemit(BuiltinEvent.INPUT_ADMIT)


@pytest.mark.asyncio
async def test_local_inspection_is_scoped_and_revoked_on_close():

    with StructuredAnalysis(listener()) as analysis, StructuredAnalysis() as other:
        client = analysis.client
        subscription = client.subscribe(AnalysisQuery())
        try:
            ref = analysis.value("document")
            snapshot = analysis.emit(BuiltinEvent.INPUT_ADMIT, (ref,))
            findings = client.get_findings(AnalysisQuery())
            assert (
                findings.records
                == client.get_snapshot(snapshot.snapshot_id).snapshot.findings
            )
            assert (await anext(subscription)).completion_status == "pending"
            assert (await anext(subscription)).completion_status == "complete"
            with pytest.raises((AccessDenied, AnalysisUnavailable)):
                other.client.get_labels(ref)
            with pytest.raises(AccessDenied):
                other.client.get_snapshot(snapshot.snapshot_id)
        finally:
            await subscription.aclose()
    with pytest.raises(AccessDenied, match="access_revoked"):
        client.get_findings(AnalysisQuery())


def test_local_checkpoint_survives_source_close_without_rerunning_analyzers():

    class Counting(Listener):
        calls = 0

        def analyze(self, event, context):
            self.calls += 1
            return super().analyze(event, context)

    marker = Counting()
    registration = AnalyzerRegistration(
        analyzer=marker, events={BuiltinEvent.INPUT_ADMIT}
    )
    with StructuredAnalysis(registration, configuration={"format": "v1"}) as analysis:
        source = analysis.value("private", confidentiality={"secret"})
        summary = analysis.value("summary", parents=(source,))
        snapshot = analysis.emit(BuiltinEvent.INPUT_ADMIT, (summary,))
        checkpoint = analysis.checkpoint(summary)
        original_store = analysis._store
    with checkpoint.restore() as restored:
        assert restored._store is not original_store
        assert restored.client.get_labels(summary).record.confidentiality == frozenset(
            {"secret"}
        )
        assert {source, summary}.issubset(
            {row.ref for row in restored.client.get_provenance(summary).records}
        )
        assert (
            restored.client.get_findings(AnalysisQuery()).records == snapshot.findings
        )
        assert marker.calls == 1
        # A new session/store; notifications are not a replay of old execution.
        assert not restored._runtime.registry.analyzers
    with pytest.raises(AnalysisUnavailable, match="checkpoint_configuration_mismatch"):
        checkpoint.restore(configuration={"format": "v2"})


def test_local_checkpoint_authentication_is_not_replaced_by_automatic_ids():

    with StructuredAnalysis() as analysis:
        checkpoint = analysis.checkpoint(analysis.value("private"))
    forged = replace(checkpoint, envelope=replace(checkpoint.envelope, digest="bad"))
    with pytest.raises(PermissionError, match="invalid_hash"):
        forged.restore()
    with StructuredAnalysis() as another:
        other = another.checkpoint(another.value("other"))
    # A signed envelope from another session is not authority for this handle.
    swapped = replace(checkpoint, envelope=other.envelope)
    with pytest.raises(PermissionError, match="principal_mismatch"):
        swapped.restore()


def test_local_labels_are_explicit_sets_and_cannot_cleanse_parents():
    with StructuredAnalysis() as analysis:
        with pytest.raises(ValueError, match="string_set"):
            analysis.value("text", confidentiality="secret")
        parent = analysis.value("private", confidentiality={"secret"})
        child = analysis.value("copy", parents=(parent,), confidentiality=set())
        assert analysis.client.get_labels(child).record.confidentiality == frozenset(
            {"secret"}
        )
        with pytest.raises(ValueError, match="owned_values"):
            analysis.checkpoint()
