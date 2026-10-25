"""Map a replaceable classifier's outputs to monotonically restrictive findings."""

from uuid import uuid4

from langgraph.prebuilt.analysis import (
    AnalysisContext,
    AnalysisEvent,
    AnalysisFinding,
    AnalysisResult,
    AnalyzerRegistration,
    AnnotationProposal,
)
from langgraph.prebuilt.analysis.serialization import canonical
from langgraph.prebuilt.analysis_plugins.repeat_after_me.classifier import (
    ClassificationInput,
    RepeatClassifier,
)
from langgraph.prebuilt.analysis_plugins.repeat_after_me.schema import Classification

CLASSIFICATION_EVENTS = (
    "input.admit",
    "retrieval.result",
    "tool.result",
    "model.request",
)


class RepeatAfterMeAnalyzer:
    analyzer_id = "example.repeat_after_me"
    version = "1"

    def __init__(
        self, classifier: RepeatClassifier, *, max_input_bytes: int = 32768
    ) -> None:
        self.classifier, self.max_input_bytes = classifier, max_input_bytes

    def registration(self) -> AnalyzerRegistration:
        return AnalyzerRegistration(
            self.analyzer_id,
            self.version,
            self,
            CLASSIFICATION_EVENTS,
            timeout=30,
            content_access=True,
        )

    def _input(
        self, event: AnalysisEvent, context: AnalysisContext
    ) -> ClassificationInput:
        sources = tuple(
            (ref.value_id, context.resolver.resolve(ref).decode("utf-8"))
            for ref in (*event.input_refs, *event.output_refs)
        )
        if sum(len(text.encode()) for _, text in sources) > self.max_input_bytes:
            raise ValueError("ram:input_limit")
        return ClassificationInput(sources, event.event_name, canonical(event.metadata))

    def _result(self, event, context, classification):
        refs = (*event.input_refs, *event.output_refs)
        allowed = {ref.value_id for ref in refs}
        classification = Classification.model_validate_json(
            classification.model_dump_json()
        )
        if not set(classification.source_ids).issubset(allowed):
            classification = Classification(
                label="uncertain", score=0, source_ids=(), reason="invalid_source"
            )
        code = {
            "repeat_to_tool": "example.ram.suspected",
            "uncertain": "example.ram.unknown",
            "benign": "example.ram.benign",
        }[classification.label]
        subjects = tuple(
            ref
            for ref in refs
            if not classification.source_ids
            or ref.value_id in classification.source_ids
        )
        findings = (
            AnalysisFinding(
                finding_id=str(uuid4()),
                analyzer_id=self.analyzer_id,
                analyzer_version=self.version,
                code=code,
                subject_refs=subjects,
                evidence_refs=subjects,
                status="complete",
                score=classification.score,
                reason=classification.reason,
                configuration_digest=self.classifier.configuration_digest,
            ),
        )
        proposals = []
        if classification.label != "benign":
            # Existing risks are retained; benign never clears prior annotations.
            for ref in subjects:
                risks = {
                    f.code
                    for f in context.prior_findings
                    if ref in f.subject_refs and f.code != "example.ram.benign"
                }
                risks.add(code)
                proposals.append(
                    AnnotationProposal(
                        subject=ref,
                        domain="analysis.risks",
                        label_json=canonical(sorted(risks)),
                    )
                )
        return AnalysisResult(findings=findings, annotation_proposals=tuple(proposals))

    def analyze(self, event: AnalysisEvent, context: AnalysisContext) -> AnalysisResult:
        try:
            result = self.classifier.classify(self._input(event, context))
        except Exception:
            result = Classification(
                label="uncertain",
                score=0,
                source_ids=(),
                reason="classifier_unavailable",
            )
        return self._result(event, context, result)

    async def aanalyze(
        self, event: AnalysisEvent, context: AnalysisContext
    ) -> AnalysisResult:
        try:
            result = await self.classifier.aclassify(self._input(event, context))
        except Exception:
            result = Classification(
                label="uncertain",
                score=0,
                source_ids=(),
                reason="classifier_unavailable",
            )
        return self._result(event, context, result)
