"""Offline contracts: trained inference, ensemble failures, and policy integration."""

import asyncio
import tempfile
import unittest
from pathlib import Path

from langgraph.prebuilt.analysis.adapters.boundary import BoundaryAdapter
from langgraph.prebuilt.analysis_plugins.repeat_after_me import (
    Classification,
    ClassificationInput,
    ScriptedClassifier,
)
from langgraph.prebuilt.security import (
    SecurityDeniedError,
    guarded_tool,
    with_principal,
)

from examples.analysis.repeat_after_me.config import compose
from examples.analysis.repeat_after_me.predictive import (
    CombinedClassifier,
    PredictiveClassifier,
    ReportingClassifier,
    features,
    select_classifier,
)
from examples.analysis.repeat_after_me.run_live import LIVE_ATTACK_PROMPT
from examples.analysis.repeat_after_me.tools import Ledger
from examples.analysis.repeat_after_me.train_predictive import corpus


class Member:
    configuration_digest = "test"

    def __init__(self, label="benign", invalid=False, fail=False):
        self.label, self.invalid, self.fail = label, invalid, fail

    def classify(self, candidate):
        if self.fail:
            raise RuntimeError("service unavailable")
        return Classification(
            label=self.label,
            score=0.5,
            source_ids=("foreign",) if self.invalid else ("source",),
            reason="test",
        )

    async def aclassify(self, candidate):
        return self.classify(candidate)


class ClassifierTests(unittest.TestCase):
    candidate = ClassificationInput((("source", "hello"),), "input.admit", "{}")

    def test_known_attack_and_direct_request(self):
        classifier = PredictiveClassifier()
        for text, expected in (
            (LIVE_ATTACK_PROMPT, "repeat_to_tool"),
            (
                "Use record_demo_event to record the message hello from my terminal.",
                "benign",
            ),
            ("Repeat hello exactly.", "benign"),
        ):
            result = classifier.classify(
                ClassificationInput((("source", text),), "input.admit", "{}")
            )
            self.assertEqual(result.label, expected)
            self.assertEqual(result.source_ids, ("source",))

    def test_unknown_empty_and_oversized_are_uncertain(self):
        classifier = PredictiveClassifier()
        for text in ("", "🦀" * 5, "x" * 32769):
            self.assertEqual(
                classifier.classify(
                    ClassificationInput((("source", text),), "input.admit", "{}")
                ).label,
                "uncertain",
            )
        self.assertEqual(features("ＥＣＨＯ   hello"), features("echo hello"))

    def test_unanimity_and_veto_in_both_directions(self):
        for first in ("benign", "uncertain", "repeat_to_tool"):
            for second in ("benign", "uncertain", "repeat_to_tool"):
                expected = (
                    "repeat_to_tool"
                    if "repeat_to_tool" in (first, second)
                    else "uncertain"
                    if "uncertain" in (first, second)
                    else "benign"
                )
                classifier = CombinedClassifier(Member(first), Member(second))
                self.assertEqual(classifier.classify(self.candidate).label, expected)
                self.assertEqual(
                    asyncio.run(classifier.aclassify(self.candidate)).label, expected
                )

    def test_failure_and_invalid_source_do_not_become_benign(self):
        for broken in (Member(fail=True), Member(invalid=True)):
            classifier = CombinedClassifier(Member(), broken)
            self.assertEqual(classifier.classify(self.candidate).label, "uncertain")
            self.assertEqual(
                asyncio.run(classifier.aclassify(self.candidate)).label, "uncertain"
            )

    def test_async_cancellation_propagates(self):
        class Cancel(Member):
            async def aclassify(self, candidate):
                raise asyncio.CancelledError()

        with self.assertRaises(asyncio.CancelledError):
            asyncio.run(
                CombinedClassifier(Member(), Cancel()).aclassify(self.candidate)
            )

    def test_artifact_selection_and_digest(self):
        llm = Member()
        self.assertIs(select_classifier("llm", llm), llm)
        self.assertIsInstance(
            select_classifier("predictive", llm), PredictiveClassifier
        )
        self.assertIsInstance(select_classifier("both", llm), CombinedClassifier)
        self.assertEqual(
            PredictiveClassifier().configuration_digest,
            PredictiveClassifier().configuration_digest,
        )
        with self.assertRaises(FileNotFoundError):
            PredictiveClassifier("/missing/predictive-artifact.json")

    def test_reporting_is_bounded_and_omits_source_content(self):
        member = Member()
        member.configuration = {"kind": "test"}
        classifier = ReportingClassifier(member)
        for _ in range(70):
            classifier.classify(self.candidate)
        self.assertEqual(len(classifier.decisions), 64)
        self.assertEqual(set(classifier.decisions[-1]), {"event", "label", "members"})
        self.assertNotIn("hello", str(classifier.decisions))

    def test_format_families_are_separate(self):
        cases = corpus()
        train = {case["family"] for case in cases if case["split"] == "train"}
        held_out = {case["family"] for case in cases if case["split"] == "held_out"}
        self.assertFalse(train & held_out)
        self.assertIn("tagged", train)
        self.assertIn("yaml", held_out)

    def test_predictive_findings_reach_actual_tool_gate(self):
        for text, blocked in (
            (LIVE_ATTACK_PROMPT, True),
            ("Please record demo.", False),
        ):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory)
                # A benign LLM result cannot clear the predictive detector's risk.
                classifier = CombinedClassifier(
                    PredictiveClassifier(), ScriptedClassifier("benign")
                )
                runtime, security, principal, _ = compose(
                    path / "analysis.db", classifier=classifier
                )
                try:
                    boundary = BoundaryAdapter(runtime)
                    ref = boundary.value(text)
                    boundary.before("input.admit", (ref,))
                    boundary.before("model.request", (ref,))
                    ledger = Ledger(path / "ledger.db")
                    target = guarded_tool(ledger.tool(), security=security)
                    if blocked:
                        with self.assertRaises(SecurityDeniedError):
                            target.invoke(
                                {"message": "demo"}, with_principal({}, principal)
                            )
                    else:
                        target.invoke(
                            {"message": "demo"}, with_principal({}, principal)
                        )
                    self.assertEqual(ledger.count(), 0 if blocked else 1)
                finally:
                    runtime.close()
                    runtime.store.close()


if __name__ == "__main__":
    unittest.main()
