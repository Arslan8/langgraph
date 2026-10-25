"""Small trained classifier and conservative ensemble for the demo.

Inference uses a JSON artifact and the standard library; training is separate.
Scores are model outputs, not calibrated security confidence.
"""

import asyncio
import json
import math
import re
import unicodedata
from collections import deque
from pathlib import Path

from langgraph.prebuilt.analysis.serialization import digest
from langgraph.prebuilt.analysis_plugins.repeat_after_me import Classification

DEFAULT_MODEL = Path(__file__).with_name("fixtures") / "predictive_model.json"


def features(text):
    """Versioned, format-agnostic character features; keep punctuation and tags."""
    text = re.sub(r"\s+", " ", unicodedata.normalize("NFKC", text).lower())
    return {
        text[i : i + n] for n in (3, 4, 5) for i in range(max(0, len(text) - n + 1))
    }


class PredictiveClassifier:
    def __init__(self, path=DEFAULT_MODEL):
        artifact = json.loads(Path(path).read_text())
        if (
            artifact["schema_version"] != 1
            or artifact["features"] != "nfkc-char-binary-3-5-v1"
        ):
            raise ValueError("Unsupported predictive artifact")
        self.weights = artifact["weights"]
        self.intercept = artifact["intercept"]
        self.benign_max = artifact["benign_max"]
        self.attack_min = artifact["attack_min"]
        if not 0 <= self.benign_max < self.attack_min <= 1:
            raise ValueError("Invalid predictive thresholds")
        if not all(
            math.isfinite(value) for value in (self.intercept, *self.weights.values())
        ):
            raise ValueError("Non-finite predictive coefficients")
        self.configuration = {
            "kind": "predictive",
            "algorithm": "binary-char-ngram-logistic-regression",
            "artifact_digest": digest(artifact),
            "training_digest": artifact["training_digest"],
            "benign_max": self.benign_max,
            "attack_min": self.attack_min,
            "max_input_bytes": 32768,
            "calibrated": False,
        }
        self.configuration_digest = digest(self.configuration)

    def classify(self, candidate):
        refs = tuple(source_id for source_id, _ in candidate.sources)
        text = "\n".join(text for _, text in candidate.sources)
        if not refs or not text.strip() or len(text.encode()) > 32768:
            return Classification(
                label="uncertain",
                score=0,
                source_ids=refs,
                reason="predictive:missing_or_oversized_input",
            )
        present = features(text)
        known = present.intersection(self.weights)
        if not known:
            return Classification(
                label="uncertain",
                score=0,
                source_ids=refs,
                reason="predictive:no_known_features",
            )
        logit = self.intercept + sum(self.weights[feature] for feature in sorted(known))
        probability = 1 / (1 + math.exp(-max(-700, min(700, logit))))
        label = (
            "repeat_to_tool"
            if probability >= self.attack_min
            else "benign"
            if probability <= self.benign_max
            else "uncertain"
        )
        return Classification(
            label=label,
            score=probability,
            source_ids=refs,
            reason=f"predictive:{label}; attack_score={probability:.3f} (uncalibrated)",
        )

    async def aclassify(self, candidate):
        return self.classify(candidate)


class CombinedClassifier:
    """Both must say benign; suspected outranks uncertainty, which outranks benign."""

    def __init__(self, predictive, llm):
        self.members = (("predictive", predictive), ("llm", llm))
        self.configuration = {
            "kind": "both",
            "rule": "suspected_then_uncertain_then_unanimous_benign",
            "members": {
                name: member.configuration_digest for name, member in self.members
            },
        }
        self.configuration_digest = digest(self.configuration)

    @staticmethod
    def _checked(result, candidate):
        return Classification.parse(
            result.model_dump_json(), frozenset(ref for ref, _ in candidate.sources)
        )

    @staticmethod
    def _failed(candidate):
        return Classification(
            label="uncertain",
            score=0,
            source_ids=tuple(ref for ref, _ in candidate.sources),
            reason="classifier_unavailable",
        )

    def _combine(self, results, candidate):
        self.last_members = {name: result.label for name, result in results}
        labels = [result.label for _, result in results]
        label = (
            "repeat_to_tool"
            if "repeat_to_tool" in labels
            else "uncertain"
            if "uncertain" in labels
            else "benign"
        )
        # Preserve all input influence; neither member may clear the other's risks.
        return Classification(
            label=label,
            score=max(result.score for _, result in results),
            source_ids=tuple(ref for ref, _ in candidate.sources),
            reason="; ".join(
                f"{name}:{result.label} [{result.reason[:160]}]"
                for name, result in results
            )[:512],
        )

    def classify(self, candidate):
        results = []
        for name, member in self.members:
            try:
                result = self._checked(member.classify(candidate), candidate)
            except Exception:  # noqa: BLE001 - plugin failure must remain restrictive
                result = self._failed(candidate)
            results.append((name, result))
        return self._combine(results, candidate)

    async def aclassify(self, candidate):
        async def run(name, member):
            try:
                result = self._checked(await member.aclassify(candidate), candidate)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - plugin failure must remain restrictive
                result = self._failed(candidate)
            return name, result

        return self._combine(
            await asyncio.gather(*(run(name, member) for name, member in self.members)),
            candidate,
        )


def select_classifier(mode, llm, model_path=DEFAULT_MODEL):
    if mode == "llm":
        return llm
    predictive = PredictiveClassifier(model_path)
    if mode == "predictive":
        return predictive
    if mode == "both":
        return CombinedClassifier(predictive, llm)
    raise ValueError(f"Unknown classifier mode: {mode}")


class ReportingClassifier:
    """Bounded local diagnostics: labels only, no source text or free-form reasons."""

    def __init__(self, classifier):
        self.classifier = classifier
        self.configuration = classifier.configuration
        self.configuration_digest = classifier.configuration_digest
        self.decisions = deque(maxlen=64)

    def _record(self, candidate, result):
        self.decisions.append(
            {
                "event": candidate.event_name,
                "label": result.label,
                "members": dict(getattr(self.classifier, "last_members", {})),
            }
        )
        return result

    def classify(self, candidate):
        return self._record(candidate, self.classifier.classify(candidate))

    async def aclassify(self, candidate):
        return self._record(candidate, await self.classifier.aclassify(candidate))
