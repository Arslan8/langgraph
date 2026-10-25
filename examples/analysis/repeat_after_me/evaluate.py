"""Held-out evaluation and separate scripted runtime overhead measurements."""

import argparse
import json
import statistics
from pathlib import Path
from time import perf_counter

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
from langgraph.prebuilt.analysis.serialization import digest
from langgraph.prebuilt.analysis_plugins.repeat_after_me import ClassificationInput

from examples.analysis.repeat_after_me.predictive import PredictiveClassifier
from examples.analysis.repeat_after_me.run_live import live_clients

CORPUS = Path(__file__).with_name("fixtures") / "evaluation.json"


def validate_corpus(cases):
    assert len(cases) == 120 and len({case["id"] for case in cases}) == 120
    for gold in ("repeat_to_tool", "benign"):
        assert (
            sum(c["gold"] == gold and c["split"] == "development" for c in cases) == 20
        )
        assert sum(c["gold"] == gold and c["split"] == "held_out" for c in cases) == 40
    for family in {case["family"] for case in cases}:
        assert len({case["split"] for case in cases if case["family"] == family}) == 1


def evaluate(classifier, cases):
    matrix = {
        gold: {
            prediction: 0
            for prediction in ("repeat_to_tool", "benign", "uncertain", "error")
        }
        for gold in ("repeat_to_tool", "benign")
    }
    latency = []
    for case in cases:
        start = perf_counter()
        try:
            candidate = ClassificationInput(
                ((case["id"], json.dumps(case["messages"])),), "input.admit", "{}"
            )
            predicted = classifier.classify(candidate).label
        except Exception:  # noqa: BLE001 - count classifier failures as errors
            predicted = "error"
        latency.append(perf_counter() - start)
        matrix[case["gold"]][predicted] += 1
    tp, fp = (
        matrix["repeat_to_tool"]["repeat_to_tool"],
        matrix["benign"]["repeat_to_tool"],
    )
    positives, negatives = (
        sum(matrix["repeat_to_tool"].values()),
        sum(matrix["benign"].values()),
    )
    uncertain = sum(row["uncertain"] for row in matrix.values())
    errors = sum(row["error"] for row in matrix.values())
    return {
        "confusion_matrix": matrix,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / positives if positives else None,
        "false_positive_rate": fp / negatives if negatives else None,
        "uncertain_error_rate": (uncertain + errors) / len(cases),
        "policy_block_rate": (tp + fp + uncertain + errors) / len(cases),
        "latency_ms_mean": statistics.mean(latency) * 1000,
        "latency_ms_max": max(latency) * 1000,
        "configuration_digest": classifier.configuration_digest,
        "cases": len(cases),
    }


class ScriptedNoop:
    def analyze(self, event, context):
        return AnalysisResult()

    async def aanalyze(self, event, context):
        return AnalysisResult()


def overhead(iterations=100):
    store = MemoryProvenanceStore()
    registry = Registry(
        BUILTIN_EVENTS,
        (
            AnalyzerRegistration(
                "benchmark.noop", "1", ScriptedNoop(), ("model.request",)
            ),
        ),
        producers=frozenset(spec.producer for spec in BUILTIN_EVENTS),
    )
    runtime = AnalysisRuntime(
        AnalysisConfig("{}", ()),
        registry,
        store,
        tenant_id="benchmark",
        session_id="s",
        run_id="r",
        principal_id="p",
    )
    adapter = BoundaryAdapter(runtime)
    ref = adapter.value("synthetic")
    timings = []
    for _ in range(iterations):
        start = perf_counter()
        adapter.before("model.request", (ref,))
        timings.append((perf_counter() - start) * 1000)
    runtime.close()
    store.close()
    return {
        "iterations": iterations,
        "mean_ms": statistics.mean(timings),
        "max_ms": max(timings),
        "backend": "sqlite-memory",
        "analyzers": 1,
        "network": False,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--live", action="store_true")
    parser.add_argument(
        "--split", choices=("development", "held_out"), default="held_out"
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--classifier", choices=("llm", "predictive", "both"), default="llm"
    )
    parser.add_argument("--backend", choices=("ollama", "llama-cpp"), default="ollama")
    parser.add_argument("--model", default="qwen3:8b")
    args = parser.parse_args()
    cases = json.loads(CORPUS.read_text())
    validate_corpus(cases)
    result = {
        "corpus_hash": digest(cases),
        "runtime_overhead": overhead(),
        "classifier_evaluation": "not run; supply --live",
    }
    if args.live or args.classifier == "predictive":
        if args.classifier == "predictive":
            classifier = PredictiveClassifier()
        else:
            _, classifier = live_clients(args.backend, args.model, args.classifier)
        result["classifier_evaluation"] = evaluate(
            classifier, [case for case in cases if case["split"] == args.split]
        )
        result["classifier_configuration"] = classifier.configuration
    print(json.dumps(result, indent=2))
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
