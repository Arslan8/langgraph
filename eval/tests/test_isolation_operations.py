"""Per-operation validity, timer units, and pairing regression tests."""

import pytest

from slanggraph_eval.isolation.cases import Case
from slanggraph_eval.isolation.operations import instrument, operations, summarize
from slanggraph_eval.isolation.worker import run


def test_instrumentation_preserves_result_and_reports_body_time():
    case = Case("test", "compute", "import math\nresult = math.sqrt(1764)", "answer", True)
    wrapped = instrument(case)
    assert wrapped.source.index("import math") < wrapped.source.index("_operation_start_ns")
    result = run(wrapped.source, {}, "none")
    assert result["value"] == 42
    assert result["operation_elapsed_ns"] >= 0
    assert "operation_elapsed_ns" not in run(case.source, {}, "none")


def test_all_microbenchmarks_are_allowed_and_sources_compile():
    corpus = operations()
    assert len(corpus) == len({c.name for c in corpus}) == 16
    assert all(c.allowed for c in corpus)
    for case in corpus:
        compile(instrument(case).source, case.name, "exec")
    assert {"append", "truncate", "create", "unlink", "mkdir", "fsync"} <= {c.name for c in corpus}


def rows():
    return [
        {
            "case": "read",
            "condition": condition,
            "round": index,
            "phase": "measured",
            "elapsed_ms": baseline + (5 if condition == "host" else 0),
            "setup_ms": 1,
            "effect_observed": True,
            "response": {"operation_elapsed_ns": 5000 if condition == "host" else 2000},
            "stages_ms": {"total": baseline + (5 if condition == "host" else 0)},
        }
        for condition in ("trusted", "host")
        for index, baseline in [(1, 100), (0, 10)]
    ]


def test_paired_body_units_and_covariance():
    summary = summarize(rows(), ("read",), 2)["read"]
    assert summary["paired_dispatch_ms"]["mean_ms"] == 5
    assert summary["paired_dispatch_ms"]["variance_ms2"] == 0
    assert summary["paired_body_ms"]["mean_ms"] == pytest.approx(0.003)
    assert summary["ratio_of_means"] == pytest.approx(60 / 55)


@pytest.mark.parametrize("fault", ["missing", "duplicate", "failed"])
def test_invalid_cohorts_cannot_produce_overhead_claim(fault):
    values = rows()
    if fault == "missing":
        values.pop()
    elif fault == "duplicate":
        values[-1] = dict(values[-2])
    else:
        values[-1]["effect_observed"] = False
    with pytest.raises(ValueError):
        summarize(values, ("read",), 2)


def test_saved_operation_matrix_and_stage_accounting():
    import json
    from collections import Counter
    from pathlib import Path

    root = Path(__file__).parents[1] / "reports/e6/operations-v1"
    if not (root / "plan.json").is_file():
        pytest.skip("Saved operation cohort is local generated evidence")
    plan = json.loads((root / "plan.json").read_text())
    values = [json.loads(line) for line in (root / "samples.jsonl").read_text().splitlines()]
    measured = [r for r in values if r["phase"] == "measured"]
    expected = {
        (case["name"], condition, index)
        for case in plan["operations"]
        for condition in plan["conditions"]
        for index in range(plan["warmup"] + 1, plan["warmup"] + plan["samples"] + 1)
    }
    actual = Counter((r["case"], r["condition"], r["round"]) for r in measured)
    assert actual == dict.fromkeys(expected, 1)
    for row in values:
        assert row["effect_observed"]
        assert row["response"]["operation_elapsed_ns"] >= 0
        assert row["response"]["operation_elapsed_ns"] / 1e6 <= row["elapsed_ms"]
        assert sum(row["stages_ms"].values()) == pytest.approx(row["elapsed_ms"])
        if row["condition"] == "host":
            assert row["activation_receipt"]
    assert summarize(values, tuple(c["name"] for c in plan["operations"]), plan["samples"]) == (
        json.loads((root / "summary.json").read_text())
    )
