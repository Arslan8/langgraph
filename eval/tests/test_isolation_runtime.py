"""Statistics tests use deliberately reordered pairs, not implementation mirrors."""

import pytest

from slanggraph_eval.isolation.runtime import CONDITIONS, WORKLOADS, stats, summarize


def timing_rows():
    rows = []
    for workload in WORKLOADS:
        for condition in CONDITIONS:
            for index, baseline in [(1, 100.0), (0, 10.0)]:
                elapsed = baseline + (5 if condition.startswith("host") else 0)
                rows.append(
                    {
                        "case": workload,
                        "condition": condition,
                        "round": index,
                        "phase": "measured",
                        "elapsed_ms": elapsed,
                        "setup_ms": 1,
                        "effect_observed": True,
                        "stages_ms": {"total": elapsed},
                    }
                )
    return rows


def test_paired_variance_not_difference_of_marginal_variances():
    result = summarize(timing_rows())
    for workload in WORKLOADS:
        pair = result[workload]["paired"]["host-trusted"]
        assert pair["mean_ms"] == 5
        assert pair["variance_ms2"] == 0
        assert pair["ratio_of_means"] == pytest.approx(60 / 55)
        assert result[workload]["conditions"]["host"]["dispatch"]["variance_ms2"] > 0


def test_reject_incomplete_pairs():
    rows = timing_rows()
    rows.pop()
    with pytest.raises(ValueError, match="unpaired"):
        summarize(rows)


def test_sample_variance_and_nearest_rank_percentile():
    result = stats([1, 3, 5])
    assert result["mean_ms"] == 3
    assert result["variance_ms2"] == 4
    assert result["sd_ms"] == 2
    assert result["p95_ms"] == 5


def test_recorded_runtime_partition_and_pairs():
    import json
    from collections import Counter
    from pathlib import Path

    directory = Path(__file__).parents[1] / "reports/e6/runtime-v1"
    if not (directory / "samples.jsonl").is_file():
        pytest.skip("Saved runtime cohort is local generated evidence")
    rows = [json.loads(line) for line in (directory / "samples.jsonl").read_text().splitlines()]
    measured = [r for r in rows if r["phase"] == "measured"]
    assert len(rows) == 1332
    assert Counter((r["case"], r["condition"]) for r in measured) == {
        (w, c): 100 for w in WORKLOADS for c in CONDITIONS
    }
    for row in rows:
        assert row["effect_observed"]
        assert sum(row["stages_ms"].values()) == pytest.approx(row["elapsed_ms"])
        assert min(row["stages_ms"].values()) >= 0
        if row["condition"].startswith("host"):
            assert row["activation_receipt"]
    assert summarize(rows) == json.loads((directory / "summary.json").read_text())
