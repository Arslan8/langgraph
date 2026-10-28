"""Session-level uncertainty and prevention of silently incomplete pairing."""

import math

import pytest
from scripts.repeat_protocol import session_inference


def observations():
    # Synthetic statistics fixture, never an experimental timing artifact.
    rows = []
    for session in range(5):
        for index in range(20):
            for mode in ("verified", "host"):
                rows.append(
                    {
                        "case": "read",
                        "condition": mode,
                        "session": session,
                        "round": session * 20 + index,
                        "phase": "measured",
                        "elapsed_ms": 10 + index + (session + 1 if mode == "host" else 0),
                    }
                )
    return rows


def test_interval_uses_session_means_not_call_degrees_of_freedom():
    result = session_inference(observations())["read"]["host-verified"]
    assert result["session_means_ms"] == [1, 2, 3, 4, 5]
    assert result["mean_ms"] == 3
    assert result["df"] == 4
    half = 2.7764451051977987 * math.sqrt(2.5) / math.sqrt(5)
    assert result["ci95_ms"] == pytest.approx([3 - half, 3 + half])


@pytest.mark.parametrize("fault", ["missing", "duplicate", "unpaired"])
def test_invalid_session_cannot_produce_interval(fault):
    rows = observations()
    if fault == "missing":
        rows.pop()
    elif fault == "duplicate":
        rows.append(dict(rows[-1]))
    else:
        rows[-1]["round"] = 999
    with pytest.raises(AssertionError):
        session_inference(rows)


def test_warmups_are_excluded():
    rows = observations()
    rows.append(dict(rows[0], phase="warmup", elapsed_ms=999999))
    assert session_inference(rows) == session_inference(observations())


def test_preliminary_timings_are_not_published_as_primary_results():
    from scripts.paper_evaluation import publication_view

    original = (
        "# Evaluation\n\nSecurity evidence.\n\n"
        "## 4. Application runtime overhead and variance\n\n"
        "EXPERIMENTAL_TIMING_SENTINEL 11.60x\n\n"
        "## 7. Claim boundaries and reproduction\n\nLimitations.\n"
    )
    main, appendix = publication_view(original, False)
    assert "EXPERIMENTAL_TIMING_SENTINEL" not in main
    assert "EXPERIMENTAL_TIMING_SENTINEL" in appendix
    assert "No primary runtime-overhead estimate is established yet" in main
    assert "Security evidence" in main and "Limitations" in main
    assert publication_view(original, True) == (original, None)
