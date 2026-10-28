"""Check matched sample integrity and independently reproduce paired statistics."""

import pytest

from slanggraph_eval.isolation.alternatives import summarize


def rows():
    return [
        dict(
            case="read",
            condition=mode,
            session=session,
            round=index,
            phase="measured",
            elapsed_ms=10 + index + (session + 1 if mode != "verified" else 0),
            valid=True,
        )
        for session in range(5)
        for index in range(20)
        for mode in ("verified", "landlock", "container")
    ]


def test_paired_session_means_and_fixed_counts():
    data = summarize(rows(), ("verified", "landlock", "container"), 20)["read"]
    for mode in ("landlock", "container"):
        difference = data["contrasts"][mode + "-verified"]
        assert difference["paired"]["n"] == 100
        assert difference["paired"]["mean_ms"] == 3
        assert difference["interval"]["session_means_ms"] == [1, 2, 3, 4, 5]


@pytest.mark.parametrize("fault", ["missing", "duplicate", "failed", "unpaired"])
def test_incomplete_or_invalid_samples_cannot_publish(fault):
    data = rows()
    if fault == "missing":
        data.pop()
    elif fault == "duplicate":
        data.append(dict(data[-1]))
    elif fault == "failed":
        data[-1]["valid"] = False
    else:
        data[-1]["round"] = 1000
    with pytest.raises(AssertionError):
        summarize(data, ("verified", "landlock", "container"), 20)
