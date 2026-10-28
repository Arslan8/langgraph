"""dataset_read route evidence: policy-before-open ordering and fixed controls."""

from pathlib import Path

import pytest

from langgraph.prebuilt.security.dataset_route_verification import verify_dataset_route

_SOURCE = (
    Path(__file__).resolve().parents[2]
    / "langgraph/prebuilt/security/dataset_operation.py"
).read_text()


def test_actual_source_proves_the_route():
    report = verify_dataset_route(_SOURCE)
    assert report["proved"], report["issues"]
    assert report["controls"]["deny_opens"] == 0
    assert report["system_complete"] is False


@pytest.mark.parametrize(
    "original,replacement,reason",
    [
        (
            "    _require_allow(decision)\n    return _read_pinned(entry)",
            "    return _read_pinned(entry)",
            "require allow in sequence",
        ),
        (
            "    entry, request = _prepare(principal, dataset_id, registry, authorize)\n    decision = authorize(principal, request)\n    if inspect.isawaitable(decision):\n        if inspect.iscoroutine",
            "    entry, request = _prepare(principal, dataset_id, registry, authorize)\n    _read_pinned(entry)\n    decision = authorize(principal, request)\n    if inspect.isawaitable(decision):\n        if inspect.iscoroutine",
            "reads before the allow check",
        ),
        ("or decision.constraints != ()", "or False", "exact unconstrained allow"),
        ("no_symlinks=True", "no_symlinks=False", "no_symlinks=True"),
        (
            '    if not hmac.compare_digest(hashlib.sha256(data).hexdigest(), entry.sha256):\n        raise UnsupportedFeatureError("dataset:changed")\n    return data',
            "    return data",
            "digest of exactly the returned bytes",
        ),
    ],
)
def test_mutations_leave_the_route_unproved(original, replacement, reason):
    assert _SOURCE.count(original) == 1, original
    report = verify_dataset_route(_SOURCE.replace(original, replacement))
    assert not report["proved"]
    assert any(reason in issue for issue in report["issues"]), report["issues"]


def test_extra_caller_of_the_pinned_read_is_unproved():
    changed = _SOURCE + "\n\ndef leak(entry):\n    return _read_pinned(entry)\n"
    report = verify_dataset_route(changed)
    assert not report["proved"]
    assert any("reachable from" in issue for issue in report["issues"])


def test_unparsable_source_is_unproved():
    assert not verify_dataset_route("def (")["proved"]
