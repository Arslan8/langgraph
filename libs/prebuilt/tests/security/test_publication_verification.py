"""Analyze inert adapter source fixtures; no fixture is imported or executed."""

from pathlib import Path
from textwrap import dedent

import pytest

from langgraph.prebuilt.security.publication_verification import (
    publication_spec,
    verify_publications,
)
from langgraph.prebuilt.security.verification import verify


def sources(body):
    return {
        "langgraph.prebuilt.security.object_manager": (
            "class MediatedStore:\n    def batch(self, ops):\n"
            + "\n".join("        " + line for line in dedent(body).strip().splitlines())
            + "\n"
        ),
        "langgraph.prebuilt.security.checkpoint_security": "class MediatedCheckpointer:\n    def list(self):\n        raise PermissionError('unsupported')\n",
        "langgraph.prebuilt.security.placement": "class OutputMediator:\n    def __call__(self):\n        raise PermissionError('unsupported')\n",
    }


@pytest.mark.parametrize(
    "body",
    [
        "return self._store.batch(ops)",
        "read = self._store.batch\nvalue = read(ops)\nreturn value",
        "value = self._store.batch(ops)\nauthorized = self._router.state(None, ops)\nreturn value",
        "value = self._router.state(None, ops)\nif ops:\n    return self._store.batch(ops)\nreturn value",
    ],
)
def test_aliases_and_assignment_do_not_hide_backing_publication(body):
    report = verify(publication_spec(sources(body)))
    assert not report["complete"], report
    assert any(
        not site["authorized"]
        for entry in report["entries"]
        for site in entry["publications"]
    )


def test_router_call_alone_does_not_prove_a_value_was_authorized():
    report = verify(
        publication_spec(sources("value = self._router.state(None, ops)\nreturn value"))
    )
    assert not report["complete"], report
    assert report["summary"]["unresolved"]
    assert not report["refusing_authorizers"]


def test_source_helper_is_analyzed_instead_of_trusted_by_name():
    candidate = sources("return authorize_results(self._store.batch(ops))")
    key = "langgraph.prebuilt.security.object_manager"
    candidate[key] += "\ndef authorize_results(values):\n    return values\n"
    report = verify(publication_spec(candidate))
    assert not report["complete"]
    assert any(
        key + ".authorize_results" in entry["visited_functions"]
        for entry in report["entries"]
    )


def test_missing_surface_and_dynamic_behavior_remain_unresolved():
    candidate = sources("return getattr(self, ops)()")
    candidate.pop("langgraph.prebuilt.security.placement")
    report = verify(publication_spec(candidate))
    assert not report["complete"]
    assert report["issues"]


def test_empty_source_snapshot_cannot_pass():
    assert not verify_publications({})["complete"]


def test_actual_output_guard_resolves_host_source_without_assuming_payload_admission():
    repo = Path(__file__).resolve().parents[4]
    snapshot = {
        path.relative_to(repo).as_posix(): path.read_text()
        for library in ("prebuilt", "langgraph", "checkpoint")
        for path in (repo / "libs" / library / "langgraph").rglob("*.py")
    }
    report = verify_publications(snapshot)
    collector = (
        "langgraph.prebuilt.security.object_manager.ObjectManagerHost.labels_for_output"
    )
    for suffix in ("OutputMediator._emit", "OutputMediator._aemit"):
        entry = next(
            item for item in report["entries"] if item["entry"].endswith(suffix)
        )
        assert (
            "langgraph.prebuilt.security.placement._require_output_host"
            in entry["visited_functions"]
        )
        assert collector in entry["visited_functions"]
        # Exact host binding now exposes the real collector's unresolved input,
        # recursive traversal and lock premises before later routing calls.
        assert any(issue["function"] == collector for issue in entry["issues"])
        assert entry["status"] == "unresolved"
    assert not report["complete"]
    assert not report["proof"]["terminals"]["authorizers"]

    path = "libs/prebuilt/langgraph/prebuilt/security/placement.py"
    snapshot[path] = snapshot[path].replace(
        "type(host) is not ObjectManagerHost", "not isinstance(host, ObjectManagerHost)"
    )
    weaker = verify_publications(snapshot)
    entry = next(
        item
        for item in weaker["entries"]
        if item["entry"].endswith("OutputMediator._emit")
    )
    assert collector not in entry["visited_functions"]
    assert not weaker["complete"]
