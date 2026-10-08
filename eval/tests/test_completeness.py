from __future__ import annotations

from pathlib import Path

from slanggraph_eval.completeness import run_completeness


def test_e4_synthetic_shapes_land_on_refusing_operations(tmp_path: Path) -> None:
    root = Path(__file__).parents[2]
    payload = run_completeness(
        root,
        tmp_path / "e4.json",
        tmp_path / "e4.db",
    )

    assert payload["all_shapes_refused_before_effect"] is True
    assert payload["escape_findings_waived"] == 56
    assert all(row["executed_children"] == 0 for row in payload["rows"])
