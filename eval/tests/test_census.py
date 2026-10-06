from __future__ import annotations

from pathlib import Path

from slanggraph_eval.census import generate_census

ROOT = Path(__file__).parents[1]


def test_vulntool_census_has_one_sink_per_case(tmp_path: Path) -> None:
    rows = generate_census(
        ROOT / "vulntools" / "manifest.json",
        ROOT / "vulntools" / "tools.py",
        tmp_path,
    )

    assert len(rows) == 9
    assert all(row["static_sinks"] == 1 for row in rows)
    assert all(row["slanggraph-landlock-broker"] == 0 for row in rows)


def test_camel_hijack_is_separate_and_exposed(tmp_path: Path) -> None:
    rows = generate_census(
        ROOT / "vulntools" / "manifest.json",
        ROOT / "vulntools" / "tools.py",
        tmp_path,
    )
    hijack = next(row for row in rows if row["tool"] == "camel_argument_hijack")

    assert hijack["cohort"] == "auxiliary"
    assert hijack["camel"] == 1
