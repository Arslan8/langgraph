from __future__ import annotations

from pathlib import Path

from slanggraph_eval.overhead import run_overhead


def test_e5_records_kernel_abi_and_measured_rows(tmp_path: Path) -> None:
    payload = run_overhead(
        tmp_path / "e5.json",
        tmp_path / "e5.db",
        framework_iterations=2,
        landlock_iterations=1,
        include_landlock=False,
    )

    assert payload["kernel"]
    assert isinstance(payload["landlock_abi"], int)
    assert [row["stage"] for row in payload["rows"]] == [
        "framework-baseline",
        "framework-object-manager",
    ]
    assert all(row["iterations"] == 2 for row in payload["rows"])
