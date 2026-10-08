from __future__ import annotations

from pathlib import Path

from slanggraph_eval.audit import AuditWriter
from slanggraph_eval.tables import generate_tables


def test_tables_are_generated_from_verified_events(tmp_path: Path) -> None:
    audit_dir = tmp_path / "audits"
    database = audit_dir / "e1.db"
    with AuditWriter(
        database,
        experiment="E1",
        condition="static_projection",
        metadata={},
    ) as audit:
        audit.append(
            "e1_census",
            {"rows": [{"tool": "read_file", "static_sinks": 1, "progent": 1}]},
        )
        audit.append(
            "e5_overhead",
            {
                "kernel": "6.test",
                "landlock_abi": 4,
                "rows": [{"stage": "framework", "median_ms": 1.0}],
            },
        )

    paths = generate_tables(audit_dir, tmp_path / "tables")
    rendered = (tmp_path / "tables" / "e1-exposure.md").read_text(encoding="utf-8")
    assert "read_file" in rendered
    assert "terminal event hash" in rendered
    overhead = (tmp_path / "tables" / "e5-overhead.md").read_text(encoding="utf-8")
    assert "Kernel `6.test`; Landlock ABI `4`" in overhead
