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

    paths = generate_tables(audit_dir, tmp_path / "tables")
    rendered = paths[0].read_text(encoding="utf-8")
    assert "read_file" in rendered
    assert "terminal event hash" in rendered
