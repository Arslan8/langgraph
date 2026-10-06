from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from slanggraph_eval.audit import AuditWriter, read_events


def test_audit_chain_round_trip(tmp_path: Path) -> None:
    database = tmp_path / "audit.db"
    with AuditWriter(
        database,
        experiment="E1",
        condition="test",
        metadata={"model": None},
    ) as audit:
        first = audit.append("one", {"value": 1})
        second = audit.append("two", {"value": 2})

    events = read_events(database)
    assert events == (first, second)
    assert second.previous_hash == first.event_hash


def test_audit_tampering_is_detected(tmp_path: Path) -> None:
    database = tmp_path / "audit.db"
    with AuditWriter(
        database,
        experiment="E2",
        condition="test",
        metadata={},
    ) as audit:
        audit.append("result", {"landed": True})
    connection = sqlite3.connect(database)
    connection.execute("UPDATE events SET payload_json = ?", ('{"landed":false}',))
    connection.commit()
    connection.close()

    with pytest.raises(ValueError, match="invalid audit hash"):
        read_events(database)
