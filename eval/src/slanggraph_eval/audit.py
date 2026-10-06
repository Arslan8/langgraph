"""Small hash-chained SQLite audit log for evaluation runs."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    experiment TEXT NOT NULL,
    condition TEXT NOT NULL,
    created_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    run_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    kind TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL,
    PRIMARY KEY (run_id, sequence),
    FOREIGN KEY (run_id) REFERENCES runs(run_id)
);
"""


@dataclass(frozen=True, slots=True)
class AuditEvent:
    run_id: str
    sequence: int
    kind: str
    payload: dict[str, Any]
    previous_hash: str
    event_hash: str


class AuditWriter:
    """Append-only writer for one evaluation run."""

    def __init__(
        self,
        path: Path,
        *,
        experiment: str,
        condition: str,
        metadata: dict[str, Any],
    ) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(path)
        self._connection.executescript(_SCHEMA)
        self.run_id = str(uuid.uuid4())
        self._sequence = 0
        self._previous_hash = "0" * 64
        self._connection.execute(
            "INSERT INTO runs VALUES (?, ?, ?, ?, ?)",
            (
                self.run_id,
                experiment,
                condition,
                datetime.now(UTC).isoformat(),
                _canonical(metadata),
            ),
        )
        self._connection.commit()

    def append(self, kind: str, payload: dict[str, Any]) -> AuditEvent:
        """Append one event and return its immutable chain fields."""
        payload_json = _canonical(payload)
        material = _canonical(
            {
                "kind": kind,
                "payload": json.loads(payload_json),
                "previous_hash": self._previous_hash,
                "run_id": self.run_id,
                "sequence": self._sequence,
            }
        )
        event_hash = hashlib.sha256(material.encode()).hexdigest()
        event = AuditEvent(
            run_id=self.run_id,
            sequence=self._sequence,
            kind=kind,
            payload=json.loads(payload_json),
            previous_hash=self._previous_hash,
            event_hash=event_hash,
        )
        self._connection.execute(
            "INSERT INTO events VALUES (?, ?, ?, ?, ?, ?)",
            (
                event.run_id,
                event.sequence,
                event.kind,
                payload_json,
                event.previous_hash,
                event.event_hash,
            ),
        )
        self._connection.commit()
        self._sequence += 1
        self._previous_hash = event_hash
        return event

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> AuditWriter:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def read_events(path: Path) -> tuple[AuditEvent, ...]:
    """Read and verify every event in an audit database."""
    connection = sqlite3.connect(path)
    try:
        rows = connection.execute(
            "SELECT events.run_id, sequence, kind, payload_json, previous_hash, event_hash "
            "FROM events JOIN runs ON events.run_id = runs.run_id "
            "ORDER BY runs.created_at, events.run_id, sequence"
        ).fetchall()
    finally:
        connection.close()
    events = tuple(
        AuditEvent(
            run_id=row[0],
            sequence=row[1],
            kind=row[2],
            payload=json.loads(row[3]),
            previous_hash=row[4],
            event_hash=row[5],
        )
        for row in rows
    )
    _verify(events)
    return events


def _verify(events: tuple[AuditEvent, ...]) -> None:
    previous_by_run: dict[str, str] = {}
    sequence_by_run: dict[str, int] = {}
    for event in events:
        expected_previous = previous_by_run.get(event.run_id, "0" * 64)
        expected_sequence = sequence_by_run.get(event.run_id, 0)
        if event.previous_hash != expected_previous or event.sequence != expected_sequence:
            raise ValueError(f"broken audit chain before {event.run_id}:{event.sequence}")
        material = _canonical(
            {
                "kind": event.kind,
                "payload": event.payload,
                "previous_hash": event.previous_hash,
                "run_id": event.run_id,
                "sequence": event.sequence,
            }
        )
        expected_hash = hashlib.sha256(material.encode()).hexdigest()
        if event.event_hash != expected_hash:
            raise ValueError(f"invalid audit hash at {event.run_id}:{event.sequence}")
        previous_by_run[event.run_id] = event.event_hash
        sequence_by_run[event.run_id] = event.sequence + 1


def _canonical(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)
