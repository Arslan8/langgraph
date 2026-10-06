"""Conservative session-wide information-flow enforcement."""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from threading import RLock
from types import MappingProxyType
from typing import Protocol, runtime_checkable

from langgraph.prebuilt.security.types import Decision, Principal, Verdict


class Confidentiality(IntEnum):
    """Built-in confidentiality lattice ordered from public to secret."""

    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    SECRET = 3


@dataclass(frozen=True, slots=True)
class ToolFlowRule:
    """Operator-owned possible output label and optional egress ceiling."""

    output_label: Confidentiality = Confidentiality.PUBLIC
    sink_ceiling: Confidentiality | None = None


@runtime_checkable
class FlowStateStore(Protocol):
    """Atomic persistent storage for one session's current flow label."""

    def raise_label(
        self, user_id: str, session_id: str, label: Confidentiality
    ) -> Confidentiality:
        """Atomically join a label into the session and return the result."""
        ...

    def get_label(self, user_id: str, session_id: str) -> Confidentiality:
        """Return the current session label."""
        ...

    def reserve(
        self,
        user_id: str,
        session_id: str,
        output_label: Confidentiality,
        sink_ceiling: Confidentiality | None,
    ) -> str | None:
        """Atomically reserve a call, returning a denial reason on conflict."""
        ...

    def release(
        self,
        user_id: str,
        session_id: str,
        sink_ceiling: Confidentiality | None,
    ) -> None:
        """Release a successful reservation after execution finishes."""
        ...


class MemoryFlowStateStore:
    """Thread-safe process-local session flow-state store."""

    def __init__(self) -> None:
        self._labels: dict[tuple[str, str], Confidentiality] = {}
        self._active_sinks: dict[tuple[str, str], dict[Confidentiality, int]] = {}
        self._lock = RLock()

    def raise_label(
        self, user_id: str, session_id: str, label: Confidentiality
    ) -> Confidentiality:
        with self._lock:
            key = (user_id, session_id)
            result = max(self._labels.get(key, Confidentiality.PUBLIC), label)
            self._labels[key] = result
            return result

    def get_label(self, user_id: str, session_id: str) -> Confidentiality:
        with self._lock:
            return self._labels.get((user_id, session_id), Confidentiality.PUBLIC)

    def reserve(
        self,
        user_id: str,
        session_id: str,
        output_label: Confidentiality,
        sink_ceiling: Confidentiality | None,
    ) -> str | None:
        with self._lock:
            key = (user_id, session_id)
            current = max(self._labels.get(key, Confidentiality.PUBLIC), output_label)
            active = self._active_sinks.get(key, {})
            if any(current > ceiling and count for ceiling, count in active.items()):
                return "flow:concurrent_egress"
            if sink_ceiling is not None and current > sink_ceiling:
                return "flow:egress"
            self._labels[key] = current
            if sink_ceiling is not None:
                sinks = self._active_sinks.setdefault(key, {})
                sinks[sink_ceiling] = sinks.get(sink_ceiling, 0) + 1
            return None

    def release(
        self,
        user_id: str,
        session_id: str,
        sink_ceiling: Confidentiality | None,
    ) -> None:
        if sink_ceiling is None:
            return
        with self._lock:
            key = (user_id, session_id)
            sinks = self._active_sinks.get(key)
            if not sinks or sink_ceiling not in sinks:
                return
            remaining = sinks[sink_ceiling] - 1
            if remaining:
                sinks[sink_ceiling] = remaining
            else:
                del sinks[sink_ceiling]
            if not sinks:
                del self._active_sinks[key]


class SqliteFlowStateStore:
    """SQLite WAL store preserving flow labels across checkpoints and restarts."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = RLock()
        self._connection = sqlite3.connect(self.path, check_same_thread=False)
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS flow_state (
                user_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                label INTEGER NOT NULL,
                PRIMARY KEY (user_id, session_id)
            )
            """
        )
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS flow_active_sinks (
                user_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                ceiling INTEGER NOT NULL,
                active_count INTEGER NOT NULL,
                PRIMARY KEY (user_id, session_id, ceiling)
            )
            """
        )
        self._connection.commit()

    def raise_label(
        self, user_id: str, session_id: str, label: Confidentiality
    ) -> Confidentiality:
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO flow_state (user_id, session_id, label) VALUES (?, ?, ?)
                ON CONFLICT(user_id, session_id) DO UPDATE SET
                    label = MAX(flow_state.label, excluded.label)
                """,
                (user_id, session_id, int(label)),
            )
            row = self._connection.execute(
                "SELECT label FROM flow_state WHERE user_id = ? AND session_id = ?",
                (user_id, session_id),
            ).fetchone()
            return Confidentiality(int(row[0]))

    def get_label(self, user_id: str, session_id: str) -> Confidentiality:
        with self._lock:
            row = self._connection.execute(
                "SELECT label FROM flow_state WHERE user_id = ? AND session_id = ?",
                (user_id, session_id),
            ).fetchone()
        return Confidentiality.PUBLIC if row is None else Confidentiality(int(row[0]))

    def reserve(
        self,
        user_id: str,
        session_id: str,
        output_label: Confidentiality,
        sink_ceiling: Confidentiality | None,
    ) -> str | None:
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._connection.execute(
                    "SELECT label FROM flow_state WHERE user_id = ? AND session_id = ?",
                    (user_id, session_id),
                ).fetchone()
                current = max(
                    Confidentiality.PUBLIC
                    if row is None
                    else Confidentiality(int(row[0])),
                    output_label,
                )
                active = self._connection.execute(
                    """
                    SELECT ceiling FROM flow_active_sinks
                    WHERE user_id = ? AND session_id = ? AND active_count > 0
                    """,
                    (user_id, session_id),
                ).fetchall()
                if any(current > Confidentiality(int(item[0])) for item in active):
                    self._connection.rollback()
                    return "flow:concurrent_egress"
                if sink_ceiling is not None and current > sink_ceiling:
                    self._connection.rollback()
                    return "flow:egress"
                self._connection.execute(
                    """
                    INSERT INTO flow_state (user_id, session_id, label)
                    VALUES (?, ?, ?)
                    ON CONFLICT(user_id, session_id) DO UPDATE SET
                        label = MAX(flow_state.label, excluded.label)
                    """,
                    (user_id, session_id, int(current)),
                )
                if sink_ceiling is not None:
                    self._connection.execute(
                        """
                        INSERT INTO flow_active_sinks
                            (user_id, session_id, ceiling, active_count)
                        VALUES (?, ?, ?, 1)
                        ON CONFLICT(user_id, session_id, ceiling) DO UPDATE SET
                            active_count = flow_active_sinks.active_count + 1
                        """,
                        (user_id, session_id, int(sink_ceiling)),
                    )
                self._connection.commit()
                return None
            except BaseException:
                self._connection.rollback()
                raise

    def release(
        self,
        user_id: str,
        session_id: str,
        sink_ceiling: Confidentiality | None,
    ) -> None:
        if sink_ceiling is None:
            return
        with self._lock, self._connection:
            self._connection.execute(
                """
                UPDATE flow_active_sinks SET active_count = active_count - 1
                WHERE user_id = ? AND session_id = ? AND ceiling = ?
                """,
                (user_id, session_id, int(sink_ceiling)),
            )
            self._connection.execute(
                """
                DELETE FROM flow_active_sinks
                WHERE user_id = ? AND session_id = ? AND ceiling = ?
                    AND active_count <= 0
                """,
                (user_id, session_id, int(sink_ceiling)),
            )

    def close(self) -> None:
        """Flush and close the database connection."""
        with self._lock:
            self._connection.close()


class SessionFlowPolicy:
    """Coarse but sound session-PC policy for cross-call confidentiality."""

    def __init__(
        self,
        rules: Mapping[str, ToolFlowRule],
        *,
        store: FlowStateStore | None = None,
    ) -> None:
        if not rules or any(not name for name in rules):
            raise ValueError("flow policy requires named rules")
        self.rules = MappingProxyType(dict(rules))
        self.store = store or MemoryFlowStateStore()

    def validate_tools(self, tool_names: Sequence[str]) -> None:
        """Require operator classification for every reachable tool."""
        missing = set(tool_names).difference(self.rules)
        if missing:
            raise ValueError("flow policy missing tools: " + ", ".join(sorted(missing)))

    def premark_batch(self, principal: Principal, tool_names: Sequence[str]) -> None:
        """Raise the session label before parallel calls can race each other."""
        label = max(
            (self.rules[name].output_label for name in tool_names),
            default=Confidentiality.PUBLIC,
        )
        self.store.raise_label(principal.user_id, principal.session_id, label)

    def permission(self, principal: Principal, tool_name: str) -> Decision:
        """Deny a sink whose ceiling is below accumulated session sensitivity."""
        rule = self.rules[tool_name]
        current = self.store.get_label(principal.user_id, principal.session_id)
        if rule.sink_ceiling is not None and current > rule.sink_ceiling:
            return Decision(Verdict.DENY, "flow:egress")
        return Decision(Verdict.ALLOW, "flow:allow")

    def acquire(
        self, principal: Principal, tool_name: str
    ) -> tuple[Decision, ToolFlowRule | None]:
        """Atomically reserve a source/sink operation until it completes."""
        rule = self.rules[tool_name]
        reason = self.store.reserve(
            principal.user_id,
            principal.session_id,
            rule.output_label,
            rule.sink_ceiling,
        )
        if reason is not None:
            return Decision(Verdict.DENY, reason), None
        return Decision(Verdict.ALLOW, "flow:allow"), rule

    def release(self, principal: Principal, reservation: ToolFlowRule | None) -> None:
        """Release an acquired operation reservation."""
        if reservation is None:
            return
        self.store.release(
            principal.user_id, principal.session_id, reservation.sink_ceiling
        )
