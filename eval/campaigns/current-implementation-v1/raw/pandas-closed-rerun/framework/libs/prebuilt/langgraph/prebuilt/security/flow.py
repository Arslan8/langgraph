"""Operator-classified scheduling and egress controls across a session."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from threading import RLock
from types import MappingProxyType
from typing import Protocol, runtime_checkable

from langgraph.prebuilt.security.execution import (
    HostToolExecutor,
    TerminationRecovery,
)
from langgraph.prebuilt.security.types import Decision, Principal, Verdict


class Confidentiality(IntEnum):
    """Built-in confidentiality lattice ordered from public to secret."""

    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    SECRET = 3


@dataclass(frozen=True, slots=True)
class ToolFlowRule:
    """Operator-owned read/output bound and optional outward-effect ceiling.

    `output_label` must conservatively bound every input the operation can read,
    not merely the value it declares that it will return. `sink_ceiling` must be
    set when the operation can cause any outward effect during its lifetime.
    These classifications are policy inputs, not evidence about hostile code.
    """

    output_label: Confidentiality = Confidentiality.PUBLIC
    sink_ceiling: Confidentiality | None = None


@runtime_checkable
class FlowStateStore(Protocol):
    """Atomic persistent storage for session labels and active sinks."""

    @property
    def persistent(self) -> bool:
        """Whether labels and unresolved reservations survive process restart."""
        ...

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

    def transfer_label(
        self,
        source_user_id: str,
        source_session_id: str,
        target_user_id: str,
        target_session_id: str,
    ) -> str | None:
        """Propagate a label to a target session or return a conflict reason."""
        ...

    def retain(
        self,
        user_id: str,
        session_id: str,
        sink_ceiling: Confidentiality | None,
        recovery: TerminationRecovery,
    ) -> None:
        """Bind an active reservation to uncertain worker termination."""
        ...

    def recover(
        self,
        user_id: str,
        session_id: str,
        recovery_id: str,
        confirmer: Callable[[TerminationRecovery], bool],
    ) -> bool:
        """Release one retained reservation after kernel termination evidence."""
        ...

    def unresolved(self, user_id: str, session_id: str) -> tuple[str, ...]:
        """Return retained recovery identities for one authenticated session."""
        ...


class MemoryFlowStateStore:
    """Thread-safe process-local session flow-state store."""

    def __init__(self) -> None:
        self._labels: dict[tuple[str, str], Confidentiality] = {}
        self._active_sinks: dict[tuple[str, str], dict[Confidentiality, int]] = {}
        self._unresolved: dict[
            str,
            tuple[tuple[str, str], Confidentiality, TerminationRecovery],
        ] = {}
        self._lock = RLock()

    @property
    def persistent(self) -> bool:
        """Return false because this store does not survive process restart."""
        return False

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

    def transfer_label(
        self,
        source_user_id: str,
        source_session_id: str,
        target_user_id: str,
        target_session_id: str,
    ) -> str | None:
        """Atomically join a source session label into a target session."""
        with self._lock:
            source = self._labels.get(
                (source_user_id, source_session_id), Confidentiality.PUBLIC
            )
            target_key = (target_user_id, target_session_id)
            target = max(self._labels.get(target_key, Confidentiality.PUBLIC), source)
            active = self._active_sinks.get(target_key, {})
            if any(target > ceiling and count for ceiling, count in active.items()):
                return "flow:concurrent_egress"
            self._labels[target_key] = target
            return None

    def retain(
        self,
        user_id: str,
        session_id: str,
        sink_ceiling: Confidentiality | None,
        recovery: TerminationRecovery,
    ) -> None:
        """Retain an active sink until its worker is proven terminated."""
        if sink_ceiling is None:
            return
        with self._lock:
            key = (user_id, session_id)
            if self._active_sinks.get(key, {}).get(sink_ceiling, 0) <= 0:
                raise ValueError("cannot retain a missing flow reservation")
            if recovery.recovery_id in self._unresolved:
                raise ValueError("duplicate termination recovery identity")
            self._unresolved[recovery.recovery_id] = (
                key,
                sink_ceiling,
                recovery,
            )

    def recover(
        self,
        user_id: str,
        session_id: str,
        recovery_id: str,
        confirmer: Callable[[TerminationRecovery], bool],
    ) -> bool:
        """Release a retained sink only after trusted termination confirmation."""
        with self._lock:
            retained = self._unresolved.get(recovery_id)
            if retained is None or retained[0] != (user_id, session_id):
                return False
            if not confirmer(retained[2]):
                return False
            self.release(user_id, session_id, retained[1])
            del self._unresolved[recovery_id]
            return True

    def unresolved(self, user_id: str, session_id: str) -> tuple[str, ...]:
        """Return process-local retained recovery identities."""
        with self._lock:
            key = (user_id, session_id)
            return tuple(
                sorted(
                    recovery_id
                    for recovery_id, retained in self._unresolved.items()
                    if retained[0] == key
                )
            )


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
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS flow_unresolved (
                recovery_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                ceiling INTEGER NOT NULL,
                pid INTEGER NOT NULL,
                start_time TEXT NOT NULL,
                boot_id TEXT NOT NULL
            )
            """
        )
        self._connection.commit()

    @property
    def persistent(self) -> bool:
        """Return true because SQLite retains labels and reservations durably."""
        return True

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

    def transfer_label(
        self,
        source_user_id: str,
        source_session_id: str,
        target_user_id: str,
        target_session_id: str,
    ) -> str | None:
        """Atomically join a source session label into a target session."""
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                source_row = self._connection.execute(
                    "SELECT label FROM flow_state WHERE user_id = ? AND session_id = ?",
                    (source_user_id, source_session_id),
                ).fetchone()
                target_row = self._connection.execute(
                    "SELECT label FROM flow_state WHERE user_id = ? AND session_id = ?",
                    (target_user_id, target_session_id),
                ).fetchone()
                source = (
                    Confidentiality.PUBLIC
                    if source_row is None
                    else Confidentiality(int(source_row[0]))
                )
                target = max(
                    Confidentiality.PUBLIC
                    if target_row is None
                    else Confidentiality(int(target_row[0])),
                    source,
                )
                active = self._connection.execute(
                    """
                    SELECT ceiling FROM flow_active_sinks
                    WHERE user_id = ? AND session_id = ? AND active_count > 0
                    """,
                    (target_user_id, target_session_id),
                ).fetchall()
                if any(target > Confidentiality(int(item[0])) for item in active):
                    self._connection.rollback()
                    return "flow:concurrent_egress"
                self._connection.execute(
                    """
                    INSERT INTO flow_state (user_id, session_id, label)
                    VALUES (?, ?, ?)
                    ON CONFLICT(user_id, session_id) DO UPDATE SET
                        label = MAX(flow_state.label, excluded.label)
                    """,
                    (target_user_id, target_session_id, int(target)),
                )
                self._connection.commit()
                return None
            except BaseException:
                self._connection.rollback()
                raise

    def retain(
        self,
        user_id: str,
        session_id: str,
        sink_ceiling: Confidentiality | None,
        recovery: TerminationRecovery,
    ) -> None:
        """Durably bind an active sink to uncertain worker termination."""
        if sink_ceiling is None:
            return
        with self._lock, self._connection:
            active = self._connection.execute(
                """
                SELECT active_count FROM flow_active_sinks
                WHERE user_id = ? AND session_id = ? AND ceiling = ?
                """,
                (user_id, session_id, int(sink_ceiling)),
            ).fetchone()
            if active is None or int(active[0]) <= 0:
                raise ValueError("cannot retain a missing flow reservation")
            self._connection.execute(
                """
                INSERT INTO flow_unresolved
                    (recovery_id, user_id, session_id, ceiling, pid, start_time, boot_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    recovery.recovery_id,
                    user_id,
                    session_id,
                    int(sink_ceiling),
                    recovery.pid,
                    recovery.start_time,
                    recovery.boot_id,
                ),
            )

    def recover(
        self,
        user_id: str,
        session_id: str,
        recovery_id: str,
        confirmer: Callable[[TerminationRecovery], bool],
    ) -> bool:
        """Release a retained sink only after trusted termination confirmation."""
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._connection.execute(
                    """
                    SELECT ceiling, pid, start_time, boot_id FROM flow_unresolved
                    WHERE recovery_id = ? AND user_id = ? AND session_id = ?
                    """,
                    (recovery_id, user_id, session_id),
                ).fetchone()
                if row is None:
                    self._connection.rollback()
                    return False
                recovery = TerminationRecovery(
                    recovery_id,
                    int(row[1]),
                    str(row[2]),
                    str(row[3]),
                )
                if not confirmer(recovery):
                    self._connection.rollback()
                    return False
                self._connection.execute(
                    """
                    UPDATE flow_active_sinks SET active_count = active_count - 1
                    WHERE user_id = ? AND session_id = ? AND ceiling = ?
                    """,
                    (user_id, session_id, int(row[0])),
                )
                self._connection.execute(
                    """
                    DELETE FROM flow_active_sinks
                    WHERE user_id = ? AND session_id = ? AND ceiling = ?
                        AND active_count <= 0
                    """,
                    (user_id, session_id, int(row[0])),
                )
                self._connection.execute(
                    "DELETE FROM flow_unresolved WHERE recovery_id = ?",
                    (recovery_id,),
                )
                self._connection.commit()
                return True
            except BaseException:
                self._connection.rollback()
                raise

    def unresolved(self, user_id: str, session_id: str) -> tuple[str, ...]:
        """Return durably retained recovery identities."""
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT recovery_id FROM flow_unresolved
                WHERE user_id = ? AND session_id = ? ORDER BY recovery_id
                """,
                (user_id, session_id),
            ).fetchall()
        return tuple(str(row[0]) for row in rows)

    def close(self) -> None:
        """Flush and close the database connection."""
        with self._lock:
            self._connection.close()


class SessionFlowPolicy:
    """Schedule calls using operator-supplied read and outward-effect bounds.

    This policy enforces its classifications at mediated call boundaries. It is
    a confidentiality mechanism only when those classifications conservatively
    bound actual behavior and every relevant effect crosses a mediated boundary
    or is independently confined.
    """

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
        rule = self.rules.get(tool_name)
        if rule is None:
            return Decision(Verdict.DENY, "flow:unclassified")
        current = self.store.get_label(principal.user_id, principal.session_id)
        if rule.sink_ceiling is not None and current > rule.sink_ceiling:
            return Decision(Verdict.DENY, "flow:egress")
        return Decision(Verdict.ALLOW, "flow:allow")

    def acquire(
        self, principal: Principal, tool_name: str
    ) -> tuple[Decision, ToolFlowRule | None]:
        """Atomically reserve a source/sink operation until it completes."""
        rule = self.rules.get(tool_name)
        if rule is None:
            return Decision(Verdict.DENY, "flow:unclassified"), None
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

    def retain(
        self,
        principal: Principal,
        reservation: ToolFlowRule | None,
        recovery: TerminationRecovery,
    ) -> None:
        """Retain a sink reservation after uncertain worker termination."""
        if reservation is None:
            return
        self.store.retain(
            principal.user_id,
            principal.session_id,
            reservation.sink_ceiling,
            recovery,
        )

    def recover_termination(
        self,
        principal: Principal,
        recovery_id: str,
        executor: HostToolExecutor,
    ) -> bool:
        """Release a retained sink after the executor confirms termination."""
        return self.store.recover(
            principal.user_id,
            principal.session_id,
            recovery_id,
            executor.confirm_termination,
        )

    def unresolved_terminations(self, principal: Principal) -> tuple[str, ...]:
        """Return retained worker recoveries for an authenticated session."""
        return self.store.unresolved(principal.user_id, principal.session_id)

    def transfer_session(self, source: Principal, target: Principal) -> Decision:
        """Propagate taint for a mediated checkpoint, artifact, or session copy."""
        try:
            reason = self.store.transfer_label(
                source.user_id,
                source.session_id,
                target.user_id,
                target.session_id,
            )
        except BaseException:
            return Decision(Verdict.DENY, "flow:store_error")
        if reason is not None:
            return Decision(Verdict.DENY, reason)
        return Decision(Verdict.ALLOW, "flow:transfer")

    @contextmanager
    def guard_operation(
        self, principal: Principal, operation_name: str
    ) -> Iterator[None]:
        """Guard a non-tool sink such as model inference, tracing, or rendering.

        The named operation must have a configured `ToolFlowRule`. The caller
        must keep the context open for the complete effect lifetime, including
        supervised descendants and background work.
        """
        try:
            decision, reservation = self.acquire(principal, operation_name)
        except BaseException as exc:
            raise PermissionError("flow:store_error") from exc
        if decision.verdict is not Verdict.ALLOW:
            raise PermissionError(decision.reason)
        try:
            yield
        finally:
            self.release(principal, reservation)
