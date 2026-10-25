"""Bounded, non-blocking delivery with replay and per-delivery authorization."""

from __future__ import annotations

import asyncio
from collections import deque
from threading import RLock

from langgraph.prebuilt.analysis.access.authorization import AccessPolicy
from langgraph.prebuilt.analysis.access.contracts import (
    AnalysisNotification,
    AnalysisQuery,
)
from langgraph.prebuilt.analysis.access.queries import matches, matches_finding
from langgraph.prebuilt.analysis.contracts import AnalysisSnapshot
from langgraph.prebuilt.analysis.errors import CursorExpired, SubscriptionOverflow


class AnalysisSubscription:
    def __init__(self, query: AnalysisQuery, policy: AccessPolicy) -> None:
        self.query, self.policy = query, policy
        self._queue: deque[tuple[str, AnalysisSnapshot]] = deque()
        self._lock = RLock()
        self._closed = False
        self._error: Exception | None = None
        self.last_delivered_cursor: str | None = None

    def enqueue(self, cursor: str, snapshot: AnalysisSnapshot) -> None:
        with self._lock:
            if self._closed or not matches(snapshot, self.query):
                return
            context = self.policy.context
            if (
                snapshot.principal_id != context.principal_id
                or snapshot.event.tenant_id != context.tenant_id
                or snapshot.event.session_id not in context.session_ids
            ):
                return
            if len(self._queue) >= 256:
                self._error = SubscriptionOverflow(self.last_delivered_cursor)
                self._closed = True
                self._queue.clear()
            else:
                self._queue.append((cursor, snapshot))

    def __aiter__(self):
        return self

    async def __anext__(self) -> AnalysisNotification:
        while True:
            with self._lock:
                self.policy.check()
                if self._error is not None:
                    raise self._error
                if self._queue:
                    cursor, snapshot = self._queue.popleft()
                elif self._closed:
                    raise StopAsyncIteration
                else:
                    snapshot = None
            if snapshot is None:
                await asyncio.sleep(0.01)
                continue
            if not self.policy.snapshot(snapshot):
                continue
            refs = tuple(
                ref
                for ref in (*snapshot.event.input_refs, *snapshot.event.output_refs)
                if self.policy.value(ref)
            )
            findings = tuple(
                f
                for f in snapshot.findings
                if matches_finding(f, self.query) and self.policy.finding(f)
            )
            self.last_delivered_cursor = cursor
            return AnalysisNotification(
                notification_id=snapshot.snapshot_id,
                event_id=snapshot.event.event_id,
                invocation_id=snapshot.invocation_id,
                snapshot_id=snapshot.snapshot_id,
                record_revision=snapshot.revision,
                completion_status=snapshot.status,
                run_id=snapshot.event.run_id,
                cursor=cursor,
                finding_ids=tuple(f.finding_id for f in findings),
                value_refs=refs,
                partial=len(refs) != len(snapshot.flow)
                or len(findings) != len(snapshot.findings),
            )

    async def aclose(self) -> None:
        with self._lock:
            self._closed = True
            self._queue.clear()


class NotificationHub:
    """Root-owned fanout. A subscriber never executes on the enforcement path."""

    def __init__(self, retention: int = 4096) -> None:
        self.retention = retention
        self._lock = RLock()
        self._retained: dict[str, deque[tuple[str, AnalysisSnapshot]]] = {}
        self._sequence: dict[str, int] = {}
        self._subscriptions: list[AnalysisSubscription] = []

    def publish(self, snapshot: AnalysisSnapshot) -> None:
        with self._lock:
            run = snapshot.event.run_id
            number = self._sequence.get(run, 0) + 1
            self._sequence[run] = number
            cursor = f"{run}:{number}"
            self._retained.setdefault(run, deque(maxlen=self.retention)).append(
                (cursor, snapshot)
            )
            for sub in tuple(self._subscriptions):
                sub.enqueue(cursor, snapshot)
            self._subscriptions = [
                sub for sub in self._subscriptions if not sub._closed
            ]

    def subscribe(
        self,
        query: AnalysisQuery,
        policy: AccessPolicy,
        after_cursor: str | None = None,
    ) -> AnalysisSubscription:
        policy.check()
        sub = AnalysisSubscription(query, policy)
        with self._lock:
            if after_cursor is not None:
                try:
                    run, number_text = after_cursor.rsplit(":", 1)
                    number = int(number_text)
                    retained = self._retained.get(run, ())
                    if (
                        query.run_id != run
                        or not retained
                        or number < int(retained[0][0].rsplit(":", 1)[1]) - 1
                        or number > self._sequence[run]
                    ):
                        raise ValueError
                    for cursor, snapshot in retained:
                        if int(cursor.rsplit(":", 1)[1]) > number:
                            sub.enqueue(cursor, snapshot)
                except (ValueError, KeyError) as exc:
                    raise CursorExpired("analysis:cursor_expired") from exc
            self._subscriptions.append(sub)
        return sub
