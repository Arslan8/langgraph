"""Observation-only pytest plugin: retain production grants, receipts and resource state."""

import dataclasses
import enum
import functools
import json
import os
import platform
import sqlite3
import time
from pathlib import Path

import pytest

EVENTS = []
START = 0


def serial(value):
    if dataclasses.is_dataclass(value):
        return {f.name: serial(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, dict):
        return {str(k): serial(v) for k, v in value.items()}
    if isinstance(value, tuple | list | set | frozenset):
        return [serial(v) for v in value]
    if value is None or isinstance(value, str | bool | int | float):
        return value
    return str(value)


def pytest_sessionstart(session):
    from langgraph.prebuilt.security.object_broker import ObjectBrokerDispatcher

    original = ObjectBrokerDispatcher.invoke

    @functools.wraps(original)
    def invoke(self, principal, call, grant):
        event = dict(
            kind="production_broker",
            principal=serial(principal),
            call=serial(call),
            grant=serial(grant),
            grant_digest=grant.digest,
        )
        EVENTS.append(event)
        start = time.perf_counter()
        try:
            result = original(self, principal, call, grant)
            event["result"] = serial(result)
            return result
        except Exception as error:
            event["error"] = dict(type=type(error).__name__, message=str(error))
            raise
        finally:
            event["elapsed_ms"] = (time.perf_counter() - start) * 1000
            event["lowering"] = serial(self.lowering_records())
            event["broker_audit"] = serial(self.audit_records())

    ObjectBrokerDispatcher.invoke = invoke


def snapshot(item):
    result = {}
    database = item.funcargs.get("database")
    if isinstance(database, Path) and database.exists():
        try:
            with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as conn:
                result["records"] = conn.execute(
                    "SELECT key,value FROM records ORDER BY key"
                ).fetchall()
        except sqlite3.Error as error:
            result["database_error"] = str(error)
    setup = item.funcargs.get("setup")
    if isinstance(setup, tuple) and len(setup) == 5 and isinstance(setup[-1], list):
        result["accepted_broker_operations"] = list(setup[-1])
    return serial(result)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item):
    global START
    EVENTS.clear()
    START = time.perf_counter()
    item._evidence_before = snapshot(item)
    yield
    item._evidence_after = snapshot(item)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    result = yield
    report = result.get_result()
    if report.when != "call" and not (report.when == "setup" and report.outcome != "passed"):
        return
    source = Path(str(item.path)).read_text()
    condition = (
        "contract_unit"
        if (
            "test_enforcement.py" in str(item.path) or "test_resource_mediator.py" in str(item.path)
        )
        else "production_test"
    )
    entry = dict(
        case_id=item.nodeid,
        repeat=int(os.environ["SLG_REPEAT"]),
        session=int(os.environ["SLG_REPEAT"]),
        mode=condition,
        concrete_executor="see invocation events; test source for non-broker routes",
        source_revision=os.environ["SLG_SOURCE_HASH"],
        host=platform.node(),
        outcome=report.outcome,
        elapsed_ms=report.duration * 1000,
        events=EVENTS,
        resource_before=getattr(item, "_evidence_before", None),
        resource_after=getattr(item, "_evidence_after", None),
        phases_not_reached="not-applicable",
        fixture_simulation="monkeypatch" in source or "test_enforcement.py" in str(item.path),
        diagnostic=str(report.longrepr) if report.failed or report.skipped else None,
    )
    with Path(os.environ["SLG_TRIALS"]).open("a") as stream:
        stream.write(json.dumps(serial(entry), sort_keys=True) + "\n")
