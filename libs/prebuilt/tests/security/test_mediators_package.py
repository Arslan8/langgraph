"""Backend import compatibility and fail-closed tutorial behavior."""

import pytest

from langgraph.prebuilt.security import (
    SQLITE_RECORD_SCHEMA,
    EnforcementKind,
    ObjectGrantLine,
    Requirement,
    ResourceInvocation,
    SupportLevel,
    sqlite_record_mediator,
)
from langgraph.prebuilt.security.mediators import sqlite_record_mediator as packaged
from langgraph.prebuilt.security.mediators.sqlite import SQLITE_RECORD_SCHEMA as schema
from langgraph.prebuilt.security.mediators.template import EXAMPLE, example_mediator
from langgraph.prebuilt.security.sqlite_mediator import sqlite_record_mediator as legacy
from tests.security.test_enforcement import _context, _host


def test_existing_sqlite_imports_refer_to_the_moved_backend():
    assert sqlite_record_mediator is packaged is legacy
    assert SQLITE_RECORD_SCHEMA == schema
    assert packaged.__module__ == "langgraph.prebuilt.security.mediators.sqlite"


def test_tutorial_cannot_claim_or_execute_resource_authority():
    adapter = example_mediator()
    line = ObjectGrantLine(
        "example-read",
        "example",
        "read",
        EXAMPLE._object_id,
        {},
        Requirement.NEED,
        EnforcementKind.BROKER,
        "tutorial.example.v1",
    )
    context = ResourceInvocation(
        "alice", "session", "example_tool", "call", "grant", _context()
    )
    assessment = adapter.assess(line, _host())
    assert assessment.support is SupportLevel.UNSUPPORTED
    assert not assessment.witness
    with pytest.raises(NotImplementedError, match="activation"):
        adapter.activate((line,), context)
    with pytest.raises(NotImplementedError, match="validation"):
        adapter.invoke(line, {}, context)
    adapter.release(context)
