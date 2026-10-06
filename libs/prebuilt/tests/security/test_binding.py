"""Tests for private blobs and out-of-state principal binding."""

from __future__ import annotations

from unittest.mock import Mock

import pytest

from langgraph.prebuilt.security import (
    PRINCIPAL_CONFIG_KEY,
    AuditRecord,
    MemoryAuditSink,
    Principal,
    SecurityBindingError,
    SecurityModule,
    Verdict,
    allocate_blobs,
    copy_blobs,
    principal_from,
    with_principal,
)
from langgraph.prebuilt.security.binding import history_for, next_call_index


def _principal() -> Principal:
    return Principal("alice", frozenset({"analyst"}), frozenset(), "session")


def test_blob_copy_does_not_share_slots() -> None:
    """Delegation starts from copied rather than aliased module state."""
    original = allocate_blobs(["cap", "paths"])
    original["paths"]["root"] = "/workspace"

    copied = copy_blobs(original)
    copied["paths"]["root"] = "/tmp"

    assert original["paths"]["root"] == "/workspace"
    assert copied["paths"]["root"] == "/tmp"


def test_with_principal_copies_config_and_prepares_slots() -> None:
    """Binding preserves caller config and invokes module credential setup."""

    class Labels(SecurityModule):
        name = "labels"

        def cred_prepare(self, principal: Principal, slot: object) -> None:
            slot["tenant"] = "research"  # type: ignore[index]

    principal = _principal()
    original = {"configurable": {"thread_id": "thread-1"}}

    bound = with_principal(original, principal, modules=[Labels()])

    assert PRINCIPAL_CONFIG_KEY not in original["configurable"]
    assert principal_from(bound) is principal
    assert principal.security["labels"]["tenant"] == "research"
    assert "cap" in principal.security


def test_with_principal_populates_mutable_runtime_context() -> None:
    """A graph runtime context receives the same authenticated principal."""
    context: dict[str, object] = {}
    runtime = Mock(context=context)
    principal = _principal()

    with_principal({"configurable": {"__pregel_runtime": runtime}}, principal)

    assert context[PRINCIPAL_CONFIG_KEY] is principal


def test_principal_is_never_read_from_graph_state() -> None:
    """A principal-looking state field cannot establish identity."""
    assert principal_from({"state": {PRINCIPAL_CONFIG_KEY: _principal()}}) is None


def test_invalid_reserved_value_fails_closed() -> None:
    """Corruption of the framework-owned config key is not ignored."""
    with pytest.raises(TypeError, match="invalid"):
        principal_from({"configurable": {PRINCIPAL_CONFIG_KEY: "alice"}})


def test_cred_prepare_error_aborts_binding() -> None:
    """A module failure never yields a partially prepared bound config."""

    class Broken(SecurityModule):
        name = "broken"

        def cred_prepare(self, principal: Principal, slot: object) -> None:
            raise RuntimeError("boom")

    with pytest.raises(SecurityBindingError, match="broken"):
        with_principal({}, _principal(), modules=[Broken()])


def test_call_indexes_are_shared_by_copied_runtime_configs() -> None:
    """Every execution route draws indexes from one bound-session counter."""
    bound = with_principal({}, _principal())
    copied = {**bound, "metadata": {"route": "subgraph"}}

    assert next_call_index(bound) == 0
    assert next_call_index(copied) == 1


def test_history_is_scoped_to_user_and_session() -> None:
    """Policies cannot observe audit decisions from another authenticated session."""
    sink = MemoryAuditSink()
    for user_id, session_id in (
        ("alice", "session"),
        ("alice", "other-session"),
        ("bob", "session"),
    ):
        sink.write(
            AuditRecord(
                call_index=0,
                tool_name="read_file",
                user_id=user_id,
                args_hash="redacted",
                stage="permission",
                module="paths",
                verdict=Verdict.ALLOW,
                reason="allow",
                session_id=session_id,
            )
        )

    history = history_for(sink, _principal())

    assert len(history) == 1
    assert history[0].user_id == "alice"
    assert history[0].session_id == "session"
