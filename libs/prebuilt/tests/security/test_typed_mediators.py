"""Typed clients share signatures and effects with inference and backends."""

from dataclasses import replace

import pytest
from langchain_core.tools import tool

from langgraph.prebuilt.security import (
    EnforcementKind,
    HostExecutionDenied,
    ObjectGrantLine,
    Requirement,
    ResourceInvocation,
    SecurityConfigurationError,
    object_broker,
    parse_security_manifest,
)
from langgraph.prebuilt.security.inprocess import ManifestAdmission
from langgraph.prebuilt.security.manifest_consistency import check_manifest_consistency
from langgraph.prebuilt.security.mediators.contracts import current_invocation
from langgraph.prebuilt.security.mediators.records import (
    RECORDS,
    RecordMutation,
    RecordRead,
    RecordsAPI,
    records,
)
from tests.security.test_enforcement import _context


def manifest(rules="db_record read @{record} need"):
    return parse_security_manifest(
        RECORDS.class_declaration() + "\ntool reader {\n" + rules + "\n}"
    )


def check(body, rules="db_record read @{record} need"):
    return check_manifest_consistency(
        "from langgraph.prebuilt.security.mediators.records import records as db\n"
        + "def reader(record: str, value: str):\n    "
        + body,
        manifest(rules),
        tool_name="reader",
    )


def test_client_uses_contract_and_checks_arguments_before_transport(monkeypatch):
    requests = []

    def transport(cls, operation, selector, payload):
        requests.append((cls, operation, selector, payload))
        return (
            {"found": True, "value": "hello"} if operation == "read" else {"ok": True}
        )

    monkeypatch.setattr(object_broker, "object_request", transport)
    assert records.read("notes/alice") == {"found": True, "value": "hello"}
    assert records.write(record="notes/alice", value="new") == {"ok": True}
    assert records.delete("notes/alice") == {"ok": True}
    assert requests == [
        ("db_record", "read", "notes/alice", {}),
        ("db_record", "write", "notes/alice", {"value": "new"}),
        ("db_record", "delete", "notes/alice", {}),
    ]
    with pytest.raises(TypeError):
        records.write("notes/alice", 7)
    with pytest.raises(TypeError):
        records.read("notes/alice", sql="anything")
    assert len(requests) == 3
    with pytest.raises(AttributeError):
        records.read = lambda record: "unchecked"


def test_client_rejects_invalid_response(monkeypatch):
    monkeypatch.setattr(
        object_broker, "object_request", lambda *args: {"found": "yes", "value": "x"}
    )
    with pytest.raises(TypeError, match="invalid"):
        records.read("notes/alice")


def test_checker_resolves_registered_import_aliases_and_restricts_effects():
    report = check("key = record\n    db.read(key)\n    return db.write(record, value)")
    assert not report["consistent"]
    assert report["inferred_subset_of_manifest"] is False
    assert report["outside_manifest"] == [1]
    assert [effect["operation"] for effect in report["inferred"]] == ["read", "write"]


@pytest.mark.parametrize(
    "body",
    [
        "return db.read()",
        "return db.read(record, value)",
        "return db.write(record)",
        "return db.write(record, 7)",
        "return db.write(record, db.read(record))",
        "return db.read(path=record)",
        "return db.read(record, record=value)",
    ],
)
def test_checker_rejects_invalid_typed_arguments(body):
    report = check(body)
    assert not report["consistent"]
    assert report["status"] == "mismatch"


@pytest.mark.parametrize(
    "body",
    [
        "return db.reed(record)",
        "return getattr(db, value)(record)",
        "return other.read(record)",
        "db.read = other\n    return db.read(record)",
    ],
)
def test_checker_rejects_unknown_clients_methods_and_reflection(body):
    assert check(body)["status"] == "unknown"


def test_checker_rejects_manifest_contract_drift():
    source = "from langgraph.prebuilt.security.mediators.records import records\ndef reader(record): return records.read(record)"
    wrong = parse_security_manifest(
        RECORDS.class_declaration().replace("sqlite.record.v1", "sqlite.record.v2")
        + "\ntool reader {\ndb_record read @{record} need\n}"
    )
    assert (
        check_manifest_consistency(source, wrong, tool_name="reader")["status"]
        == "mismatch"
    )


@tool
def reader(record: str) -> dict:
    """Call the registered record resource API."""
    return records.read(record)


@pytest.mark.parametrize("change", ["global", "method"])
def test_admission_binds_actual_client_and_methods(monkeypatch, change):
    admission = ManifestAdmission(reader, manifest())
    assert admission.reports[0]["consistent"]
    if change == "global":
        monkeypatch.setitem(reader.func.__globals__, "records", object())
    else:
        monkeypatch.setattr(type(records), "read", lambda self, record: "unchecked")
    with pytest.raises(HostExecutionDenied, match="client"):
        admission.validate()


def test_same_named_unregistered_client_is_not_admitted(monkeypatch):
    class Impostor:
        def read(self, record):
            return "unchecked"

    monkeypatch.setitem(reader.func.__globals__, "records", Impostor())
    with pytest.raises(SecurityConfigurationError, match="unmodeled call"):
        ManifestAdmission(reader, manifest())


class Backend(RecordsAPI):
    def __init__(self):
        self.calls = []

    def read(self, record: str) -> RecordRead:
        self.calls.append((record, current_invocation().principal_id))
        return {"found": True, "value": "safe"}

    def write(self, record: str, value: str) -> RecordMutation:
        self.calls.append((record, value))
        return {"ok": True}

    def delete(self, record: str) -> RecordMutation:
        return {"ok": True}


def test_backend_validates_before_effect_and_binds_context():
    backend = Backend()
    invoke = RECORDS.bind_backend(backend)
    line = ObjectGrantLine(
        "read",
        "db_record",
        "read",
        "notes/alice",
        {},
        Requirement.NEED,
        EnforcementKind.BROKER,
        RECORDS.lowering,
    )
    context = ResourceInvocation(
        "alice", "session", "tool", "call", "grant", _context()
    )
    assert invoke(line, {}, context) == {"found": True, "value": "safe"}
    assert backend.calls == [("notes/alice", "alice")]
    for payload in ({"record": "notes/bob"}, {"sql": "anything"}):
        with pytest.raises(ValueError):
            invoke(line, payload, context)
    with pytest.raises(PermissionError):
        invoke(replace(line, lowering="unknown"), {}, context)
    assert len(backend.calls) == 1
    with pytest.raises(PermissionError, match="no active"):
        current_invocation()


def test_backend_signature_mismatch_is_rejected_at_registration():
    class WrongBackend(Backend):
        def write(self, record: str, value: int) -> RecordMutation:
            return {"ok": True}

    with pytest.raises(TypeError, match="signature"):
        RECORDS.bind_backend(WrongBackend())


def test_missing_backend_method_cannot_be_instantiated():
    class Incomplete(RecordsAPI):
        pass

    with pytest.raises(TypeError, match="abstract"):
        Incomplete()
