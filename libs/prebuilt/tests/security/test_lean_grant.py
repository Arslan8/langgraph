"""Native pre-compilation admission and v3 semantic grant checks."""

from __future__ import annotations

import copy
import json
from collections.abc import Mapping
from dataclasses import replace
from types import MappingProxyType

import pytest

from langgraph.prebuilt.security import lean_grant
from langgraph.prebuilt.security.enforcement import (
    AuthorityDomain,
    EnforcementObligation,
    Grant,
    GrantRule,
    RequirementEntry,
    RequirementLedger,
    compile_obligations,
)
from langgraph.prebuilt.security.execution import HostExecutionDenied
from langgraph.prebuilt.security.lean_grant import (
    _capture_filtered_grant,
    _capture_obligations,
)
from langgraph.prebuilt.security.policy import PolicyFilterResult
from tests.security.test_enforcement import _grant, _ledger
from tests.security.test_lean_lifecycle import binary as binary
from tests.security.test_lean_lifecycle import checker as checker
from tests.security.test_lean_lifecycle import raw_check


def filtered(conditions=None):
    grant = _grant()
    if conditions is not None:
        grant = replace(grant, rules=(replace(grant.rules[0], conditions=conditions),))
    return PolicyFilterResult(grant, _ledger(), "allow")


def admitted(conditions=None):
    captured = _capture_filtered_grant(filtered(conditions))
    assert captured.filtered.grant is not None and captured.projection is not None
    obligations = _capture_obligations(compile_obligations(captured.filtered.grant))
    return captured, obligations


def test_detached_native_records_remain_useful_after_original_alias_mutation():
    original = filtered()
    backing = {"nested": {"items": [None, True, -(2**63), 2**63 - 1, "é"]}}
    object.__setattr__(original.grant.rules[0], "conditions", MappingProxyType(backing))
    captured = _capture_filtered_grant(original)
    before = captured.projection
    backing["nested"]["items"].clear()
    object.__setattr__(original.grant, "tool_name", "replacement")
    object.__setattr__(original.ledger.entries[0], "source_id", "replacement")
    assert captured.projection == before
    assert captured.filtered.grant.tool_name == "send_email"
    assert captured.filtered.ledger.entries[0].source_id == "profile:mail"
    assert captured.filtered.grant.rules[0].conditions["nested"]["items"] == (
        None,
        True,
        -(2**63),
        2**63 - 1,
        "é",
    )
    assert json.loads(before)["digest"] == captured.filtered.grant.digest
    assert captured.filtered.allowed
    assert len(compile_obligations(captured.filtered.grant)) == 10


def test_no_original_digest_or_allowed_property_invoked(monkeypatch):
    original = filtered()
    digest = Grant.digest.fget
    calls = []

    def observe(self):
        assert self is not original.grant
        calls.append(self)
        return digest(self)

    def forbidden(self):
        pytest.fail("raw filter allowed property invoked")

    monkeypatch.setattr(Grant, "digest", property(observe))
    monkeypatch.setattr(PolicyFilterResult, "allowed", property(forbidden))
    captured = _capture_filtered_grant(original)
    assert calls == [captured.filtered.grant]


def test_exact_denied_result_preserves_diagnostics_without_grant():
    original = PolicyFilterResult(
        None, _ledger(), "denied", ("mail-rule",), ("blocked",)
    )
    captured = _capture_filtered_grant(original)
    assert captured.projection is None
    assert not captured.filtered.allowed
    assert captured.filtered.reason == "denied"
    assert captured.filtered.diagnostics == ("blocked",)
    assert captured.filtered.ledger is not original.ledger


@pytest.mark.parametrize("location", ["root", "nested"])
def test_mapping_proxy_over_foreign_mapping_never_invokes_protocols(location):
    calls = []

    class Foreign(Mapping):
        def __iter__(self):
            calls.append("iter")
            raise AssertionError

        def __len__(self):
            calls.append("len")
            raise AssertionError

        def __getitem__(self, key):
            calls.append("getitem")
            raise AssertionError

        def items(self):
            calls.append("items")
            raise AssertionError

    proxy = MappingProxyType(Foreign())
    original = filtered()
    value = proxy if location == "root" else MappingProxyType({"nested": proxy})
    object.__setattr__(original.grant.rules[0], "conditions", value)
    calls.clear()
    with pytest.raises(HostExecutionDenied):
        _capture_filtered_grant(original)
    assert calls == []


@pytest.mark.parametrize("wrapped", [False, True])
def test_native_dict_foreign_keys_rejected_before_equality_or_string(wrapped):
    calls = []

    class Key:
        def __hash__(self):
            calls.append("hash")
            return hash("native")

        def __eq__(self, other):
            calls.append("eq")
            return False

        def __str__(self):
            calls.append("str")
            raise AssertionError

    backing = {Key(): 1, "native": 2}
    original = filtered()
    object.__setattr__(
        original.grant.rules[0],
        "conditions",
        MappingProxyType(backing) if wrapped else backing,
    )
    calls.clear()
    with pytest.raises(HostExecutionDenied):
        _capture_filtered_grant(original)
    assert calls == []


@pytest.mark.parametrize(
    "value",
    [1.0, float("nan"), {"set"}, frozenset({"set"}), 2**63, -(2**63) - 1, object()],
)
def test_unsupported_conditions_refuse_before_compilation(value):
    original = filtered()
    object.__setattr__(
        original.grant.rules[0], "conditions", MappingProxyType({"value": value})
    )
    with pytest.raises(HostExecutionDenied):
        _capture_filtered_grant(original)


@pytest.mark.parametrize(
    "owner,field",
    [
        (PolicyFilterResult, "filter"),
        (Grant, "grant"),
        (GrantRule, "rule"),
        (RequirementLedger, "ledger"),
        (RequirementEntry, "entry"),
    ],
)
def test_forged_missing_slots_refuse_without_local_exception_payload(owner, field):
    original = filtered()
    forged = object.__new__(owner)
    if field == "filter":
        original = forged
    elif field == "rule":
        object.__setattr__(original.grant, "rules", (forged,))
    elif field == "entry":
        object.__setattr__(original.ledger, "entries", (forged,))
    else:
        object.__setattr__(original, field, forged)
    with pytest.raises(HostExecutionDenied) as caught:
        _capture_filtered_grant(original)
    assert caught.value.args == ("host:lean_grant_shape",)
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None


@pytest.mark.parametrize(
    "field",
    [
        "grant",
        "rules",
        "domain",
        "requirement",
        "baseline",
        "conditions",
        "provenance",
        "ledger",
        "reason",
    ],
)
def test_candidate_protocols_not_used_for_native_admission(field):
    calls = []

    class Foreign:
        def __getattribute__(self, key):
            calls.append("attribute")
            raise AssertionError

        def __iter__(self):
            calls.append("iter")
            raise AssertionError

        def __bool__(self):
            calls.append("bool")
            raise AssertionError

        def __str__(self):
            calls.append("str")
            raise AssertionError

        def __eq__(self, other):
            calls.append("eq")
            raise AssertionError

    original = filtered()
    owner = (
        original
        if field in {"grant", "ledger", "reason"}
        else original.grant
        if field == "rules"
        else original.grant.rules[0]
    )
    object.__setattr__(owner, field, Foreign())
    with pytest.raises(HostExecutionDenied):
        _capture_filtered_grant(original)
    assert calls == []


def test_cycles_refuse_and_shared_native_values_are_detached():
    original = filtered()
    shared = {"value": [1, 2]}
    object.__setattr__(
        original.grant.rules[0], "conditions", {"a": shared, "b": shared}
    )
    captured = _capture_filtered_grant(original)
    assert captured.filtered.grant.rules[0].conditions["a"] == {"value": (1, 2)}
    shared["loop"] = shared
    with pytest.raises(HostExecutionDenied):
        _capture_filtered_grant(original)


def test_early_aggregate_budget_does_not_inspect_later_rule(monkeypatch):
    original = filtered()
    first = original.grant.rules[0]
    object.__setattr__(first, "conditions", {str(i): "x" * 4096 for i in range(256)})
    later = object.__new__(GrantRule)
    object.__setattr__(original.grant, "rules", (first, later))
    record = lean_grant._record

    def observe(value, owner, slots):
        assert value is not later
        return record(value, owner, slots)

    monkeypatch.setattr(lean_grant, "_record", observe)
    with pytest.raises(HostExecutionDenied, match="lean_protocol_shape"):
        _capture_filtered_grant(original)


def test_obligations_are_detached_with_exact_kind_domain_and_dependencies():
    captured, obligations = admitted({"maximum": 42})
    original = compile_obligations(captured.filtered.grant)
    detached = _capture_obligations(original)
    object.__setattr__(original[0], "selector", "changed")
    assert detached.projection == obligations.projection
    assert detached.obligations[0].selector == "mail-service"
    assert len(detached.obligations) == 10
    assert detached.obligations[-1].domain is AuthorityDomain.RESOURCE_LIMIT


@pytest.mark.parametrize(
    "field,value",
    [
        ("kind", "operate"),
        ("domain", "filesystem"),
        ("waivable", 1),
        ("dependencies", ()),
        ("selector", object()),
    ],
)
def test_obligation_shape_rejects_foreign_or_wrong_native_values(field, value):
    original = compile_obligations(_grant())
    object.__setattr__(original[0], field, value)
    with pytest.raises(HostExecutionDenied):
        _capture_obligations(original)


def test_exact_missing_obligation_slot_is_normalized():
    with pytest.raises(HostExecutionDenied) as caught:
        _capture_obligations((object.__new__(EnforcementObligation),))
    assert caught.value.__context__ is None


def test_real_compiled_grant_accepts_useful_semantics(checker):
    captured, obligations = admitted(
        {"a": [None, True, -(2**63), 2**63 - 1, "é"], "": {"z": 0}}
    )
    checker.require_grant(
        json.loads(captured.projection), json.loads(obligations.projection)
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "extra",
        "operation",
        "selector",
        "conditions",
        "waivable",
        "complement",
        "dependencies",
        "duplicate",
    ],
)
def test_real_compiled_grant_rejects_semantic_mutation(checker, mutation):
    captured, obligations = admitted()
    rows = json.loads(obligations.projection)
    if mutation == "missing":
        rows.pop()
    elif mutation == "extra":
        rows.append({**rows[0], "id": "invented"})
    elif mutation == "duplicate":
        rows.append(copy.deepcopy(rows[0]))
    elif mutation == "complement":
        rows[1]["operation"] = "allow_unlisted"
    elif mutation == "conditions":
        rows[0]["conditions"] = {"kind": "map", "value": []}
    elif mutation == "dependencies":
        rows[0]["dependencies"] = [rows[-1]["id"]]
    elif mutation == "waivable":
        rows[0]["waivable"] = True
    else:
        rows[0][mutation] = "changed"
    with pytest.raises(HostExecutionDenied):
        checker.require_grant(json.loads(captured.projection), rows)


@pytest.mark.parametrize(
    "value",
    ["-0", "+1", "01", "-01", "١", "9223372036854775808", "-9223372036854775809", " 1"],
)
def test_raw_protocol_refuses_noncanonical_or_out_of_range_int(binary, value):
    captured, obligations = admitted({"maximum": 1})
    grant = json.loads(captured.projection)
    rows = json.loads(obligations.projection)
    grant["rules"][0]["conditions"]["value"][0]["value"]["value"] = value
    rows[0]["conditions"]["value"][0]["value"]["value"] = value
    result = raw_check(
        binary,
        json.dumps(
            {
                "protocol": "worker-route-grant-v3",
                "kind": "grant",
                "grant": grant,
                "obligations": rows,
            }
        ).encode(),
    )
    assert result.returncode != 0
    assert result.stdout == b""


@pytest.mark.parametrize(
    "owner,field",
    [
        (PolicyFilterResult, "filter"),
        (Grant, "grant"),
        (GrantRule, "rule"),
        (RequirementLedger, "ledger"),
        (RequirementEntry, "entry"),
    ],
)
def test_record_subclasses_are_refused_without_attribute_hooks(owner, field):
    calls = []

    def hostile(self, name):
        calls.append(name)
        raise AssertionError

    subclass = type("Foreign", (owner,), {"__getattribute__": hostile})
    original = filtered()
    foreign = object.__new__(subclass)
    if field == "filter":
        original = foreign
    elif field == "rule":
        object.__setattr__(original.grant, "rules", (foreign,))
    elif field == "entry":
        object.__setattr__(original.ledger, "entries", (foreign,))
    else:
        object.__setattr__(original, field, foreign)
    with pytest.raises(HostExecutionDenied):
        _capture_filtered_grant(original)
    assert calls == []


@pytest.mark.parametrize(
    "value",
    [
        type("String", (str,), {})("text"),
        type("Integer", (int,), {})(1),
        type("Tuple", (tuple,), {})(()),
        type("List", (list,), {})([]),
        type("Dict", (dict,), {})(),
    ],
)
def test_scalar_and_container_subclasses_refuse(value):
    original = filtered()
    object.__setattr__(original.grant.rules[0], "conditions", {"value": value})
    with pytest.raises(HostExecutionDenied):
        _capture_filtered_grant(original)


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_grant",
        "extra_grant",
        "missing_obligations",
        "extra_envelope",
        "wrong_kind",
        "wrong_domain",
        "wrong_requirement",
        "unsorted_map",
        "duplicate_map_key",
        "unknown_tag",
        "float_tag",
        "bare_int",
        "false_int",
    ],
)
def test_raw_preflight_refuses_unsupported_shapes(binary, mutation):
    captured, obligations = admitted({"a": 1, "b": 2})
    grant = json.loads(captured.projection)
    rows = json.loads(obligations.projection)
    payload = {
        "protocol": "worker-route-grant-v3",
        "kind": "grant",
        "grant": grant,
        "obligations": rows,
    }
    if mutation == "missing_grant":
        del payload["grant"]
    elif mutation == "extra_grant":
        grant["trusted"] = True
    elif mutation == "missing_obligations":
        del payload["obligations"]
    elif mutation == "extra_envelope":
        payload["trusted"] = True
    elif mutation == "wrong_kind":
        payload["kind"] = "grant_ready"
    elif mutation == "wrong_domain":
        grant["rules"][0]["domain"] = "unknown"
    elif mutation == "wrong_requirement":
        grant["rules"][0]["requirement"] = "optional"
    elif mutation == "unsorted_map":
        grant["rules"][0]["conditions"]["value"].reverse()
    elif mutation == "duplicate_map_key":
        grant["rules"][0]["conditions"]["value"][1]["key"] = "a"
    else:
        node = grant["rules"][0]["conditions"]["value"][0]["value"]
        if mutation == "unknown_tag":
            node["kind"] = "opaque"
        elif mutation == "float_tag":
            node["kind"] = "float"
        elif mutation == "bare_int":
            node["value"] = 1
        else:
            node["value"] = False
    result = raw_check(binary, json.dumps(payload).encode())
    assert result.returncode != 0
    assert result.stdout == b""


def test_byte_budget_aborts_before_later_hostile_nested_value(monkeypatch):
    original = filtered()
    later = object()
    object.__setattr__(
        original.grant.rules[0],
        "conditions",
        {"first": ("x" * 4096,) * 256, "later": later},
    )
    native = lean_grant._condition

    def observe(value, budget, active, depth=0):
        assert value is not later
        return native(value, budget, active, depth)

    monkeypatch.setattr(lean_grant, "_condition", observe)
    with pytest.raises(HostExecutionDenied, match="lean_protocol_shape"):
        _capture_filtered_grant(original)
