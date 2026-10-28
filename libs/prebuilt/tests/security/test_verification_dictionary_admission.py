"""Native dictionary admission is derived from an effect-free normalization loop."""

import ast
from dataclasses import replace
from pathlib import Path

import pytest

from langgraph.prebuilt.security import binding
from langgraph.prebuilt.security.mediation import Authorizer, Operation
from langgraph.prebuilt.security.verification import (
    ReturnProtocol,
    VerificationSpec,
    verify,
)


def normalizer():
    tree = ast.parse(Path(binding.__file__).read_text())
    return ast.unparse(
        next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "_plain_dictionary"
        )
    )


def contract(helper=None, body=None):
    helper = normalizer() if helper is None else helper
    body = (
        body
        or """config = _plain_dictionary(config)
resource = config.get('resource')
decision = permission(principal, resource)
if decision.verdict is not Verdict.ALLOW:
    raise PermissionError('denied')
return dispatch(principal, resource)"""
    )
    source = (
        "from __future__ import annotations\nfrom policy import permission, Verdict\nfrom host import dispatch\n"
        + helper
        + "\nclass Tool:\n    def invoke(self, config, principal, request):\n"
        + "\n".join("        " + line for line in body.splitlines())
        + "\n"
    )
    return VerificationSpec(
        sources={"sample": source},
        surfaces=("sample.Tool",),
        authorizers=(Authorizer("policy.permission", ("arg:0", "arg:1")),),
        operations=(Operation("host.dispatch", ("arg:0", "arg:1")),),
        return_protocols={"sample.Tool.invoke": ReturnProtocol(("host.dispatch",))},
    )


def test_actual_binding_normalizer_derives_key_and_value_correspondence():
    report = verify(contract())
    assert report["complete"], report
    entry = report["entries"][0]
    assert "sample._plain_dictionary" in entry["visited_functions"]
    assert entry["mapping_normalizations"]
    assert all(
        item["step_value"] == "unchanged" for item in entry["mapping_normalizations"]
    )
    assert entry["dispatches"] and all(
        item["authorized"] for item in entry["dispatches"]
    )


@pytest.mark.parametrize(
    "change",
    [
        lambda text: text.replace(
            "type(value) is not dict", "not isinstance(value, dict)"
        ),
        lambda text: text.replace("tuple(value.items())", "value.items()"),
        lambda text: text.replace(
            "tuple(value.items())", "tuple(value.copy().items())"
        ),
        lambda text: text.replace("type(key) is not str", "not isinstance(key, str)"),
        lambda text: text.replace("type(key) is not str", "type(item) is not str"),
        lambda text: text.replace("copied[key] = item", "copied[key] = None"),
        lambda text: text.replace("copied[key] = item", "copied[item] = key"),
        lambda text: text.replace(
            "copied[key] = item", "copied[key] = item\n        dispatch(key, item)"
        ),
    ],
)
def test_unproved_loop_step_or_protocol_cannot_gain_dictionary_shape(change):
    original = normalizer()
    modified = change(original)
    assert modified != original
    report = verify(contract(modified))
    assert not report["complete"]


def test_exact_dict_alone_does_not_authorize_key_lookup_or_copy():
    for operation in ("config.get('resource')", "config.copy()"):
        report = verify(
            contract(
                body=f"""if type(config) is not dict:
    raise TypeError('unsupported')
value = {operation}
return dispatch(principal, value)"""
            )
        )
        assert not report["complete"]
        assert any(
            "keys require validation" in issue["reason"]
            for issue in report["entries"][0]["issues"]
        )


def test_normalizer_name_is_not_an_opaque_trust_contract():
    spec = contract()
    source = spec.sources["sample"].replace("_plain_dictionary", "arbitrary_name")
    assert verify(replace(spec, sources={"sample": source}))["complete"]


def test_shadowed_native_type_query_cannot_use_the_induction_rule():
    helper = (
        "from builtins import type as native_type\n"
        "def fake_type(value):\n    return str\n"
        + normalizer()
        .replace("type(value)", "native_type(value)")
        .replace("copied = {}", "type = fake_type\n    copied = {}")
    )
    assert not verify(contract(helper))["complete"]


def test_normalization_grants_no_dispatch_authority():
    report = verify(
        contract(
            body="config = _plain_dictionary(config)\nreturn dispatch(principal, config.get('resource'))"
        )
    )
    assert not report["complete"]
    assert any(not site["authorized"] for site in report["entries"][0]["dispatches"])


def test_known_literal_dictionary_keeps_ordinary_finite_iteration_semantics():
    spec = contract(
        body="config = _plain_dictionary({'resource': 'known'})\ndecision = permission(principal, config.get('resource'))\nif decision.verdict is not Verdict.ALLOW:\n    raise PermissionError('denied')\nreturn dispatch(principal, config.get('resource'))"
    )
    assert verify(spec)["complete"]
