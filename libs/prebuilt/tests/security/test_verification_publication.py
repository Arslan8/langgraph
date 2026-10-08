"""Inert source fixtures for publication contracts; candidate code is never run."""

import json
from dataclasses import replace
from textwrap import dedent

import pytest

from langgraph.prebuilt.security.mediation import Authorizer
from langgraph.prebuilt.security.verification import (
    ReadSource,
    Requirement,
    VerificationSpec,
    load_spec,
    verify,
)


def contract(body, helpers="", *, asynchronous=False):
    prefix = "async " if asynchronous else ""
    source = (
        "from policy import review, Verdict\nfrom backing import read\n"
        + dedent(helpers)
        + f"class Reader:\n    {prefix}def get(self, principal, resource, alternate):\n"
        + "\n".join("        " + line for line in dedent(body).strip().splitlines())
        + "\n"
    )
    return VerificationSpec(
        sources={"sample": source},
        surfaces=("sample.Reader",),
        authorizers=(
            Authorizer(
                "policy.review",
                ("arg:0", "arg:1", "result:value"),
                permission="read_publication",
                decision="decision",
            ),
        ),
        operations=(),
        read_sources=(ReadSource("backing.read"),),
        return_requirements=(
            Requirement("read_publication", ("arg:1", "arg:2", "result:")),
        ),
        async_terminals=("backing.read", "policy.review") if asynchronous else (),
    )


GOOD = """
value = read(resource)
decision = review(principal, resource, value)
if decision.decision.verdict is not Verdict.ALLOW:
    raise PermissionError('denied')
return decision.value
"""


@pytest.mark.parametrize("asynchronous", [False, True])
def test_authorized_exact_return_has_a_source_proof(asynchronous):
    body = GOOD
    if asynchronous:
        body = body.replace("= read(", "= await read(").replace(
            "= review(", "= await review("
        )
    report = verify(contract(body, asynchronous=asynchronous))
    assert report["complete"], report
    assert report["summary"]["publication_obligations"] == 1


@pytest.mark.parametrize(
    "body",
    [
        GOOD.replace("return decision.value", "return value"),
        GOOD.replace("return decision.value", "alias = value\nreturn alias"),
        GOOD.replace("return decision.value", "return (decision.value, value)"),
        GOOD.replace("review(principal, resource", "review(alternate, resource"),
        GOOD.replace("review(principal, resource", "review(principal, alternate"),
        GOOD.replace("return decision.value", "return read(resource)"),
        GOOD.replace(
            "return decision.value",
            "if alternate:\n    return value\nreturn decision.value",
        ),
        GOOD.replace("return decision.value", "raise PermissionError(value)"),
        "return read(resource)",
    ],
)
def test_unmediated_or_mismatched_publication_never_passes(body):
    report = verify(contract(body))
    assert not report["complete"], report
    assert report["summary"]["violated"] + report["summary"]["unresolved"] > 0


def test_helpers_and_aliases_preserve_the_value_obligation():
    helpers = """
    def identity(value):
        alias = value
        return alias
    """
    assert verify(
        contract(
            GOOD.replace("return decision.value", "return identity(decision.value)"),
            helpers,
        )
    )["complete"]
    assert not verify(
        contract(
            GOOD.replace("return decision.value", "return identity(value)"), helpers
        )
    )["complete"]


def test_new_inherited_api_is_automatically_checked():
    spec = contract(GOOD)
    source = spec.sources["sample"] + dedent("""
    class Child(Reader):
        def another(self, principal, resource, alternate):
            return read(resource)
    """)
    report = verify(replace(spec, sources={"sample": source}))
    assert not report["complete"]
    entries = {item["entry"]: item for item in report["entries"]}
    assert entries["sample.Child.get"]["status"] == "verified"
    assert entries["sample.Child.another"]["status"] == "violated"


@pytest.mark.parametrize("body", ["return unknown(resource)", "yield read(resource)"])
def test_unknown_behavior_cannot_satisfy_publication_contract(body):
    report = verify(contract(body))
    assert not report["complete"]
    assert report["summary"]["unresolved"]


def test_analysis_budget_exhaustion_is_unresolved():
    report = verify(replace(contract(GOOD), max_steps=1))
    assert not report["complete"]
    assert report["summary"]["unresolved"]


def test_literal_refusal_can_be_proved_without_publishing_data():
    report = verify(contract("raise PermissionError('not supported')"))
    assert report["complete"], report
    assert not report["summary"]["publication_obligations"]


def test_exit_contract_must_bind_the_whole_return_value():
    with pytest.raises(ValueError, match="exact returned result"):
        replace(contract(GOOD), return_requirements=(Requirement("read", ("arg:1",)),))


def test_read_terminal_is_not_an_authorization_primitive():
    spec = contract("return read(resource)")
    with pytest.raises(ValueError, match="distinct"):
        replace(spec, read_sources=(*spec.read_sources, ReadSource("policy.review")))


def test_refusing_primitive_is_explicit_and_never_inferred_from_its_name():
    body = "return review(principal, resource, read(resource))"
    spec = replace(
        contract(body),
        authorizers=(
            Authorizer(
                "policy.review",
                ("arg:0", "arg:1", "result:"),
                permission="read_publication",
            ),
        ),
    )
    assert not verify(spec)["complete"]
    assert verify(replace(spec, refusing_authorizers=("policy.review",)))["complete"]
    with pytest.raises(ValueError, match="authorizer contracts"):
        replace(spec, refusing_authorizers=("backing.read",))


def test_terminal_await_protocol_is_required():
    spec = contract(GOOD)
    report = verify(replace(spec, async_terminals=("backing.read",)))
    assert not report["complete"]
    assert report["summary"]["unresolved"]


def test_absence_marker_exemption_must_be_explicit_and_is_narrow():
    spec = contract("return None")
    assert not verify(spec)["complete"]
    assert verify(replace(spec, allow_none_return=True))["complete"]
    assert not verify(
        replace(contract("return read(resource)"), allow_none_return=True)
    )["complete"]
    with pytest.raises(ValueError, match="boolean"):
        replace(spec, allow_none_return="false")


def test_publication_contract_loads_without_losing_its_decision_selector(tmp_path):
    spec = contract(GOOD)
    (tmp_path / "reader.py").write_text(spec.sources["sample"])
    path = tmp_path / "contract.json"
    path.write_text(
        json.dumps(
            {
                "sources": {"sample": "reader.py"},
                "surfaces": list(spec.surfaces),
                "authorizers": [vars(item) for item in spec.authorizers],
                "operations": [],
                "read_sources": [vars(item) for item in spec.read_sources],
                "return_requirements": [
                    vars(item) for item in spec.return_requirements
                ],
                "refusing_authorizers": [],
                "allow_none_return": False,
            }
        )
    )
    loaded = load_spec(path)
    assert loaded.authorizers[0].decision == "decision"
    assert verify(loaded)["complete"]
