"""Source-derived return provenance is separate from publication permission."""

import json
from dataclasses import replace
from textwrap import dedent

import pytest

from langgraph.prebuilt.security.mediation import Authorizer, Operation
from langgraph.prebuilt.security.verification import (
    Requirement,
    ReturnProtocol,
    VerificationSpec,
    load_spec,
    verify,
)

GOOD = """
authorization = review(principal, request)
if authorization.decision.verdict is Verdict.ESCALATE:
    return authorization
if authorization.decision.verdict is not Verdict.ALLOW:
    raise PermissionError('denied')
return dispatch(principal, authorization.request)
"""


def contract(body=GOOD, *, asynchronous=False, helpers=""):
    prefix = "async " if asynchronous else ""
    source = (
        "from policy import review, Verdict\nfrom host import dispatch\n"
        + dedent(helpers)
        + f"class Router:\n    {prefix}def route(self, principal, request):\n"
        + "\n".join("        " + line for line in dedent(body).strip().splitlines())
        + "\n"
    )
    return VerificationSpec(
        sources={"sample": source},
        surfaces=("sample.Router",),
        authorizers=(
            Authorizer(
                "policy.review", ("arg:0", "result:request"), decision="decision"
            ),
        ),
        operations=(Operation("host.dispatch", ("arg:0", "arg:1")),),
        return_protocols={
            "sample.Router.route": ReturnProtocol(
                ("host.dispatch",), ("policy.review",)
            ),
        },
        async_terminals=("policy.review", "host.dispatch") if asynchronous else (),
    )


@pytest.mark.parametrize("asynchronous", [False, True])
def test_aliases_and_source_helpers_preserve_exact_result_provenance(asynchronous):
    body = GOOD.replace(
        "return authorization", "return identity(authorization)"
    ).replace(
        "return dispatch(principal, authorization.request)",
        "value = dispatch(principal, authorization.request)\nalias = value\nreturn identity(alias)",
    )
    if asynchronous:
        body = body.replace("= review(", "= await review(").replace(
            "= dispatch(", "= await dispatch("
        )
    report = verify(
        contract(
            body,
            asynchronous=asynchronous,
            helpers="def identity(value):\n    return value\n",
        )
    )
    assert report["complete"], report
    assert {item["kind"] for item in report["entries"][0]["return_outcomes"]} == {
        "authorized_operation",
        "escalated_authorization",
    }
    assert "sample.identity" in report["entries"][0]["visited_functions"]


@pytest.mark.parametrize(
    "tail",
    [
        "value.request = request\nreturn value",
        "alias = value\nalias.request = request\nreturn value",
        "return (value, request)",
        "return value.request",
        "return authorization",
        "return None",
        "if request:\n    return request\nreturn value",
    ],
)
def test_substituted_or_mutated_dispatch_result_has_no_provenance(tail):
    body = GOOD.replace(
        "return dispatch(principal, authorization.request)",
        "value = dispatch(principal, authorization.request)\n" + tail,
    )
    report = verify(contract(body))
    assert not report["complete"]
    assert any(not item["verified"] for item in report["entries"][0]["return_outcomes"])


@pytest.mark.parametrize(
    "tail",
    [
        "authorization.request = request\n    return authorization",
        "authorization.decision.reason = 'changed'\n    return authorization",
        "authorization.decision.verdict = Verdict.ALLOW\n    return authorization",
        "other = review(principal, request)\n    return authorization",
    ],
)
def test_changed_or_superseded_escalation_is_not_a_valid_protocol_result(tail):
    report = verify(contract(GOOD.replace("return authorization", tail)))
    assert not report["complete"]


def test_protocol_evidence_does_not_satisfy_a_publication_obligation():
    spec = replace(
        contract(),
        return_requirements=(Requirement("publish", ("arg:1", "result:")),),
    )
    report = verify(spec)
    assert not report["complete"]
    assert all(item["verified"] for item in report["entries"][0]["return_outcomes"])
    assert all(not item["authorized"] for item in report["entries"][0]["publications"])


def test_missing_and_invented_entry_contracts_fail_closed():
    spec = contract()
    source = (
        spec.sources["sample"]
        + "\n    def extra(self, principal, request):\n        return self.route(principal, request)\n"
    )
    report = verify(replace(spec, sources={"sample": source}))
    assert not report["complete"]
    assert any(
        "lacks a return protocol" in issue["reason"]
        for entry in report["entries"]
        for issue in entry["issues"]
    )
    report = verify(
        replace(
            spec,
            return_protocols={
                **spec.return_protocols,
                "sample.Router.missing": ReturnProtocol(("host.dispatch",)),
            },
        )
    )
    assert not report["complete"]
    assert any("undiscovered API" in issue["reason"] for issue in report["issues"])


@pytest.mark.parametrize(
    "mutation", ["request['value'] = None", "alias['value'] = None"]
)
def test_opaque_result_cannot_be_assumed_detached_from_mutable_inputs(mutation):
    body = "request = {'value': request}\nalias = request\n" + GOOD.replace(
        "return dispatch(principal, authorization.request)",
        "value = dispatch(principal, authorization.request)\n"
        + mutation
        + "\nreturn value",
    )
    report = verify(contract(body))
    assert not report["complete"]
    assert any(not item["verified"] for item in report["entries"][0]["return_outcomes"])


def test_literal_refusal_is_valid_but_produces_no_success_evidence():
    report = verify(contract("raise PermissionError('unsupported')"))
    assert report["complete"], report
    assert not report["entries"][0]["return_outcomes"]
    assert report["summary"]["dispatch_obligations"] == 0


@pytest.mark.parametrize(
    "protocol",
    [
        ReturnProtocol(("host.unknown",)),
        ReturnProtocol(("policy.review",)),
        ReturnProtocol((), ("host.dispatch",)),
        ReturnProtocol(()),
        ReturnProtocol(("host.dispatch", "host.dispatch")),
    ],
)
def test_unknown_mistyped_or_duplicate_contract_targets_are_rejected(protocol):
    with pytest.raises(ValueError, match="return protocols"):
        replace(contract(), return_protocols={"sample.Router.route": protocol})


def test_json_spec_retains_the_return_protocol(tmp_path):
    spec = contract()
    (tmp_path / "router.py").write_text(spec.sources["sample"])
    path = tmp_path / "spec.json"
    path.write_text(
        json.dumps(
            {
                "sources": {"sample": "router.py"},
                "surfaces": list(spec.surfaces),
                "authorizers": [vars(item) for item in spec.authorizers],
                "operations": [vars(item) for item in spec.operations],
                "return_protocols": {
                    entry: vars(protocol)
                    for entry, protocol in spec.return_protocols.items()
                },
            }
        )
    )
    loaded = load_spec(path)
    assert loaded.return_protocols == spec.return_protocols
    assert verify(loaded)["complete"]
