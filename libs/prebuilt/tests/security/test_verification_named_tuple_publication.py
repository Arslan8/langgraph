"""Record publication follows value grants and cannot conceal capabilities."""

from textwrap import dedent, indent

import pytest

from langgraph.prebuilt.security.mediation import Authorizer, Operation
from langgraph.prebuilt.security.verification import (
    Requirement,
    VerificationSpec,
    verify,
)
from tests.security.test_verification_named_tuples import RECORD, check


@pytest.mark.parametrize("returned", ["record", "record._replace(resource=operation)"])
def test_native_data_record_publication_requires_the_exact_authorized_value(returned):
    proof = verify(
        VerificationSpec(
            sources={
                "fixture": "from __future__ import annotations\n"
                "from typing import NamedTuple\n"
                "from policy import permission, Verdict\n"
                + RECORD
                + "\nclass Tool:\n"
                + "    def invoke(self, principal, resource, operation):\n"
                + indent(
                    dedent(f"""
                    record = Request(principal, resource)
                    decision = permission(principal, record)
                    if decision.verdict is not Verdict.ALLOW:
                        raise PermissionError('denied')
                    return {returned}
                    """).strip(),
                    "        ",
                )
            },
            surfaces=("fixture.Tool",),
            authorizers=(
                Authorizer(
                    "policy.permission", ("arg:0", "arg:1"), permission="publish"
                ),
            ),
            operations=(),
            return_requirements=(Requirement("publish", ("arg:1", "result:")),),
        )
    )
    expected = "verified" if returned == "record" else "violated"
    assert proof["entries"][0]["status"] == expected, proof
    assert proof["complete"] is (expected == "verified"), proof
    assert len(proof["entries"][0]["publications"]) == 1


@pytest.mark.parametrize(
    "value", ["dispatch", "self", "record._replace", "{'callback': dispatch}"]
)
def test_native_record_cannot_hide_an_executable_capability_in_its_fields(value):
    proof = check(f"""
        record = Request(principal, resource)
        return Request(principal, {value})
    """)
    assert not proof["complete"], proof
    assert any(
        "capability escapes" in issue["reason"]
        for issue in proof["entries"][0]["issues"]
    )


def test_record_with_a_declared_effectful_method_cannot_escape_as_inert_data():
    proof = verify(
        VerificationSpec(
            sources={
                "fixture": "from __future__ import annotations\n"
                "from typing import NamedTuple\n"
                + RECORD
                + "\nclass Tool:\n    def invoke(self, principal, resource):\n"
                + "        return Request(principal, resource)\n"
            },
            surfaces=("fixture.Tool",),
            authorizers=(Authorizer("policy.permission", ("arg:0",)),),
            operations=(Operation("fixture.Request._replace", ("arg:0",)),),
        )
    )
    assert not proof["complete"], proof
    assert any(
        "capability escapes" in issue["reason"]
        for issue in proof["entries"][0]["issues"]
    )
