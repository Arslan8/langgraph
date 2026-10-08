"""Source-only checks for native NamedTuple data flowing through authorization."""

import inspect
from itertools import permutations
from textwrap import dedent, indent
from typing import NamedTuple

import pytest
from langgraph.checkpoint.base import CheckpointTuple
from langgraph.store.base import (
    GetOp,
    ListNamespacesOp,
    MatchCondition,
    PutOp,
    SearchOp,
)

from langgraph.prebuilt.security.mediation import Authorizer, Operation
from langgraph.prebuilt.security.verification import (
    VerificationSpec,
    verify,
)

RECORD = """
class Request(NamedTuple):
    principal: object
    resource: object
    operation: object = None
    context: tuple = ('default',)
"""


def check(body, declaration=RECORD, *, asynchronous=False, surface="fixture.Tool"):
    source = (
        "from __future__ import annotations\n"
        "from typing import NamedTuple\n"
        "from policy import permission, Verdict\n"
        "from legacy import dispatch\n"
        + dedent(declaration)
        + "\nclass Tool:\n"
        + ("    async def" if asynchronous else "    def")
        + " invoke(self, principal, resource, operation, context):\n"
        + indent(dedent(body).strip(), "        ")
        + "\n"
    )
    return verify(
        VerificationSpec(
            sources={"fixture": source},
            surfaces=(surface,),
            authorizers=(Authorizer("policy.permission", ("arg:0", "arg:1")),),
            operations=(Operation("legacy.dispatch", ("arg:0", "arg:1")),),
            async_terminals=("policy.permission", "legacy.dispatch")
            if asynchronous
            else (),
        )
    )


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("ordering", list(permutations(range(4))))
@pytest.mark.parametrize("projection", ["attribute", "index", "mapping", "unpack"])
@pytest.mark.parametrize("selected_field", range(4))
def test_field_projection_matrix_preserves_actual_argument_bindings(
    asynchronous, ordering, projection, selected_field
):
    fields = ("principal", "resource", "operation", "context")
    arguments = ", ".join(fields[index] for index in ordering)
    if projection == "attribute":
        expression = f"record.{fields[selected_field]}"
        setup = ""
    elif projection == "index":
        expression = f"record[{selected_field}]"
        setup = ""
    elif projection == "mapping":
        expression = f"record._asdict()['{fields[selected_field]}']"
        setup = ""
    else:
        expression = "selected"
        targets = ["selected" if i == selected_field else f"other{i}" for i in range(4)]
        setup = ", ".join(targets) + " = record"
    await_ = "await " if asynchronous else ""
    proof = check(
        f"""
        record = Request({arguments})
        {setup}
        d = {await_}permission(principal, {fields[selected_field]})
        if d.verdict is Verdict.ALLOW:
            return {await_}dispatch(principal, {expression})
        """,
        asynchronous=asynchronous,
    )
    expected = "verified" if ordering[selected_field] == selected_field else "violated"
    assert not proof["issues"], proof
    assert proof["entries"][0]["status"] == expected, proof
    assert proof["complete"] is (expected == "verified"), proof


@pytest.mark.parametrize(
    "construction",
    [
        "Request(principal, resource)",
        "Request(principal=principal, resource=resource)",
        "Request(resource=resource, principal=principal)",
        "Request(principal, resource=resource)",
        "Request(*(principal, resource))",
        "Request(**{'principal': principal, 'resource': resource})",
    ],
)
def test_constructor_forms_and_shared_defaults(construction):
    proof = check(f"""
        record = {construction}
        another = Request(principal, resource)
        if record.context is another.context:
            d = permission(principal, record.resource)
            if d.verdict is Verdict.ALLOW:
                return dispatch(principal, resource)
    """)
    assert proof["complete"], proof
    assert len(proof["entries"][0]["dispatches"]) == 1


@pytest.mark.parametrize(
    "record_type",
    [CheckpointTuple, GetOp, PutOp, SearchOp, MatchCondition, ListNamespacesOp],
)
def test_repository_record_declarations_preserve_fields(record_type):
    first_field = record_type._fields[0]
    construction = ", ".join(f"{name}=resource" for name in record_type._fields)
    proof = check(
        f"""
        record = {record_type.__name__}({construction})
        d = permission(principal, resource)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, record.{first_field})
        """,
        inspect.getsource(record_type),
    )
    assert proof["complete"], proof
    assert len(proof["entries"][0]["dispatches"]) == 1


@pytest.mark.parametrize("replacement", ["resource", "operation"])
@pytest.mark.parametrize(
    "projection", ["changed.resource", "changed[1]", "changed._asdict()['resource']"]
)
def test_replace_preserves_original_and_binds_replaced_values(replacement, projection):
    proof = check(f"""
        record = Request(principal, resource)
        changed = record._replace(resource={replacement})
        d = permission(principal, resource)
        if d.verdict is Verdict.ALLOW:
            dispatch(principal, record.resource)
            again = permission(principal, resource)
            if again.verdict is Verdict.ALLOW:
                return dispatch(principal, {projection})
    """)
    assert proof["entries"][0]["status"] == (
        "verified" if replacement == "resource" else "violated"
    ), proof
    assert len(proof["entries"][0]["dispatches"]) == 2


@pytest.mark.parametrize(
    "projection", ["record", "record._replace()", "record._asdict()", "tuple(record)"]
)
def test_nested_mutable_values_remain_dependencies(projection):
    proof = check(f"""
        nested = {{'value': resource}}
        record = Request(principal, nested)
        bound = {projection}
        d = permission(principal, bound)
        if d.verdict is not Verdict.ALLOW:
            raise PermissionError('denied')
        nested['value'] = operation
        return dispatch(principal, bound)
    """)
    assert proof["entries"][0]["status"] == "violated", proof


def test_mapping_copy_is_detached_but_record_replacement_has_new_identity():
    proof = check("""
        record = Request(principal, resource)
        copy = record._asdict()
        d = permission(principal, record)
        if d.verdict is not Verdict.ALLOW:
            raise PermissionError('denied')
        copy['resource'] = operation
        dispatch(principal, record)
        again = permission(principal, record)
        if again.verdict is Verdict.ALLOW:
            return dispatch(principal, record._replace())
    """)
    sites = proof["entries"][0]["dispatches"]
    assert [site["authorized"] for site in sites] == [True, False], proof


@pytest.mark.parametrize(
    "statement",
    [
        "record.resource = operation",
        "del record.resource",
        "record[1] = operation",
        "del record[1]",
        "object.__setattr__(record, 'resource', operation)",
        "object.__setattr__(record, 'extra', operation)",
        "Request(principal)",
        "Request(principal, resource, operation, context, None)",
        "Request(principal, resource, resource=operation)",
        "Request(principal, resource, extra=operation)",
        "record._replace(extra=operation)",
        "record._replace(operation)",
        "record._asdict(extra=operation)",
    ],
)
def test_known_invalid_native_operations_stop_normal_continuation(statement):
    proof = check(f"""
        record = Request(principal, resource)
        d = permission(principal, record)
        if d.verdict is not Verdict.ALLOW:
            raise PermissionError('denied')
        dispatch(principal, record)
        {statement}
        dispatch(principal, operation)
    """)
    assert proof["complete"], proof
    assert len(proof["entries"][0]["dispatches"]) == 1


@pytest.mark.parametrize(
    "projection", ["tuple(record)[1]", "record[:][1]", "record[-3]", "list(record)[1]"]
)
def test_sequence_conversions_preserve_field_value(projection):
    proof = check(f"""
        record = Request(principal, resource)
        d = permission(principal, resource)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, {projection})
    """)
    assert proof["complete"], proof


def test_nominal_type_is_retained_but_tuple_conversion_is_plain_tuple():
    proof = check("""
        record = Request(principal, resource)
        copy = tuple(record)
        if isinstance(record, Request) and isinstance(record, tuple):
            if not isinstance(copy, Request):
                return dispatch(principal, resource)
    """)
    assert proof["entries"][0]["status"] == "violated", proof


@pytest.mark.parametrize(
    "declaration",
    [
        RECORD + "\nclass Child(Request):\n    pass\n",
        RECORD.replace(
            "class Request(NamedTuple):", "@dispatch\nclass Request(NamedTuple):"
        ),
        RECORD.replace(
            "    principal: object", "    principal: object = dispatch(None, None)"
        ),
        RECORD.replace("    context: tuple = ('default',)", "    context: object = []"),
        RECORD.replace(
            "    context: tuple = ('default',)", "    _private: object = None"
        ),
        RECORD.replace("    context: tuple = ('default',)", "    context: object"),
        RECORD
        + "\n    def __getattribute__(self, name):\n        return dispatch(None, None)\n",
        RECORD + "\n    def helper(self):\n        return dispatch(None, None)\n",
        RECORD + "\n    resource: object\n",
        "NamedTuple = dispatch\n" + RECORD,
        RECORD + "\nNamedTuple = dispatch\n",
    ],
)
def test_unsupported_declaration_effects_and_layouts_remain_unresolved(declaration):
    proof = check("return None", declaration)
    assert not proof["complete"], proof
    assert proof["issues"], proof


@pytest.mark.parametrize(
    "attribute", ["_make", "_fields", "__new__", "__init__", "missing"]
)
def test_unmodeled_generated_members_cannot_be_treated_as_missing(attribute):
    proof = check(f"""
        record = Request(principal, resource)
        candidate = record.{attribute}
        return None
    """)
    assert not proof["complete"], proof
    assert proof["entries"][0]["status"] == "unresolved", proof


def test_declaring_generated_record_as_an_api_does_not_hide_generated_methods():
    proof = check("return None", surface="fixture.Request")
    assert not proof["complete"], proof
    assert any("generated-method" in issue["reason"] for issue in proof["issues"])


def test_refused_attribute_write_still_analyzes_handler_effects():
    proof = check("""
        record = Request(principal, resource)
        try:
            record.resource = operation
        except:
            dispatch(principal, operation)
    """)
    assert proof["entries"][0]["status"] == "violated", proof


def test_immutable_record_cannot_forge_an_authorization_decision():
    proof = check(
        """
        decision = ClaimedDecision(Verdict.ALLOW)
        if decision.verdict is Verdict.ALLOW:
            return dispatch(principal, resource)
        """,
        "class ClaimedDecision(NamedTuple):\n    verdict: object\n",
    )
    assert proof["entries"][0]["status"] == "violated", proof


@pytest.mark.parametrize(
    "import_statement, base",
    [
        ("import typing", "typing.NamedTuple"),
        ("from typing import NamedTuple as NativeTuple", "NativeTuple"),
        ("import typing_extensions as te", "te.NamedTuple"),
        ("from typing_extensions import NamedTuple as NativeTuple", "NativeTuple"),
    ],
)
def test_native_base_import_aliases_are_resolved(import_statement, base):
    proof = check(
        """
        record = Request(principal, resource)
        d = permission(principal, resource)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, record.resource)
        """,
        import_statement + "\n" + RECORD.replace("(NamedTuple)", f"({base})"),
    )
    assert proof["complete"], proof


def test_pending_grant_is_revoked_when_nested_record_data_changes():
    proof = check("""
        nested = {'value': resource}
        record = Request(principal, nested)
        d = permission(principal, record)
        nested['value'] = operation
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, record)
    """)
    assert proof["entries"][0]["status"] == "violated", proof


def test_generated_method_alias_keeps_the_original_receiver():
    proof = check("""
        record = Request(principal, resource)
        replace = record._replace
        record = Request(principal, operation)
        changed = replace()
        d = permission(principal, resource)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, changed.resource)
    """)
    assert proof["complete"], proof


def test_native_record_contract_with_benign_values():
    class NativeRecord(NamedTuple):
        principal: object
        resource: object
        context: tuple = ("default",)

    principal = object()
    nested = {"value": object()}
    record = NativeRecord(principal, nested)
    replaced = record._replace(principal=None)
    copied = record._asdict()
    sequence = tuple(record)
    assert replaced is not record
    assert replaced.resource is record.resource is nested
    assert copied["resource"] is sequence[1] is nested
    assert record.context is NativeRecord(None, None).context
    assert type(sequence) is tuple
    assert type(record[:]) is tuple
    copied["resource"] = None
    assert record.resource is nested
    marker = object()
    nested["value"] = marker
    assert replaced.resource["value"] is marker


@pytest.mark.parametrize("method", ["_replace", "_asdict"])
@pytest.mark.parametrize("guarded", [False, True])
def test_declared_effect_contract_takes_precedence_over_native_data_model(
    method, guarded
):
    body = "record = Request(principal, resource)\n"
    if guarded:
        body += (
            "decision = permission(record)\n"
            "if decision.verdict is not Verdict.ALLOW:\n"
            "    raise PermissionError('denied')\n"
        )
    body += f"return record.{method}()\n"
    proof = verify(
        VerificationSpec(
            sources={
                "fixture": "from __future__ import annotations\n"
                "from typing import NamedTuple\n"
                "from policy import permission, Verdict\n"
                + RECORD
                + "\nclass Tool:\n    def invoke(self, principal, resource):\n"
                + indent(body, "        ")
            },
            surfaces=("fixture.Tool",),
            authorizers=(Authorizer("policy.permission", ("arg:0",)),),
            operations=(Operation(f"fixture.Request.{method}", ("arg:0",)),),
        )
    )
    assert proof["complete"] is guarded, proof
    assert proof["entries"][0]["status"] == ("verified" if guarded else "violated"), (
        proof
    )
    assert len(proof["entries"][0]["dispatches"]) == 1
