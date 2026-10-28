"""Source-derived subscription and explicit dataclass initializer obligations."""

from textwrap import dedent

import pytest

from tests.security.test_verification_records import check

MAPPING = """
from collections.abc import Mapping
from typing import Any
@dataclass(frozen=True, slots=True, init=False, eq=False)
class View(Mapping[str, Any]):
    value: object
    def __init__(self, value):
        object.__setattr__(self, 'value', value)
    def __getitem__(self, key):
        return self.value
    def __iter__(self):
        raise TypeError('unsupported iterator')
    def __len__(self):
        return 1
"""
BODY = """
view = View(request)
d = permission(principal, request)
if d.verdict is Verdict.ALLOW:
    return dispatch(principal, view['value'])
"""


def test_mapping_source_subscription_keeps_useful_authorized_result():
    report = check(BODY, MAPPING)
    assert report["complete"], report
    assert len(report["entries"][0]["dispatches"]) == 1
    assert "example.View.__getitem__" in report["entries"][0]["visited_functions"]


def test_explicit_initializer_does_not_run_post_init_automatically():
    helpers = MAPPING + "\n    def __post_init__(self):\n        dispatch(None, None)\n"
    report = check(BODY, helpers)
    assert report["complete"], report
    assert len(report["entries"][0]["dispatches"]) == 1
    assert "example.View.__post_init__" not in report["entries"][0]["visited_functions"]


@pytest.mark.parametrize(
    "method",
    [
        "dispatch(None, None)\n        return self.value",
        "return None",
        "return key",
    ],
)
def test_subscription_effect_or_replacement_cannot_reuse_original_permission(method):
    report = check(BODY, MAPPING.replace("return self.value", method))
    assert not report["complete"], report
    assert any(not item["authorized"] for item in report["entries"][0]["dispatches"])


def test_subscription_nested_mutation_revokes_existing_alias_grant():
    helpers = MAPPING.replace(
        "return self.value", "self.value['value'] = key\n        return self.value"
    )
    report = check(
        """
        payload = {'value': request}
        view = View(payload)
        d = permission(principal, payload)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, view['replacement'])
    """,
        helpers,
    )
    assert not report["complete"], report
    assert not report["entries"][0]["dispatches"][-1]["authorized"]


@pytest.mark.parametrize(
    "expression", ["view", "not view", "view and request", "view or request"]
)
def test_mapping_truth_never_skips_effectful_len(expression):
    helpers = MAPPING.replace("return 1", "dispatch(None, None)\n        return 1")
    report = check(
        f"""
        view = View(request)
        d = permission(principal, request)
        if {expression}:
            if d.verdict is Verdict.ALLOW:
                return dispatch(principal, request)
    """,
        helpers,
    )
    assert not report["complete"], report
    assert any(
        "__len__ protocol" in issue["reason"]
        for issue in report["entries"][0]["issues"]
    )


@pytest.mark.parametrize(
    "expression", ["view.get('value')", "view.keys()", "view.items()", "view.values()"]
)
def test_unmodeled_mapping_mixins_do_not_become_missing_attribute_refusals(expression):
    report = check(
        f"""
        view = View(request)
        result = {expression}
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, request)
    """,
        MAPPING,
    )
    assert not report["complete"], report
    assert any(
        "inherited native Mapping methods" in issue["reason"]
        for issue in report["entries"][0]["issues"]
    )


@pytest.mark.parametrize(
    "change",
    [
        lambda source: source.replace(
            "Mapping[str, Any]", "Mapping[dispatch(None, None), Any]"
        ),
        lambda source: source.replace(
            "class View(Mapping[str, Any]):",
            "class View(Mapping[str, Any], metaclass=Unknown):",
        ),
        lambda source: source.replace("def __getitem__", "async def __getitem__"),
        lambda source: source.replace(
            "    def __getitem__", "    @property\n    def __getitem__"
        ),
        lambda source: (
            source
            + "\n    @classmethod\n    def __subclasshook__(cls, candidate):\n        return dispatch(None, None)\n"
        ),
        lambda source: source.replace("init=False", "init=True"),
        lambda source: source.replace("eq=False", "eq=True"),
    ],
)
def test_unsupported_abc_constructor_and_descriptor_forms_never_pass(change):
    report = check(BODY, change(MAPPING))
    assert not report["complete"], report


def test_special_subscription_ignores_instance_field_shadow():
    helpers = """
    class View:
        def __init__(self, value):
            self.value = value
            self.__getitem__ = dispatch
        def __getitem__(self, key):
            return self.value
    """
    report = check(BODY, dedent(helpers))
    # The write itself remains unsupported; source subscription still uses the
    # class implementation instead of granting a call through that field.
    assert not report["complete"], report
    assert any(
        "object protocol mutation" in issue["reason"]
        for issue in report["entries"][0]["issues"]
    )
    assert len(report["entries"][0]["dispatches"]) == 1
    assert report["entries"][0]["dispatches"][0]["authorized"]
