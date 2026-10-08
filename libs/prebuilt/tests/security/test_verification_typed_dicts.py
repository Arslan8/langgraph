"""TypedDict source models preserve dict behavior without schema authority."""

from dataclasses import replace
from typing import TypedDict

import pytest

from langgraph.prebuilt.security.verification import verify
from tests.security.test_verification import spec
from tests.security.test_verification_records import check

DECLARATION = """
from typing import TypedDict
class Config(TypedDict, total=False):
    value: object
"""


@pytest.mark.parametrize(
    "construction",
    [
        "Config(value=request)",
        "Config({'value': request})",
        "Config({'value': None}, value=request)",
        "Config(**{'value': request})",
    ],
)
@pytest.mark.parametrize("provider", ["typing", "typing_extensions"])
def test_native_constructor_preserves_projected_identity(construction, provider):
    report = check(
        f"""
        config = {construction}
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, config['value'])
        """,
        DECLARATION.replace("from typing ", f"from {provider} "),
    )
    assert report["complete"], report


def test_required_annotations_do_not_validate_values_or_extra_keys():
    report = check(
        """
        config = Config(extra=request)
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, config['extra'])
        """,
        DECLARATION.replace("total=False", "total=True"),
    )
    assert report["complete"], report


def test_constructor_does_not_grant_authority():
    report = check("return dispatch(principal, Config(value=request))", DECLARATION)
    assert report["entries"][0]["status"] == "violated"


def test_constructor_shares_nested_values_but_copies_outer_storage():
    report = check(
        """
        original = {'value': request}
        copied = Config(original)
        d = permission(principal, copied)
        if d.verdict is Verdict.ALLOW:
            original['value'] = None
            return dispatch(principal, copied)
        """,
        DECLARATION,
    )
    assert report["complete"], report
    report = check(
        """
        nested = {'value': request}
        copied = Config(value=nested)
        d = permission(principal, copied)
        if d.verdict is Verdict.ALLOW:
            nested['value'] = None
            return dispatch(principal, copied)
        """,
        DECLARATION,
    )
    assert report["entries"][0]["status"] == "violated"


def test_native_dict_mutation_revokes_grant():
    report = check(
        """
        config = Config(value=request)
        d = permission(principal, config)
        if d.verdict is Verdict.ALLOW:
            config['value'] = None
            return dispatch(principal, config)
        """,
        DECLARATION,
    )
    assert report["entries"][0]["status"] == "violated"


def test_constructor_argument_effects_are_analyzed():
    report = check("return Config(value=dispatch(principal, request))", DECLARATION)
    assert report["entries"][0]["status"] == "violated"


def test_typed_dict_value_is_a_native_dict():
    report = check(
        """
        config = Config(value=request)
        if not isinstance(config, dict):
            return dispatch(principal, request)
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, config['value'])
        """,
        DECLARATION,
    )
    assert report["complete"], report


def test_isinstance_against_declaration_raises_before_dispatch():
    report = check(
        """
        if isinstance(request, Config):
            return dispatch(principal, request)
        return dispatch(principal, request)
        """,
        DECLARATION,
    )
    assert not report["entries"][0]["dispatches"]
    assert not report["entries"][0]["issues"]


def test_type_error_handler_requires_authorization():
    report = check(
        """
        try:
            isinstance(request, Config)
        except TypeError:
            return dispatch(principal, request)
        """,
        DECLARATION,
    )
    assert report["entries"][0]["status"] == "violated"


def test_single_inherited_declaration_uses_native_constructor():
    report = check(
        """
        config = Child(value=request)
        d = permission(principal, request)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, config['value'])
        """,
        DECLARATION + "\nclass Child(Config):\n    other: str\n",
    )
    assert report["complete"], report


@pytest.mark.parametrize(
    "declaration",
    [
        DECLARATION + "    value = dispatch(None, None)\n",
        DECLARATION + "    def hidden(self):\n        dispatch(None, None)\n",
        DECLARATION.replace("TypedDict, total=False", "TypedDict, total=choose()"),
        DECLARATION.replace("TypedDict, total=False", "TypedDict, metaclass=Custom"),
        DECLARATION.replace("class Config", "@decorate\nclass Config"),
        DECLARATION.replace("value: object", "value: object = dispatch(None, None)"),
        "class Config(TypedDict):\n    pass\nfrom typing import TypedDict\n",
        "from typing import TypedDict\nTypedDict = None\nclass Config(TypedDict):\n    pass\n",
        "from typing import TypedDict\nclass Config(TypedDict, object):\n    pass\n",
    ],
)
def test_unmodeled_class_definition_is_not_exempted(declaration):
    report = check(
        """
        config = Config(value=request)
        d = permission(principal, config)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, config)
        """,
        declaration,
    )
    assert not report["complete"]
    assert report["issues"]


def test_unknown_input_is_not_assumed_to_be_a_dict():
    report = check(
        """
        config = Config(request)
        d = permission(principal, config)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, config)
        """,
        DECLARATION,
    )
    assert not report["complete"]
    assert any(
        "known mapping" in issue["reason"] for issue in report["entries"][0]["issues"]
    )


@pytest.mark.parametrize(
    "body",
    [
        "def __init__(self, value):\n        self.value = value",
        "def hidden(self):\n        return None",
    ],
)
def test_unsupported_descendant_is_not_treated_as_an_ordinary_class(body):
    report = check(
        """
        config = Child(value=request)
        d = permission(principal, config)
        if d.verdict is Verdict.ALLOW:
            return dispatch(principal, config)
        """,
        DECLARATION + "\nclass Child(Config):\n    " + body + "\n",
    )
    assert not report["complete"]
    assert any("TypedDict subclass" in issue["reason"] for issue in report["issues"])


def test_callable_in_typed_dict_cannot_escape():
    report = check("return Config(value=dispatch)", DECLARATION)
    assert not report["complete"]
    assert any(
        "capability escapes" in issue["reason"]
        for issue in report["entries"][0]["issues"]
    )


def test_eager_annotations_still_require_a_definition_model():
    original = spec(
        DECLARATION + "\nclass Tool:\n    def invoke(self):\n        pass\n"
    )
    report = verify(original)
    assert not report["complete"]
    assert report["issues"]


def test_declaration_as_api_surface_cannot_hide_native_methods():
    original = spec(DECLARATION)
    report = verify(
        replace(
            original,
            sources={
                "example": "from __future__ import annotations\n"
                + original.sources["example"]
            },
            surfaces=("example.Config",),
        )
    )
    assert not report["complete"]
    assert any("native dictionary" in i["reason"] for i in report["issues"])


def test_native_typed_dict_contract():
    class NativeConfig(TypedDict):
        value: int

    nested = object()
    original = {"unexpected": nested}
    config = NativeConfig(original)  # type: ignore[misc]
    assert type(config) is dict
    assert config == original and config is not original
    assert config["unexpected"] is nested  # type: ignore[typeddict-item]
    with pytest.raises(TypeError):
        isinstance(config, NativeConfig)  # type: ignore[misc]
