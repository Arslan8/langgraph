"""Policy argument storage admits inspectable native shapes before protocols."""

from collections.abc import Mapping
from dataclasses import FrozenInstanceError, replace
from types import MappingProxyType

import pytest

from langgraph.prebuilt.security import Decision, Verdict
from langgraph.prebuilt.security.types import _decision_arguments, _DecisionArguments


class Opaque:
    calls = 0

    def __bool__(self):
        type(self).calls += 1
        raise AssertionError("opaque truthiness executed")

    def __iter__(self):
        type(self).calls += 1
        raise AssertionError("opaque iteration executed")

    def __len__(self):
        type(self).calls += 1
        raise AssertionError("opaque length executed")

    def __hash__(self):
        type(self).calls += 1
        raise AssertionError("opaque hashing executed")

    def __eq__(self, other):
        type(self).calls += 1
        raise AssertionError("opaque equality executed")


class CustomMapping(Mapping):
    calls = 0

    def __getitem__(self, key):
        type(self).calls += 1
        raise AssertionError("custom mapping lookup executed")

    def __iter__(self):
        type(self).calls += 1
        raise AssertionError("custom mapping iteration executed")

    def __len__(self):
        type(self).calls += 1
        raise AssertionError("custom mapping length executed")

    def items(self):
        type(self).calls += 1
        raise AssertionError("custom mapping items executed")


class DictSubclass(dict):
    def items(self):
        raise AssertionError("dictionary subclass items executed")


class TupleSubclass(tuple):
    def __len__(self):
        raise AssertionError("tuple subclass length executed")

    def __iter__(self):
        raise AssertionError("tuple subclass iteration executed")


class StringSubclass(str):
    def __hash__(self):
        raise AssertionError("string subclass hashing executed")

    def __eq__(self, other):
        raise AssertionError("string subclass equality executed")


@pytest.mark.parametrize("verdict", [Verdict.TRANSFORM, Verdict.REDACT])
@pytest.mark.parametrize(
    "arguments",
    [
        CustomMapping(),
        MappingProxyType(CustomMapping()),
        MappingProxyType({"content": "plain"}),
        DictSubclass(content="plain"),
        [("content", "plain")],
        Opaque(),
    ],
)
def test_decision_refuses_unsupported_mapping_shapes_before_protocols(
    verdict, arguments
):
    CustomMapping.calls = 0
    Opaque.calls = 0
    with pytest.raises(TypeError, match="plain dictionary or native record"):
        Decision(verdict, "policy", new_args=arguments)
    assert CustomMapping.calls == 0
    assert Opaque.calls == 0


@pytest.mark.parametrize("verdict", [Verdict.TRANSFORM, Verdict.REDACT])
def test_native_argument_snapshot_keeps_mapping_interface_and_opaque_values(verdict):
    opaque = Opaque()
    original = {"content": opaque, "plain": "value"}
    decision = Decision(verdict, "policy", new_args=original)
    arguments = decision.new_args
    Opaque.calls = 0
    original["content"] = "changed"
    assert type(arguments) is _DecisionArguments
    assert arguments["content"] is opaque
    assert arguments.get("content") is opaque
    assert arguments.get("missing", "default") == "default"
    assert list(arguments) == ["content", "plain"]
    assert list(arguments.keys()) == ["content", "plain"]
    assert len(arguments) == 2
    assert "content" in arguments
    copied = dict(arguments)
    snapshot = _decision_arguments(arguments)
    assert type(snapshot) is dict
    assert copied["content"] is opaque
    assert snapshot["content"] is opaque
    snapshot["content"] = "changed"
    assert arguments["content"] is opaque
    assert Opaque.calls == 0
    with pytest.raises(TypeError):
        arguments["content"] = "changed"
    with pytest.raises(FrozenInstanceError):
        arguments._items = ()


def test_mapping_equality_and_decision_reconstruction_remain_supported():
    original = Decision(Verdict.TRANSFORM, "policy", new_args={"path": "safe"})
    assert original.new_args == {"path": "safe"}
    assert {"path": "safe"} == original.new_args
    changed = replace(original, reason="updated")
    rebuilt = Decision(Verdict.REDACT, "rebuilt", new_args=original.new_args)
    assert changed.new_args == {"path": "safe"}
    assert rebuilt.new_args == {"path": "safe"}
    assert changed.new_args is not original.new_args
    assert rebuilt.new_args is not original.new_args
    assert Decision(Verdict.TRANSFORM, "empty", new_args={}).new_args == {}


@pytest.mark.parametrize(
    "storage",
    [
        Opaque(),
        [],
        TupleSubclass((("content", "value"),)),
        (Opaque(),),
        (["content", "value"],),
        (TupleSubclass(("content", "value")),),
        ((),),
        (("content",),),
        (("content", "value", "extra"),),
        ((Opaque(), "value"),),
        ((StringSubclass("content"), "value"),),
        (("content", "first"), ("content", "second")),
    ],
)
@pytest.mark.parametrize("operation", ["snapshot", "construct", "replace"])
def test_forged_tuple_backing_is_rejected_without_its_protocols(storage, operation):
    forged = object.__new__(_DecisionArguments)
    object.__setattr__(forged, "_items", storage)
    Opaque.calls = 0
    with pytest.raises(TypeError, match="decision argument"):
        if operation == "snapshot":
            _decision_arguments(forged)
        elif operation == "construct":
            Decision(Verdict.TRANSFORM, "policy", new_args=forged)
        else:
            original = Decision(Verdict.REDACT, "policy", new_args={})
            object.__setattr__(original, "new_args", forged)
            replace(original, reason="updated")
    assert Opaque.calls == 0


def test_uninitialized_and_subclassed_internal_records_are_not_admitted():
    with pytest.raises(TypeError, match="missing"):
        _decision_arguments(object.__new__(_DecisionArguments))

    class Derived(_DecisionArguments):
        def items(self):
            raise AssertionError("subclass items executed")

    with pytest.raises(TypeError, match="plain dictionary or native record"):
        _decision_arguments(Derived({"content": "value"}))


def test_mapping_lookup_does_not_execute_unsupported_key_protocols():
    arguments = Decision(
        Verdict.REDACT, "policy", new_args={"content": "value"}
    ).new_args
    Opaque.calls = 0
    with pytest.raises(TypeError, match="plain strings"):
        arguments[Opaque()]
    assert Opaque.calls == 0


def test_sparse_dictionary_keys_are_validated_without_rehashing():
    class Key:
        armed = False
        calls = 0

        def __hash__(self):
            if type(self).armed:
                type(self).calls += 1
            return 0

        def __eq__(self, other):
            if type(self).armed:
                type(self).calls += 1
                raise AssertionError("native dictionary key equality executed")
            return self is other

    keys = [Key() for _ in range(100)]
    arguments = {key: "opaque" for key in keys}
    for key in keys[5:]:
        del arguments[key]
    Key.armed = True
    with pytest.raises(TypeError, match="plain strings"):
        Decision(Verdict.TRANSFORM, "policy", new_args=arguments)
    assert Key.calls == 0
