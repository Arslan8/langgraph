"""Captured output fields must be native storage, never foreign descriptors."""

from __future__ import annotations

import subprocess
import sys
import warnings
from uuid import UUID

import pytest
from langchain_core.messages import AIMessage
from langgraph.types import Command, Interrupt, Send, TimeoutPolicy

from langgraph.prebuilt.security.objects import (
    LabeledValue,
    OutputRequest,
    SecurityLabels,
)
from langgraph.prebuilt.security.output_data import (
    OutputDataError,
    _native_descriptor,
    validate_output_request,
)


def test_preimport_foreign_send_descriptor_refuses_without_running_getter():
    script = """
import sys
from langgraph.types import Send
assert 'langgraph.prebuilt.security.output_data' not in sys.modules
calls = []
class Foreign:
    def __get__(self, instance, owner=None):
        calls.append('effect')
        return None
Send.timeout = Foreign()
try:
    from langgraph.prebuilt.security.output_data import validate_output_request
except PermissionError as error:
    assert error.args == ('output_data:invalid_layout',)
    assert error.__context__ is None
    assert error.__cause__ is None
else:
    raise AssertionError('foreign descriptor was admitted at import')
assert calls == []
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("replacement", ["foreign", "wrong-owner", "wrong-name"])
def test_native_capture_rejects_foreign_or_misbinding_descriptor(replacement):
    calls = []

    class Native:
        __slots__ = ("field", "other")

    class Other:
        __slots__ = ("field",)

    class Foreign:
        def __getattribute__(self, name):
            calls.append(name)
            raise AssertionError("foreign descriptor protocol ran")

        def __get__(self, instance, owner=None):
            calls.append("get")
            raise AssertionError("foreign getter ran")

    if replacement == "foreign":
        Native.field = Foreign()
    elif replacement == "wrong-owner":
        Native.field = Other.field
    else:
        Native.field = Native.other
    with pytest.raises(OutputDataError, match="invalid_layout") as caught:
        _native_descriptor(Native, "field")
    assert calls == []
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None


def test_native_capture_bypasses_custom_metaclass_namespace():
    calls = []

    class Meta(type):
        @property
        def __dict__(cls):  # ty: ignore[override-of-final-variable] -- hostile runtime shape
            calls.append("namespace-property")
            raise AssertionError("foreign namespace property ran")

        def __getattribute__(cls, name):
            calls.append("attribute:" + name)
            raise AssertionError("foreign metaclass lookup ran")

    class Native(metaclass=Meta):
        __slots__ = ("field",)

    descriptor = _native_descriptor(Native, "field")
    assert descriptor.__objclass__ is Native
    assert descriptor.__name__ == "field"
    assert calls == []


def test_foreign_owner_class_property_is_never_consulted():
    calls = []

    class Foreign:
        @property
        def __class__(self):
            calls.append("class")
            return type

    with pytest.raises(OutputDataError, match="invalid_layout"):
        _native_descriptor(Foreign(), "field")
    assert calls == []


def test_foreign_class_keys_are_refused_before_hash_or_equality():
    calls = []

    class Key:
        def __hash__(self):
            calls.append("hash")
            return hash("field")

        def __eq__(self, other):
            calls.append("equality")
            return False

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)
        native = type("Native", (), {Key(): "opaque", "__slots__": ("field",)})
    calls.clear()
    with pytest.raises(OutputDataError, match="invalid_layout"):
        _native_descriptor(native, "field")
    assert calls == []


def test_later_public_class_replacement_does_not_replace_captured_native_slot(
    monkeypatch,
):
    calls = []
    candidate = Send("node", {"plain": "data"})

    class Foreign:
        def __get__(self, instance, owner=None):
            calls.append("get")
            return None

    monkeypatch.setattr(Send, "timeout", Foreign())
    validate_output_request(OutputRequest("api", candidate, output_id="o"))
    assert calls == []


def test_useful_native_framework_model_and_exception_records_remain_admitted():
    content = [
        Command(update={"plain": "data"}),
        Send("node", {"plain": "data"}, timeout=1),
        TimeoutPolicy(run_timeout=1),
        Interrupt("pause", id="interrupt"),
        AIMessage(content="answer"),
        UUID(int=1),
        RuntimeError("ordinary detached error"),
        LabeledValue("plain", [1, True, None], SecurityLabels()),
    ]
    validate_output_request(OutputRequest("api", content, output_id="o"))
