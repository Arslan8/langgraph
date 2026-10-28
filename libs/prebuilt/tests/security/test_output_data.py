"""Closed output admission preserves useful records without object protocols."""

from dataclasses import dataclass
from uuid import uuid4

import pytest
from langchain_core.agents import AgentAction, AgentActionMessageLog, AgentFinish
from langchain_core.documents import Document
from langchain_core.messages import (
    AIMessage,
    AIMessageChunk,
    BaseMessage,
    BaseMessageChunk,
    ChatMessage,
    ChatMessageChunk,
    FunctionMessage,
    FunctionMessageChunk,
    HumanMessage,
    HumanMessageChunk,
    RemoveMessage,
    SystemMessage,
    SystemMessageChunk,
    ToolMessage,
    ToolMessageChunk,
)
from langchain_core.outputs import (
    ChatGeneration,
    ChatGenerationChunk,
    ChatResult,
    Generation,
    GenerationChunk,
    LLMResult,
    RunInfo,
)
from langchain_core.prompt_values import (
    ChatPromptValue,
    ChatPromptValueConcrete,
    StringPromptValue,
)
from langgraph.callbacks import GraphInterruptEvent, GraphResumeEvent
from langgraph.types import Command, Interrupt, PregelTask, Send, StateSnapshot

from langgraph.prebuilt.security.objects import (
    LabeledValue,
    OutputRequest,
    SecurityLabels,
)
from langgraph.prebuilt.security.output_data import (
    OutputDataError,
    output_data_digest,
    validate_output_data,
    validate_output_request,
    validate_security_labels,
)


def secret(value="secret"):
    return LabeledValue("private", value, SecurityLabels(frozenset({"secret"}), "low"))


def test_exact_native_data_and_nested_labels_remain_useful():
    value = {
        "data": [None, True, 42, -3, 1.25, "text", b"bytes", ("tuple",)],
        "nested": LabeledValue("outer", {"inner": secret()}),
    }
    assert validate_output_data(value) == SecurityLabels(frozenset({"secret"}), "low")
    assert len(output_data_digest(value)) == 64


@pytest.mark.parametrize(
    "factory",
    [
        lambda: BaseMessage(content="hello", type="message"),
        lambda: BaseMessageChunk(content="hello", type="message"),
        lambda: AIMessage(content="hello", additional_kwargs={"private": secret()}),
        lambda: AIMessageChunk(
            content="hello", response_metadata={"private": secret()}
        ),
        lambda: HumanMessage(content="hello"),
        lambda: HumanMessageChunk(content="hello"),
        lambda: SystemMessage(content="hello"),
        lambda: SystemMessageChunk(content="hello"),
        lambda: FunctionMessage(content="hello", name="function"),
        lambda: FunctionMessageChunk(content="hello", name="function"),
        lambda: ChatMessage(content="hello", role="user"),
        lambda: ChatMessageChunk(content="hello", role="user"),
        lambda: ToolMessage(
            content="hello", tool_call_id="call", artifact={"private": secret()}
        ),
        lambda: ToolMessageChunk(content="hello", tool_call_id="call"),
        lambda: RemoveMessage(id="message"),
        lambda: Generation(text="hello", generation_info={"private": secret()}),
        lambda: GenerationChunk(text="hello"),
        lambda: ChatGeneration(message=AIMessage(content="hello")),
        lambda: ChatGenerationChunk(message=AIMessageChunk(content="hello")),
        lambda: LLMResult(
            generations=[[Generation(text="hello")]], run=[RunInfo(run_id=uuid4())]
        ),
        lambda: ChatResult(
            generations=[ChatGeneration(message=AIMessage(content="hello"))]
        ),
        lambda: RunInfo(run_id=uuid4()),
        lambda: AgentAction(tool="read", tool_input={"path": "data"}, log="ok"),
        lambda: AgentActionMessageLog(
            tool="read",
            tool_input="data",
            log="ok",
            message_log=[AIMessage(content="hello")],
        ),
        lambda: AgentFinish(return_values={"output": "done"}, log="ok"),
        lambda: Document(page_content="hello", metadata={"private": secret()}),
        lambda: StringPromptValue(text="hello"),
        lambda: ChatPromptValue(messages=[HumanMessage(content="hello")]),
        lambda: ChatPromptValueConcrete(messages=[HumanMessage(content="hello")]),
    ],
)
def test_actual_langchain_record_types_are_admitted(factory):
    value = factory()
    validate_output_data(value)
    assert output_data_digest(value) == output_data_digest(value)


def test_all_message_storage_is_admitted_and_contributes_labels():
    message = AIMessage(content="hello", extra_label=secret())
    object.__setattr__(message, "__pydantic_private__", {"private_label": secret()})
    assert validate_output_data(message).confidentiality == frozenset({"secret"})
    before = output_data_digest(message)
    message.__pydantic_extra__["extra_label"] = "different"
    assert output_data_digest(message) != before
    message.__pydantic_private__["opaque"] = object()
    with pytest.raises(OutputDataError, match="unsupported_type"):
        validate_output_data(message)


def test_snapshot_interrupt_and_lifecycle_fields_preserve_labels_and_identity():
    interrupt = Interrupt(secret(), id="interrupt", response_schema={"type": "string"})
    task = PregelTask(
        "id", "node", ("node", 0), None, (interrupt,), None, {"result": "ok"}
    )
    snapshot = StateSnapshot(
        {"value": "public"},
        ("node",),
        {"configurable": {"thread_id": "thread"}},
        {"step": 1},
        "2026-10-26",
        None,
        (task,),
        (interrupt,),
    )
    run_id = uuid4()
    values = [
        snapshot,
        GraphInterruptEvent(run_id, "pending", "checkpoint", (), (interrupt,)),
        GraphResumeEvent(run_id, "pending", "checkpoint", ()),
    ]
    for value in values:
        validate_output_data(value)
        output_data_digest(value)
    assert validate_output_data(snapshot).confidentiality == frozenset({"secret"})


def test_command_and_send_callback_payloads_use_explicit_native_slots():
    value = Command(
        update={"value": "public"}, goto=Send("worker", secret(), timeout=1.0)
    )
    assert validate_output_data(value).confidentiality == frozenset({"secret"})
    output_data_digest(value)
    value.__dict__["opaque"] = object()
    with pytest.raises(OutputDataError, match="record_shape"):
        validate_output_data(value)


def test_hostile_protocols_are_not_invoked():
    called = []

    class HostileMeta(type):
        def __hash__(cls):
            called.append("class hash")
            return 1

        def __eq__(cls, other):
            called.append("class equality")
            return False

    class Hostile(metaclass=HostileMeta):
        def __getattribute__(self, name):
            called.append("attribute")
            raise AssertionError

        def __repr__(self):
            called.append("repr")
            raise AssertionError

        def __str__(self):
            called.append("str")
            raise AssertionError

    class MappingSubclass(dict):
        def items(self):
            called.append("items")
            raise AssertionError

    class ListSubclass(list):
        def __iter__(self):
            called.append("iterate")
            raise AssertionError

    class StringSubclass(str):
        def __str__(self):
            called.append("string conversion")
            raise AssertionError

    @dataclass
    class OtherRecord:
        data: object

    for value in (
        Hostile(),
        MappingSubclass(),
        ListSubclass(),
        StringSubclass("data"),
        OtherRecord("data"),
    ):
        for operation in (validate_output_data, output_data_digest):
            with pytest.raises(OutputDataError, match="unsupported_type"):
                operation(value)
    assert called == []


def test_native_dictionary_checks_keys_before_hash_equality_or_conversion():
    called = []

    class Key:
        def __hash__(self):
            called.append("hash")
            return 1

        def __eq__(self, other):
            called.append("equality")
            return False

        def __str__(self):
            called.append("str")
            return "key"

    value = {Key(): "data"}
    called.clear()
    with pytest.raises(OutputDataError, match="string_key_required"):
        validate_output_data(value)
    assert called == []


def test_unmodeled_model_attributes_and_class_subclasses_refuse_without_calls():
    called = []

    class MessageSubclass(AIMessage):
        def model_dump(self, *args, **kwargs):
            called.append(True)
            return {}

    with pytest.raises(OutputDataError, match="unsupported_type"):
        validate_output_data(MessageSubclass(content="hello"))
    message = AIMessage(content="hello")
    message.__dict__["model_dump"] = lambda *args: called.append(True)
    with pytest.raises(OutputDataError, match="record_shape"):
        validate_output_data(message)
    assert called == []


def test_forged_label_sets_are_refused_without_subset_or_iteration():
    called = []

    class FakeSet:
        def __iter__(self):
            called.append("iterate")
            return iter(())

        def issubset(self, other):
            called.append("subset")
            return True

    labels = SecurityLabels()
    object.__setattr__(labels, "confidentiality", FakeSet())
    with pytest.raises(OutputDataError, match="native_string_set_required"):
        validate_security_labels(labels)
    assert called == []


def test_budget_cycles_nonfinite_and_capability_payloads_are_refused():
    cyclic = []
    cyclic.append(cyclic)
    for value, options, reason in (
        (cyclic, {}, "cycle"),
        ([[["deep"]]], {"max_depth": 1}, "depth"),
        ([1, 2, 3], {"max_nodes": 2}, "budget"),
        ("long", {"max_bytes": 4}, "budget"),
        (float("nan"), {}, "nonfinite_float"),
        (object(), {}, "unsupported_type"),
        (lambda: None, {}, "unsupported_type"),
    ):
        with pytest.raises(OutputDataError, match=reason):
            validate_output_data(value, **options)


def test_channel_labels_are_conservative_without_value_equality():
    channels = {"value": SecurityLabels(frozenset({"secret"}), "low")}
    assert (
        validate_output_data({"wrapped": {"value": "changed"}}, channel_labels=channels)
        == channels["value"]
    )
    assert (
        validate_output_data({"other": "public"}, channel_labels=channels)
        == SecurityLabels()
    )


def test_final_request_checks_explicit_payload_label_consistency():
    request = OutputRequest("console", secret(), output_id="output")
    with pytest.raises(OutputDataError, match="payload_confidentiality"):
        validate_output_request(request)
    object.__setattr__(request, "labels", SecurityLabels(frozenset({"secret"})))
    with pytest.raises(OutputDataError, match="payload_integrity"):
        validate_output_request(request)
    object.__setattr__(request, "labels", SecurityLabels(frozenset({"secret"}), "low"))
    assert validate_output_request(request) is None
    # Shape admission does not itself authorize clearance or declassification.
    assert request.clearance == frozenset()


@pytest.mark.parametrize(
    "operation,kind",
    [
        (validate_security_labels, SecurityLabels),
        (validate_output_data, LabeledValue),
        (output_data_digest, LabeledValue),
        (validate_output_request, OutputRequest),
    ],
)
def test_missing_native_layout_failures_do_not_retain_objects(operation, kind):
    value = object.__new__(kind)
    with pytest.raises(OutputDataError) as caught:
        operation(value)
    assert caught.value.args == ("output_data:invalid_layout",)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_live_exceptions_are_rejected_and_fresh_error_payloads_are_traversed():
    fresh = RuntimeError(secret())
    assert validate_output_data(fresh).confidentiality == frozenset({"secret"})
    try:
        raise ValueError("private traceback")
    except ValueError as error:
        live = error
    with pytest.raises(OutputDataError, match="live_exception"):
        validate_output_data(live)


def test_digest_binds_types_order_all_record_fields_and_nested_labels():
    values = [1, True, 1.0, "1", b"1", [1], (1,), {"a": 1, "b": 2}, {"b": 2, "a": 1}]
    assert len({output_data_digest(value) for value in values}) == len(values)
    left = ToolMessage(
        content="hello", tool_call_id="call", artifact={"value": "first"}
    )
    right = ToolMessage(
        content="hello", tool_call_id="call", artifact={"value": "second"}
    )
    assert output_data_digest(left) != output_data_digest(right)
    assert output_data_digest(secret("first")) != output_data_digest(secret("second"))
    assert output_data_digest(LabeledValue("private", "secret")) != output_data_digest(
        secret()
    )
