"""Tests for private blobs and out-of-state principal binding."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest
from langgraph.runtime import Runtime

from langgraph.prebuilt.security import (
    PRINCIPAL_CONFIG_KEY,
    AuditRecord,
    MemoryAuditSink,
    Principal,
    SecurityBindingError,
    SecurityModule,
    Verdict,
    allocate_blobs,
    copy_blobs,
    principal_from,
    with_principal,
)
from langgraph.prebuilt.security.binding import history_for, next_call_index


def _principal() -> Principal:
    return Principal("alice", frozenset({"analyst"}), frozenset(), "session")


def test_blob_copy_does_not_share_slots() -> None:
    """Delegation starts from copied rather than aliased module state."""
    original = allocate_blobs(["cap", "paths"])
    original["paths"]["root"] = "/workspace"

    copied = copy_blobs(original)
    copied["paths"]["root"] = "/tmp"

    assert original["paths"]["root"] == "/workspace"
    assert copied["paths"]["root"] == "/tmp"


def test_with_principal_copies_config_and_prepares_slots() -> None:
    """Binding preserves caller config and invokes module credential setup."""

    class Labels(SecurityModule):
        name = "labels"

        def cred_prepare(self, principal: Principal, slot: object) -> None:
            slot["tenant"] = "research"  # type: ignore[index]

    principal = _principal()
    original = {"configurable": {"thread_id": "thread-1"}}

    bound = with_principal(original, principal, modules=[Labels()])

    assert PRINCIPAL_CONFIG_KEY not in original["configurable"]
    assert principal_from(bound) is principal
    assert principal.security["labels"]["tenant"] == "research"
    assert "cap" in principal.security


def test_with_principal_copies_runtime_context_before_binding() -> None:
    """The new runtime gets identity without mutating caller-owned context."""
    context: dict[str, object] = {}
    runtime = Runtime(context=context)
    principal = _principal()

    bound = with_principal({"configurable": {"__pregel_runtime": runtime}}, principal)

    new_runtime = bound["configurable"]["__pregel_runtime"]
    assert new_runtime is not runtime
    assert new_runtime.context is not context
    assert new_runtime.context[PRINCIPAL_CONFIG_KEY] is principal
    assert context == {}


def test_principal_is_never_read_from_graph_state() -> None:
    """A principal-looking state field cannot establish identity."""
    assert principal_from({"state": {PRINCIPAL_CONFIG_KEY: _principal()}}) is None


def test_invalid_reserved_value_fails_closed() -> None:
    """Corruption of the framework-owned config key is not ignored."""
    with pytest.raises(TypeError, match="invalid"):
        principal_from({"configurable": {PRINCIPAL_CONFIG_KEY: "alice"}})


def test_cred_prepare_error_aborts_binding() -> None:
    """A module failure never yields a partially prepared bound config."""

    class Broken(SecurityModule):
        name = "broken"

        def cred_prepare(self, principal: Principal, slot: object) -> None:
            raise RuntimeError("boom")

    with pytest.raises(SecurityBindingError, match="broken"):
        with_principal({}, _principal(), modules=[Broken()])


def test_call_indexes_are_shared_by_copied_runtime_configs() -> None:
    """Every execution route draws indexes from one bound-session counter."""
    bound = with_principal({}, _principal())
    copied = {**bound, "metadata": {"route": "subgraph"}}

    assert next_call_index(bound) == 0
    assert next_call_index(copied) == 1


def test_history_is_scoped_to_user_and_session() -> None:
    """Policies cannot observe audit decisions from another authenticated session."""
    sink = MemoryAuditSink()
    for user_id, session_id in (
        ("alice", "session"),
        ("alice", "other-session"),
        ("bob", "session"),
    ):
        sink.write(
            AuditRecord(
                call_index=0,
                tool_name="read_file",
                user_id=user_id,
                args_hash="redacted",
                stage="permission",
                module="paths",
                verdict=Verdict.ALLOW,
                reason="allow",
                session_id=session_id,
            )
        )

    history = history_for(sink, _principal())

    assert len(history) == 1
    assert history[0].user_id == "alice"
    assert history[0].session_id == "session"


class _HostileDictionary(dict):
    calls = 0

    def __bool__(self):
        type(self).calls += 1
        raise AssertionError("custom truth test executed")

    def get(self, *args):
        type(self).calls += 1
        raise AssertionError("custom mapping lookup executed")

    def __iter__(self):
        type(self).calls += 1
        raise AssertionError("custom mapping iteration executed")

    def copy(self):
        type(self).calls += 1
        raise AssertionError("custom mapping copy executed")


@pytest.mark.parametrize("nested", [False, True])
@pytest.mark.parametrize("operation", [principal_from, with_principal, next_call_index])
def test_binding_rejects_mapping_subclasses_without_running_protocols(
    nested, operation
):
    _HostileDictionary.calls = 0
    hostile = _HostileDictionary()
    config = {"configurable": hostile} if nested else hostile
    with pytest.raises(TypeError, match="plain dictionary"):
        if operation is with_principal:
            operation(config, _principal())
        else:
            operation(config)
    assert _HostileDictionary.calls == 0


class _CollidingKey:
    calls = 0

    def __hash__(self):
        type(self).calls += 1
        return hash("configurable")

    def __eq__(self, other):
        type(self).calls += 1
        raise AssertionError("custom key equality executed")


class _StringKey(str):
    __hash__ = str.__hash__

    def __eq__(self, other):
        raise AssertionError("string-subclass equality executed")


@pytest.mark.parametrize("key", [_CollidingKey(), _StringKey("configurable")])
@pytest.mark.parametrize("position", ["config", "configurable", "context"])
def test_native_dictionary_keys_are_admitted_before_lookup(key, position):
    hostile = {key: _principal()}
    _CollidingKey.calls = 0
    config = (
        hostile
        if position == "config"
        else {"configurable": hostile}
        if position == "configurable"
        else {"configurable": {"__pregel_runtime": Runtime(context=hostile)}}
    )
    with pytest.raises(TypeError, match="plain strings"):
        principal_from(config)
    assert _CollidingKey.calls == 0


def test_sparse_native_dictionary_copy_cannot_execute_key_equality():
    class Key:
        armed = False
        calls = 0

        def __hash__(self):
            return 0

        def __eq__(self, other):
            if type(self).armed:
                type(self).calls += 1
                raise AssertionError("sparse dictionary copy invoked key equality")
            return self is other

    keys = [Key() for _ in range(100)]
    config = {key: index for index, key in enumerate(keys)}
    for key in keys[5:]:
        del config[key]
    Key.armed = True
    with pytest.raises(TypeError, match="plain strings"):
        principal_from(config)
    assert Key.calls == 0


def test_runtime_dictionary_context_remains_a_supported_identity_source():
    principal = _principal()
    runtime = Runtime(context={PRINCIPAL_CONFIG_KEY: principal})
    assert principal_from({"configurable": {"__pregel_runtime": runtime}}) is principal
    assert principal_from({"configurable": {"__pregel_runtime": Runtime()}}) is None


@pytest.mark.parametrize("operation", ["read", "bind", "bind_partial"])
def test_malformed_runtime_refusal_does_not_retain_the_receiver(operation):
    runtime = object.__new__(Runtime)
    if operation == "bind_partial":
        object.__setattr__(runtime, "context", {})
    config = {"configurable": {"__pregel_runtime": runtime}}
    with pytest.raises(TypeError, match="initialized Runtime") as caught:
        if operation == "read":
            principal_from(config)
        else:
            with_principal(config, _principal())
    assert caught.value.args == ("principal context requires an initialized Runtime",)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert not hasattr(caught.value, "obj")


def test_direct_identity_still_ignores_a_malformed_irrelevant_runtime():
    principal = _principal()
    config = {
        "configurable": {
            "__pregel_runtime": object.__new__(Runtime),
            PRINCIPAL_CONFIG_KEY: principal,
        }
    }
    assert principal_from(config) is principal


class _OpaqueRuntime:
    calls = 0

    @property
    def context(self):
        type(self).calls += 1
        raise AssertionError("opaque runtime attribute executed")


def test_fallback_runtime_identity_rejects_opaque_runtime_without_attribute_access():
    _OpaqueRuntime.calls = 0
    with pytest.raises(TypeError, match="exact Runtime"):
        principal_from({"configurable": {"__pregel_runtime": _OpaqueRuntime()}})
    assert _OpaqueRuntime.calls == 0


def test_optional_direct_identity_does_not_consult_runtime_context():
    _OpaqueRuntime.calls = 0
    config = {"configurable": {"__pregel_runtime": _OpaqueRuntime()}}
    assert principal_from(config, include_runtime_context=False) is None
    principal = _principal()
    config["configurable"][PRINCIPAL_CONFIG_KEY] = principal
    assert principal_from(config, include_runtime_context=False) is principal
    assert _OpaqueRuntime.calls == 0


@pytest.mark.parametrize("flag", [None, 0, 1, "false", _OpaqueRuntime()])
def test_runtime_context_switch_requires_an_exact_boolean(flag):
    with pytest.raises(TypeError, match="must be a boolean"):
        principal_from({}, include_runtime_context=flag)


def test_authoritative_principal_does_not_consult_an_irrelevant_runtime():
    _OpaqueRuntime.calls = 0
    principal = _principal()
    bound = with_principal(
        {"configurable": {"__pregel_runtime": _OpaqueRuntime()}}, principal
    )
    assert principal_from(bound) is principal
    assert _OpaqueRuntime.calls == 0


@pytest.mark.parametrize("context", [_HostileDictionary(), _OpaqueRuntime()])
def test_unsupported_runtime_context_cannot_establish_identity(context):
    _HostileDictionary.calls = 0
    _OpaqueRuntime.calls = 0
    with pytest.raises(TypeError, match="plain dictionary"):
        principal_from({"configurable": {"__pregel_runtime": Runtime(context=context)}})
    assert _HostileDictionary.calls == 0
    assert _OpaqueRuntime.calls == 0


def test_opaque_context_is_not_modified_by_direct_principal_binding():
    _HostileDictionary.calls = 0
    principal = _principal()
    bound = with_principal(
        {"configurable": {"__pregel_runtime": Runtime(context=_HostileDictionary())}},
        principal,
    )
    assert principal_from(bound) is principal
    assert _HostileDictionary.calls == 0


def test_malformed_binding_is_rejected_before_credential_hooks():
    class CountingModule(SecurityModule):
        name = "counting"
        calls = 0

        def cred_prepare(self, principal, slot):
            self.calls += 1

    module = CountingModule()
    with pytest.raises(TypeError, match="plain dictionary"):
        with_principal(
            {"configurable": _HostileDictionary()}, _principal(), modules=(module,)
        )
    assert module.calls == 0


def test_principal_subclass_is_not_accepted_as_authoritative_identity():
    class DerivedPrincipal(Principal):
        pass

    principal = DerivedPrincipal("alice", frozenset(), frozenset(), "session")
    with pytest.raises(TypeError, match="invalid"):
        principal_from({"configurable": {PRINCIPAL_CONFIG_KEY: principal}})
    with pytest.raises(TypeError, match="must be a Principal"):
        with_principal({}, principal)


def test_counter_instance_cannot_replace_its_atomic_next_method():
    bound = with_principal({}, _principal())
    counter = bound["configurable"]["__security_call_counter__"]
    with pytest.raises(AttributeError):
        counter.next = lambda: 0
    assert next_call_index(bound) == 0
    assert next_call_index(bound) == 1


def test_parallel_child_bindings_preserve_parent_runtime_identity():
    parent_principal = _principal()
    original = Runtime(context={"tenant": "research"})
    parent = with_principal(
        {"configurable": {"__pregel_runtime": original}}, parent_principal
    )
    children = [
        Principal(f"child-{index}", frozenset(), frozenset(), f"session-{index}")
        for index in range(20)
    ]
    with ThreadPoolExecutor(max_workers=4) as pool:
        configs = list(pool.map(lambda child: with_principal(parent, child), children))
    parent_runtime = parent["configurable"]["__pregel_runtime"]
    assert original.context == {"tenant": "research"}
    assert parent_runtime.context[PRINCIPAL_CONFIG_KEY] is parent_principal
    for config, child in zip(configs, children, strict=True):
        runtime = config["configurable"]["__pregel_runtime"]
        assert runtime is not parent_runtime
        assert runtime.context is not parent_runtime.context
        assert runtime.context[PRINCIPAL_CONFIG_KEY] is child
        assert runtime.context["tenant"] == "research"
        assert principal_from(config) is child
