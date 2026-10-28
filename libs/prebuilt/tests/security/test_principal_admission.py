"""Principal transport cannot smuggle executable credential-container protocols."""

from threading import Lock

import pytest

from langgraph.prebuilt.security import Principal, SecurityModule
from langgraph.prebuilt.security.binding import principal_from, with_principal
from langgraph.prebuilt.security.types import Blobs, Slot


def principal():
    return Principal("alice", frozenset({"analyst"}), frozenset({"read"}), "session")


def admit(value, entry):
    if entry == "bind":
        return with_principal({}, value)
    return principal_from({"configurable": {"__principal__": value}})


class Opaque:
    calls = 0

    def __bool__(self):
        type(self).calls += 1
        raise AssertionError("opaque truthiness executed")

    def __iter__(self):
        type(self).calls += 1
        raise AssertionError("opaque iteration executed")

    def __hash__(self):
        type(self).calls += 1
        return 0

    def __eq__(self, other):
        type(self).calls += 1
        raise AssertionError("opaque equality executed")

    def allocate(self, name):
        type(self).calls += 1
        raise AssertionError("opaque allocation executed")

    def __enter__(self):
        type(self).calls += 1
        raise AssertionError("opaque lock executed")

    def __exit__(self, *args):
        type(self).calls += 1
        raise AssertionError("opaque lock executed")


class StringSubclass(str):
    def __bool__(self):
        raise AssertionError("string-subclass truthiness executed")


class SetSubclass(frozenset):
    def __iter__(self):
        raise AssertionError("set-subclass iteration executed")


class MappingSubclass(dict):
    def items(self):
        raise AssertionError("mapping-subclass items executed")


@pytest.mark.parametrize("entry", ["bind", "read"])
@pytest.mark.parametrize(
    "field,value",
    [
        ("user_id", Opaque()),
        ("user_id", StringSubclass("alice")),
        ("user_id", ""),
        ("session_id", Opaque()),
        ("session_id", ""),
        ("delegated_by", Opaque()),
        ("delegated_by", StringSubclass("parent")),
        ("roles", Opaque()),
        ("roles", SetSubclass({"analyst"})),
        ("roles", frozenset({StringSubclass("analyst")})),
        ("roles", frozenset({Opaque()})),
        ("scopes", ["read"]),
        ("scopes", frozenset({Opaque()})),
        ("security", Opaque()),
    ],
)
def test_non_native_principal_fields_are_refused_before_their_protocols(
    entry, field, value
):
    candidate = principal()
    object.__setattr__(candidate, field, value)
    Opaque.calls = 0
    with pytest.raises(TypeError, match="invalid"):
        admit(candidate, entry)
    assert Opaque.calls == 0


@pytest.mark.parametrize("entry", ["bind", "read"])
@pytest.mark.parametrize(
    "target,field,value",
    [
        ("blobs", "_lock", Opaque()),
        ("blobs", "_lock", Lock()),
        ("blobs", "_slots", MappingSubclass()),
        ("blobs", "_slots", {"module": Opaque()}),
        ("slot", "_lock", Opaque()),
        ("slot", "_lock", Lock()),
        ("slot", "_values", MappingSubclass()),
        ("slot", "_values", {StringSubclass("key"): "value"}),
    ],
)
def test_nested_credentials_require_exact_containers_and_native_reentrant_locks(
    entry, target, field, value
):
    candidate = principal()
    slot = candidate.security.allocate("module")
    setattr(candidate.security if target == "blobs" else slot, field, value)
    Opaque.calls = 0
    with pytest.raises(TypeError, match="invalid"):
        admit(candidate, entry)
    assert Opaque.calls == 0


@pytest.mark.parametrize("entry", ["bind", "read"])
@pytest.mark.parametrize("target", ["blobs", "slot"])
def test_credential_subclasses_are_not_accepted(entry, target):
    class DerivedBlobs(Blobs):
        def allocate(self, name):
            raise AssertionError("custom credential allocation executed")

    class DerivedSlot(Slot):
        def __getitem__(self, key):
            raise AssertionError("custom slot access executed")

    candidate = principal()
    if target == "blobs":
        object.__setattr__(candidate, "security", DerivedBlobs())
    else:
        candidate.security._slots["module"] = DerivedSlot()
    with pytest.raises(TypeError, match="invalid"):
        admit(candidate, entry)


@pytest.mark.parametrize("target", ["principal", "blobs", "slot"])
def test_uninitialized_native_objects_fail_closed(target):
    candidate = principal()
    if target == "principal":
        candidate = object.__new__(Principal)
    elif target == "blobs":
        object.__setattr__(candidate, "security", object.__new__(Blobs))
    else:
        candidate.security._slots["module"] = object.__new__(Slot)
    with pytest.raises(TypeError, match="missing") as caught:
        with_principal({}, candidate)
    assert caught.value.args == ("invalid missing principal fields",)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert not hasattr(caught.value, "obj")


@pytest.mark.parametrize("target", ["blobs", "slot"])
def test_sparse_native_credential_keys_are_never_rehashed_during_admission(target):
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
                raise AssertionError("credential key equality executed")
            return self is other

    keys = [Key() for _ in range(100)]
    values = {key: Slot() for key in keys}
    for key in keys[5:]:
        del values[key]
    candidate = principal()
    if target == "blobs":
        candidate.security._slots = values
    else:
        candidate.security.allocate("module")._values = values
    Key.armed = True
    with pytest.raises(TypeError, match="invalid"):
        with_principal({}, candidate)
    assert Key.calls == 0


def test_opaque_policy_payload_values_remain_shared_and_are_not_inspected():
    value = Opaque()
    candidate = principal()
    candidate.security.allocate("module")["value"] = value
    Opaque.calls = 0
    bound = with_principal({}, candidate)
    assert principal_from(bound) is candidate
    assert candidate.security["module"]["value"] is value
    assert Opaque.calls == 0


@pytest.mark.parametrize("following_hook", [False, True])
def test_corrupted_credentials_are_rejected_before_another_hook_or_binding_return(
    following_hook,
):
    opaque = Opaque()

    class Poison(SecurityModule):
        name = "poison"

        def cred_prepare(self, principal, slot):
            object.__setattr__(principal, "security", opaque)

    class Following(SecurityModule):
        name = "following"
        calls = 0

        def cred_prepare(self, principal, slot):
            self.calls += 1

    following = Following()
    modules = (Poison(), following) if following_hook else (Poison(),)
    Opaque.calls = 0
    with pytest.raises(TypeError, match="invalid"):
        with_principal({}, principal(), modules=modules)
    assert following.calls == 0
    assert Opaque.calls == 0


def test_existing_binding_is_revalidated_when_its_native_shape_changes():
    bound = with_principal({}, principal())
    candidate = principal_from(bound)
    candidate.security._slots = MappingSubclass()
    with pytest.raises(TypeError, match="invalid"):
        principal_from(bound)


def test_direct_only_lookup_still_validates_nested_credentials():
    candidate = principal()
    object.__setattr__(candidate, "security", Opaque())
    Opaque.calls = 0
    with pytest.raises(TypeError, match="invalid"):
        principal_from(
            {"configurable": {"__principal__": candidate}},
            include_runtime_context=False,
        )
    assert Opaque.calls == 0
