"""Real pathname swaps cannot redirect an admitted file terminal's descriptor."""

import errno
import os
import sys
from contextlib import contextmanager
from pathlib import Path

import pytest

from langgraph.prebuilt.security import HostExecutionDenied, Requirement, inprocess
from langgraph.prebuilt.security.object_policy import (
    EnforcementKind,
    ObjectGrant,
    ObjectGrantLine,
)


@contextmanager
def grant_for(path):
    line = ObjectGrantLine(
        "read",
        "fs",
        "read",
        str(path),
        {},
        Requirement.NEED,
        EnforcementKind.LANGUAGE_SANDBOX,
    )
    token = inprocess._active_grant.set(
        ObjectGrant("alice", "reader", "call", "policy", (line,))
    )
    try:
        yield
    finally:
        inprocess._active_grant.reset(token)


def _legacy_read(path):
    """Replay the former resolve/check/path-open sequence for a bounded witness."""
    canonical = str(Path(path).resolve(strict=True))
    grant = inprocess._active_grant.get()
    assert grant is not None
    assert any(
        line.class_name == "fs"
        and line.operation == "read"
        and line.selector == canonical
        for line in grant.lines
    )
    return Path(canonical).read_text(encoding="utf-8")


def _paths(root):
    directory = root / "allowed"
    directory.mkdir(parents=True)
    path = directory / "value"
    path.write_text("allowed value")
    denied = root / "denied"
    denied.mkdir()
    secret = denied / "value"
    secret.write_text("outside grant")
    return path, secret


def _swap(path, secret, component):
    if component == "leaf":
        path.unlink()
        path.symlink_to(secret)
    else:
        parent = path.parent
        parent.rename(parent.with_name("parked"))
        parent.symlink_to(secret.parent, target_is_directory=True)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux descriptor primitive")
@pytest.mark.parametrize("component", ["leaf", "ancestor"])
def test_preopen_symlink_swap_reproduces_old_read_and_is_now_refused(
    tmp_path, monkeypatch, component
):
    resolve = Path.resolve
    observations = []
    for name, reader in (("legacy", _legacy_read), ("repaired", inprocess.read_text)):
        path, secret = _paths(tmp_path / name)
        swapped = False

        def resolve_then_swap(candidate, *args, **kwargs):
            nonlocal swapped
            canonical = resolve(candidate, *args, **kwargs)
            if candidate == path and not swapped:
                swapped = True
                # This is a real namespace mutation at the check/open boundary;
                # neither the kernel open nor its denial is mocked.
                _swap(path, secret, component)
            return canonical

        with monkeypatch.context() as patch, grant_for(path):
            patch.setattr(Path, "resolve", resolve_then_swap)
            if name == "legacy":
                observations.append(reader(str(path)))
            else:
                with pytest.raises(
                    HostExecutionDenied, match="descriptor_read_unavailable"
                ):
                    reader(str(path))
            assert swapped
    assert observations == ["outside grant"]


@pytest.mark.skipif(sys.platform != "linux", reason="Linux descriptor primitive")
@pytest.mark.parametrize("component", ["leaf", "ancestor"])
def test_postpin_symlink_swap_keeps_the_granted_object(
    tmp_path, monkeypatch, component
):
    path, secret = _paths(tmp_path)
    pin = inprocess.open_path_descriptor
    pinned = []

    def pin_then_swap(value, **kwargs):
        descriptor = pin(value, **kwargs)
        pinned.append(descriptor)
        _swap(path, secret, component)
        return descriptor

    monkeypatch.setattr(inprocess, "open_path_descriptor", pin_then_swap)
    with grant_for(path):
        assert inprocess.read_text(str(path)) == "allowed value"
    assert Path(path).read_text() == "outside grant"
    for descriptor in pinned:
        with pytest.raises(OSError, match="Bad file descriptor"):
            os.fstat(descriptor)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux descriptor primitive")
def test_initial_alias_to_an_authorized_canonical_target_preserves_useful_read(
    tmp_path,
):
    path, _ = _paths(tmp_path)
    alias = tmp_path / "alias"
    alias.symlink_to(path)
    path.write_text("allowed UTF-8: café")
    with grant_for(path):
        assert inprocess.read_text(str(alias)) == "allowed UTF-8: café"


@pytest.mark.skipif(sys.platform != "linux", reason="Linux descriptor primitive")
@pytest.mark.parametrize("kind", ["directory", "fifo"])
def test_nonregular_objects_are_rejected_before_read_open(tmp_path, monkeypatch, kind):
    path = tmp_path / "object"
    if kind == "directory":
        path.mkdir()
    else:
        os.mkfifo(path)
    native_open = os.open

    def checked_open(value, flags, *args, **kwargs):
        assert not str(value).startswith("/proc/self/fd/")
        return native_open(value, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", checked_open)
    with (
        grant_for(path),
        pytest.raises(HostExecutionDenied, match="regular_file_required"),
    ):
        inprocess.read_text(str(path))


@pytest.mark.parametrize("unsupported", ["platform", "openat2"])
def test_unsupported_descriptor_mechanism_has_no_pathname_read_fallback(
    tmp_path, monkeypatch, unsupported
):
    path, _ = _paths(tmp_path)

    def unavailable(*args, **kwargs):
        raise OSError(errno.ENOSYS, "unavailable")

    def forbidden_path_read(*args, **kwargs):
        raise AssertionError("pathname fallback used")

    monkeypatch.setattr(Path, "read_text", forbidden_path_read)
    if unsupported == "platform":
        monkeypatch.setattr(sys, "platform", "unsupported")
    else:
        monkeypatch.setattr(inprocess, "open_path_descriptor", unavailable)
    with (
        grant_for(path),
        pytest.raises(
            HostExecutionDenied,
            match="descriptor_read_unsupported|descriptor_read_unavailable",
        ),
    ):
        inprocess.read_text(str(path))


@pytest.mark.skipif(sys.platform != "linux", reason="Linux descriptor primitive")
@pytest.mark.parametrize("failure", ["decode", "reopen", "identity"])
def test_both_owned_descriptors_close_on_failed_read(tmp_path, monkeypatch, failure):
    path, secret = _paths(tmp_path)
    if failure == "decode":
        path.write_bytes(b"granted-file-secret\xff")
    pin = inprocess.open_path_descriptor
    native_open = os.open
    owned = []

    def tracked_pin(*args, **kwargs):
        descriptor = pin(*args, **kwargs)
        owned.append(descriptor)
        return descriptor

    def controlled_open(value, flags, *args, **kwargs):
        if str(value).startswith("/proc/self/fd/"):
            if failure == "reopen":
                raise OSError(errno.EACCES, "denied")
            if failure == "identity":
                value = secret
            descriptor = native_open(value, flags, *args, **kwargs)
            owned.append(descriptor)
            return descriptor
        return native_open(value, flags, *args, **kwargs)

    monkeypatch.setattr(inprocess, "open_path_descriptor", tracked_pin)
    monkeypatch.setattr(os, "open", controlled_open)
    with grant_for(path), pytest.raises(HostExecutionDenied) as error:
        inprocess.read_text(str(path))
    if failure == "decode":
        assert error.value.args == ("inprocess:invalid_text_encoding",)
        assert error.value.__context__ is None
        assert error.value.__cause__ is None
        assert "granted-file-secret" not in repr(error.value)
    assert len(owned) == (1 if failure == "reopen" else 2)
    for descriptor in owned:
        with pytest.raises(OSError, match="Bad file descriptor"):
            os.fstat(descriptor)


def test_missing_grant_is_refused_before_any_filesystem_resolution(monkeypatch):
    def forbidden_resolve(*args, **kwargs):
        raise AssertionError("unauthorized path resolution")

    monkeypatch.setattr(Path, "resolve", forbidden_resolve)
    with pytest.raises(HostExecutionDenied, match="resource_not_granted"):
        inprocess.read_text("untrusted")
