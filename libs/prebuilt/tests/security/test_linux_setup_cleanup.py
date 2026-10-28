"""Real setup resources stay owned until a complete worker command is returned.

These tests build commands and force setup failures; they do not launch a
confined worker or claim activation evidence. Acquired descriptors and artifact
copies are real, including the openat2 ancestor-replacement refusal.
"""

from __future__ import annotations

import asyncio
import errno
import hashlib
import os
import shutil
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from langgraph.prebuilt.security import linux
from langgraph.prebuilt.security.enforcement import AdapterPlan


@pytest.fixture
def setup_resources(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    artifact = tmp_path / "artifact.py"
    artifact.write_text("def run(): return 'useful'\n")
    first = tmp_path / "first"
    first.write_text("useful resource")
    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()
    (allowed / "record").write_text("allowed")
    (outside / "record").write_text("outside")
    executor = object.__new__(linux.LinuxSandboxExecutor)
    executor.bubblewrap_path = "/usr/bin/bwrap"
    executor.python_executable = Path(sys.executable)
    executor._worker_script = Path(linux.__file__).with_name("_linux_worker.py")
    spec = linux.LinuxToolSpec(
        "artifact:run", artifact, hashlib.sha256(artifact.read_bytes()).hexdigest()
    )
    plan = AdapterPlan(
        linux._ADAPTER_ID,
        frozenset({"setup-test"}),
        "native-plan",
        {
            "environment": {
                "PATH": "/usr/bin",
                "PYTHONCOERCECLOCALE": "0",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONNOUSERSITE": "1",
                "PYTHONSAFEPATH": "1",
                "PYTHONUNBUFFERED": "1",
                "PYTHONUTF8": "1",
            },
            "protocol": [
                "parent-request-pipe",
                "parent-response-pipe",
                "parent-diagnostic-pipe",
            ],
            "limits": {name: 1 for name in linux._SUPPORTED_LIMITS},
            "mounts": [
                {"path": str(path), "mode": "ro"}
                for path in (artifact, first, allowed / "record")
            ],
        },
    )
    observed = SimpleNamespace(
        executor=executor,
        spec=spec,
        plan=plan,
        first=first,
        allowed=allowed,
        outside=outside,
        root=tmp_path,
        artifacts=[],
        resources=[],
        pipes=[],
        identities={},
    )
    original_artifact = linux._verified_artifact_fd
    original_resource = linux._verified_resource_fd
    original_pipe = linux.os.pipe2
    original_close = os.close

    def record(descriptor):
        info = os.fstat(descriptor)
        observed.identities[descriptor] = (info.st_dev, info.st_ino, info.st_mode)

    def artifact_fd(spec):
        descriptor, directory = original_artifact(spec)
        observed.artifacts.append((descriptor, directory))
        record(descriptor)
        return descriptor, directory

    def resource_fd(path):
        descriptor = original_resource(path)
        observed.resources.append(descriptor)
        record(descriptor)
        return descriptor

    def pipe(flags):
        result = original_pipe(flags)
        observed.pipes.extend(result)
        for descriptor in result:
            record(descriptor)
        return result

    monkeypatch.setattr(linux, "_verified_artifact_fd", artifact_fd)
    monkeypatch.setattr(linux, "_verified_resource_fd", resource_fd)
    monkeypatch.setattr(linux.os, "pipe2", pipe)
    try:
        yield observed
    finally:
        # Failed before-repair observations must not leak into another test.
        for descriptor, identity in observed.identities.items():
            try:
                info = os.fstat(descriptor)
            except OSError:
                continue
            if (info.st_dev, info.st_ino, info.st_mode) == identity:
                original_close(descriptor)
        for _, directory in observed.artifacts:
            if directory.exists():
                shutil.rmtree(directory)


def _assert_released(observed) -> None:
    assert observed.artifacts, "the test must acquire a real copied artifact"
    for descriptor in observed.identities:
        with pytest.raises(OSError, match="Bad file descriptor"):
            os.fstat(descriptor)
    assert all(not directory.exists() for _, directory in observed.artifacts)


def test_ancestor_race_refusal_releases_previously_acquired_resources(
    setup_resources, monkeypatch
):
    """A real late openat2 refusal must unwind the preceding useful opens."""
    observed = setup_resources
    canonical = linux._canonical_existing_path

    def replace_ancestor(path):
        checked = canonical(path)
        if checked == observed.allowed / "record":
            observed.allowed.rename(observed.root / "moved")
            observed.allowed.symlink_to(observed.outside, target_is_directory=True)
        return checked

    monkeypatch.setattr(linux, "_canonical_existing_path", replace_ancestor)
    with pytest.raises(OSError) as caught:
        observed.executor._worker_command(observed.plan, observed.spec, None)
    assert caught.value.errno == errno.ELOOP
    assert observed.resources, "at least one previous resource must have opened"
    _assert_released(observed)


@pytest.mark.parametrize(
    "error_type",
    [OSError, KeyboardInterrupt, SystemExit, GeneratorExit, asyncio.CancelledError],
)
def test_resource_setup_base_exception_releases_owned_handles(
    setup_resources, monkeypatch, error_type
):
    observed = setup_resources
    resource = linux._verified_resource_fd
    failure = error_type("controlled setup interruption")

    def fail_late(path):
        if path == observed.allowed / "record":
            raise failure
        return resource(path)

    monkeypatch.setattr(linux, "_verified_resource_fd", fail_late)
    with pytest.raises(error_type) as caught:
        observed.executor._worker_command(observed.plan, observed.spec, None)
    assert caught.value is failure
    assert observed.resources
    _assert_released(observed)


def test_pipe_allocation_failure_releases_existing_resources(
    setup_resources, monkeypatch
):
    observed = setup_resources
    failure = OSError(errno.EMFILE, "controlled descriptor exhaustion")

    def unavailable(flags):
        raise failure

    monkeypatch.setattr(linux.os, "pipe2", unavailable)
    with pytest.raises(OSError) as caught:
        observed.executor._worker_command(observed.plan, observed.spec, None)
    assert caught.value is failure
    assert observed.resources
    _assert_released(observed)


@pytest.mark.parametrize("error_type", [ValueError, KeyboardInterrupt])
def test_failure_after_pipe_creation_also_closes_status_pipe(
    setup_resources, error_type
):
    observed = setup_resources
    failure = error_type("controlled command assembly interruption")

    class InvalidPath:
        def __fspath__(self):
            raise failure

    # This deliberately invalid controller configuration fails after pipe2.
    observed.executor._worker_script = InvalidPath()
    with pytest.raises(error_type) as caught:
        observed.executor._worker_command(observed.plan, observed.spec, None)
    assert caught.value is failure
    assert len(observed.pipes) == 2
    _assert_released(observed)


@pytest.mark.parametrize("duplicate_artifact", [False, True])
def test_success_transfers_each_used_descriptor_once(
    setup_resources, duplicate_artifact
):
    observed = setup_resources
    plan = observed.plan
    if duplicate_artifact:
        mounts = (*plan.payload["mounts"], plan.payload["mounts"][0])
        plan = replace(plan, payload={**plan.payload, "mounts": mounts})
    command, inherited, read_fd, write_fd, directory = (
        observed.executor._worker_command(plan, observed.spec, None)
    )
    assert command[0] == observed.executor.bubblewrap_path
    assert len(inherited) == len(set(inherited))
    assert observed.artifacts[0][0] in inherited
    assert set(observed.resources) <= set(inherited)
    for descriptor in (*inherited, read_fd, write_fd):
        os.fstat(descriptor)
        assert not os.get_inheritable(descriptor)
    artifact_fd = observed.artifacts[0][0]
    assert (
        Path(f"/proc/self/fd/{artifact_fd}").read_bytes()
        == observed.spec.artifact_path.read_bytes()
    )
    resource_fd = observed.resources[0]
    assert Path(f"/proc/self/fd/{resource_fd}").read_text() == "useful resource"
    os.write(write_fd, b"status")
    assert os.read(read_fd, 6) == b"status"
    # Simulate the caller accepting and then disposing of transferred ownership.
    for descriptor in (*inherited, read_fd, write_fd):
        os.close(descriptor)
    linux._remove_private_artifact(directory)
    _assert_released(observed)


def test_unused_artifact_descriptor_is_closed_before_success_transfer(setup_resources):
    observed = setup_resources
    plan = replace(
        observed.plan,
        payload={
            **observed.plan.payload,
            "mounts": observed.plan.payload["mounts"][1:],
        },
    )
    _, inherited, read_fd, write_fd, directory = observed.executor._worker_command(
        plan, observed.spec, None
    )
    artifact_fd = observed.artifacts[0][0]
    assert artifact_fd not in inherited
    with pytest.raises(OSError, match="Bad file descriptor"):
        os.fstat(artifact_fd)
    for descriptor in (*inherited, read_fd, write_fd):
        os.close(descriptor)
    linux._remove_private_artifact(directory)
    _assert_released(observed)


@pytest.mark.parametrize("error_type", [OSError, KeyboardInterrupt])
def test_cleanup_continues_after_close_error_without_closing_reused_number(
    setup_resources, monkeypatch, error_type
):
    """A reported close error cannot justify retrying a now-reused descriptor."""
    observed = setup_resources
    original_close = os.close
    replacement = os.open(observed.first, os.O_RDONLY | os.O_CLOEXEC)
    closed = []
    reused = []
    failure = ValueError("original setup failure")

    class InvalidPath:
        def __fspath__(self):
            raise failure

    def close_then_fail(descriptor):
        original_close(descriptor)
        if descriptor in observed.identities:
            closed.append(descriptor)
            if not reused:
                # Linux releases an FD number even for some reported close
                # errors. Force reuse before returning that error to cleanup.
                os.dup2(replacement, descriptor, inheritable=False)
                reused.append(descriptor)
                raise error_type("controlled failure after descriptor release")

    observed.executor._worker_script = InvalidPath()
    try:
        with monkeypatch.context() as patch:
            patch.setattr(linux.os, "close", close_then_fail)
            with pytest.raises(ValueError) as caught:
                observed.executor._worker_command(observed.plan, observed.spec, None)
        assert caught.value is failure
        assert set(closed) == set(observed.identities)
        assert len(closed) == len(set(closed))
        assert len(reused) == 1
        assert os.fstat(reused[0]).st_ino == observed.first.stat().st_ino
        assert all(not directory.exists() for _, directory in observed.artifacts)
        for descriptor in set(observed.identities) - set(reused):
            with pytest.raises(OSError, match="Bad file descriptor"):
                os.fstat(descriptor)
    finally:
        original_close(replacement)
        for descriptor in reused:
            original_close(descriptor)


@pytest.mark.parametrize("phase", ["directory_permissions", "copy_fsync"])
def test_artifact_copy_base_exception_removes_private_directory(
    setup_resources, monkeypatch, phase
):
    observed = setup_resources
    created = []
    original_mkdtemp = linux.tempfile.mkdtemp
    original_chmod = Path.chmod
    failure = KeyboardInterrupt("controlled artifact setup interruption")

    def directory(*args, **kwargs):
        path = original_mkdtemp(*args, **kwargs)
        created.append(Path(path))
        return path

    def chmod(path, *args, **kwargs):
        if phase == "directory_permissions" and path in created:
            raise failure
        return original_chmod(path, *args, **kwargs)

    def fsync(descriptor):
        raise failure

    monkeypatch.setattr(linux.tempfile, "mkdtemp", directory)
    monkeypatch.setattr(Path, "chmod", chmod)
    if phase == "copy_fsync":
        monkeypatch.setattr(linux.os, "fsync", fsync)
    try:
        with pytest.raises(KeyboardInterrupt) as caught:
            observed.executor._worker_command(observed.plan, observed.spec, None)
        assert caught.value is failure
        assert created
        assert all(not path.exists() for path in created)
        assert not observed.identities
    finally:
        for path in created:
            if path.exists():
                shutil.rmtree(path)


def test_outer_artifact_removal_error_preserves_original_setup_failure(
    setup_resources, monkeypatch
):
    observed = setup_resources
    failure = ValueError("original setup failure")
    attempted = []

    class InvalidPath:
        def __fspath__(self):
            raise failure

    def remove(directory):
        attempted.append(directory)
        raise OSError("controlled artifact removal failure")

    observed.executor._worker_script = InvalidPath()
    monkeypatch.setattr(linux, "_remove_private_artifact", remove)
    with pytest.raises(ValueError) as caught:
        observed.executor._worker_command(observed.plan, observed.spec, None)
    assert caught.value is failure
    assert attempted == [observed.artifacts[0][1]]
    for descriptor in observed.identities:
        with pytest.raises(OSError, match="Bad file descriptor"):
            os.fstat(descriptor)
    # A failed deletion is not proof of deletion; the fixture removes this
    # deliberately retained residue only after the observation is asserted.
    assert attempted[0].exists()


@pytest.mark.parametrize("cleanup_error", [OSError, KeyboardInterrupt])
def test_resource_helper_cleanup_error_does_not_mask_original_failure(
    setup_resources, monkeypatch, cleanup_error
):
    observed = setup_resources
    original_open = linux.open_path_descriptor
    original_stat = os.fstat
    original_close = os.close
    helper_fds = []
    failure = ValueError("original resource inspection failure")

    def open_descriptor(path, **kwargs):
        descriptor = original_open(path, **kwargs)
        if path == str(observed.allowed / "record"):
            helper_fds.append(descriptor)
        return descriptor

    def stat(descriptor):
        if descriptor in helper_fds:
            raise failure
        return original_stat(descriptor)

    def close(descriptor):
        original_close(descriptor)
        if descriptor in helper_fds:
            raise cleanup_error("controlled helper close failure")

    with monkeypatch.context() as patch:
        patch.setattr(linux, "open_path_descriptor", open_descriptor)
        patch.setattr(linux.os, "fstat", stat)
        patch.setattr(linux.os, "close", close)
        with pytest.raises(ValueError) as caught:
            observed.executor._worker_command(observed.plan, observed.spec, None)
    assert caught.value is failure
    assert helper_fds
    for descriptor in helper_fds:
        with pytest.raises(OSError, match="Bad file descriptor"):
            original_stat(descriptor)
    _assert_released(observed)


def test_artifact_helper_cleanup_error_does_not_mask_copy_failure(
    setup_resources, monkeypatch
):
    observed = setup_resources
    created = []
    attempted = []
    original_mkdtemp = linux.tempfile.mkdtemp
    failure = KeyboardInterrupt("original artifact copy failure")

    def directory(*args, **kwargs):
        path = original_mkdtemp(*args, **kwargs)
        created.append(Path(path))
        return path

    def fsync(descriptor):
        raise failure

    def remove(path):
        attempted.append(path)
        raise OSError("controlled helper artifact removal failure")

    monkeypatch.setattr(linux.tempfile, "mkdtemp", directory)
    monkeypatch.setattr(linux.os, "fsync", fsync)
    monkeypatch.setattr(linux, "_remove_private_artifact", remove)
    try:
        with pytest.raises(KeyboardInterrupt) as caught:
            observed.executor._worker_command(observed.plan, observed.spec, None)
        assert caught.value is failure
        assert attempted == created
        assert created
        assert all(path.exists() for path in created)
        assert not observed.identities
    finally:
        for path in created:
            if path.exists():
                shutil.rmtree(path)
