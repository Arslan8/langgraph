"""Authority changes and uncertain cleanup must never reuse old state."""

from dataclasses import replace
from subprocess import CompletedProcess, TimeoutExpired

import pytest

from langgraph.prebuilt.security._container_lifecycle import (
    ContainerCleanupError,
    ContainerIdentity,
    ContainerLifecycle,
    DockerContainerRuntime,
)

IDENTITY = ContainerIdentity(*("a" * 64 for _ in range(5)))


class Runtime:
    def __init__(self):
        self.created = []
        self.removed = []
        self.valid = True
        self.removal = True
        self.fail_create = False

    def create(self, name, identity):
        self.created.append((name, identity))
        if self.fail_create:
            raise TimeoutError("daemon reply lost after creation")
        return "b" * 64

    def matches(self, container_id, identity):
        return self.valid

    def destroy(self, name):
        self.removed.append(name)
        return self.removal


@pytest.mark.parametrize(
    "field",
    [
        "principal_digest",
        "policy_digest",
        "grant_digest",
        "runtime_digest",
        "native_plan_digest",
    ],
)
def test_every_identity_change_recreates(field):
    runtime = Runtime()
    lifecycle = ContainerLifecycle(runtime)
    with lifecycle.lease(IDENTITY) as first:
        assert not first.reused
    with lifecycle.lease(IDENTITY) as same:
        assert same.reused
        assert same.name == first.name
    with lifecycle.lease(replace(IDENTITY, **{field: "c" * 64})) as changed:
        assert not changed.reused
        assert changed.name != first.name
        assert runtime.removed == [first.name]
    lifecycle.close()
    assert runtime.removed == [first.name, changed.name]


def test_failed_destruction_quarantines_even_identical_identity():
    runtime = Runtime()
    lifecycle = ContainerLifecycle(runtime)
    with pytest.raises(ContainerCleanupError):
        with lifecycle.lease(IDENTITY):
            runtime.removal = False
            raise TimeoutError("execution outcome uncertain")
    for identity in [IDENTITY, replace(IDENTITY, grant_digest="c" * 64)]:
        with pytest.raises(ContainerCleanupError):
            with lifecycle.lease(identity):
                pytest.fail("quarantined container was reused")
    assert len(runtime.created) == 1
    runtime.removal = True
    with lifecycle.lease(IDENTITY) as lease:
        assert not lease.reused
    assert len(runtime.created) == 2
    lifecycle.close()


def test_uncertain_creation_is_removed_before_retry():
    runtime = Runtime()
    runtime.fail_create = True
    runtime.removal = False
    lifecycle = ContainerLifecycle(runtime)
    with pytest.raises(ContainerCleanupError):
        with lifecycle.lease(IDENTITY):
            pytest.fail("creation failed")
    runtime.fail_create = False
    with pytest.raises(ContainerCleanupError):
        with lifecycle.lease(IDENTITY):
            pytest.fail("cleanup is unresolved")
    assert len(runtime.created) == 1
    runtime.removal = True
    lifecycle.close()


def test_backend_exception_remains_unconfirmed_and_quarantined(monkeypatch):
    runtime = Runtime()
    lifecycle = ContainerLifecycle(runtime)
    original = runtime.destroy

    def broken_destroy(name):
        raise RuntimeError("unexpected backend failure")

    with pytest.raises(ContainerCleanupError) as caught:
        with lifecycle.lease(IDENTITY):
            monkeypatch.setattr(runtime, "destroy", broken_destroy)
            raise TimeoutError("worker still running")
    assert isinstance(caught.value.__cause__, RuntimeError)
    with pytest.raises(ContainerCleanupError):
        with lifecycle.lease(IDENTITY):
            pytest.fail("quarantined container was reused")
    assert len(runtime.created) == 1
    monkeypatch.setattr(runtime, "destroy", original)
    lifecycle.close()


def test_nested_use_and_close_are_rejected():
    lifecycle = ContainerLifecycle(Runtime())
    with lifecycle.lease(IDENTITY):
        with pytest.raises(RuntimeError, match="Nested"):
            with lifecycle.lease(IDENTITY):
                pass
        with pytest.raises(RuntimeError, match="active"):
            lifecycle.close()
    lifecycle.close()


@pytest.mark.parametrize("remaining,expected", [("", True), ("b" * 64, False)])
def test_lost_removal_reply_requires_successful_absence_query(remaining, expected):
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        if command[1] == "rm":
            raise TimeoutExpired(command, 1)
        return CompletedProcess(command, 0, remaining, "")

    runtime = DockerContainerRuntime(lambda identity: (), run=run)
    assert runtime.destroy("slg-session-" + "a" * 32) is expected
    assert [call[1] for call in calls] == ["rm", "ps"]


def test_daemon_failure_is_not_absence():
    runtime = DockerContainerRuntime(
        lambda identity: (),
        run=lambda command, **kwargs: CompletedProcess(
            command, 1, "", "daemon unavailable"
        ),
    )
    assert not runtime.destroy("slg-session-" + "a" * 32)
