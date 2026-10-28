"""Cleanup signals a bound kernel handle, never a reusable numeric PID."""

from __future__ import annotations

import errno
import os
import subprocess
import sys
from pathlib import Path

import pytest

from langgraph.prebuilt.security import linux


@pytest.fixture
def child():
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        yield process
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=3)


def test_real_child_exit_is_confirmed_without_numeric_signal(child, monkeypatch):
    start = linux._process_start_time(child.pid)

    def numeric_signal(*args):
        raise AssertionError("numeric PID signal can target a replacement process")

    with monkeypatch.context() as patch:
        patch.setattr(linux.os, "kill", numeric_signal)
        assert linux._confirm_worker_terminated(child.pid, start, timeout_s=2)
    assert child.wait(timeout=1) == -9


def test_changed_identity_is_not_signaled_and_handle_is_closed(child, monkeypatch):
    opened = []
    original = linux._open_worker_pidfd

    def capture(pid):
        descriptor = original(pid)
        opened.append(descriptor)
        return descriptor

    def signal(*args):
        raise AssertionError("a changed identity must not be signaled")

    monkeypatch.setattr(linux, "_open_worker_pidfd", capture)
    monkeypatch.setattr(linux, "_kill_worker_pidfd", signal)
    assert linux._confirm_worker_terminated(child.pid, "wrong-start", timeout_s=0.2)
    assert child.poll() is None
    assert len(opened) == 1
    with pytest.raises(OSError, match="Bad file descriptor"):
        os.fstat(opened[0])


def test_handle_is_acquired_before_identity_recheck(child, monkeypatch):
    original_open = linux._open_worker_pidfd
    original_start = linux._process_start_time
    start = original_start(child.pid)
    captured = []

    def open_handle(pid):
        descriptor = original_open(pid)
        captured.append(descriptor)
        return descriptor

    def read_start(pid):
        assert captured, "identity check must follow handle acquisition"
        return original_start(pid)

    monkeypatch.setattr(linux, "_open_worker_pidfd", open_handle)
    monkeypatch.setattr(linux, "_process_start_time", read_start)
    assert linux._confirm_worker_terminated(child.pid, start, timeout_s=2)
    assert child.wait(timeout=1) == -9


@pytest.mark.parametrize("operation", ["_open_worker_pidfd", "_kill_worker_pidfd"])
@pytest.mark.parametrize("error", [errno.ENOSYS, errno.EPERM, errno.EMFILE])
def test_unavailable_handles_or_signals_do_not_confirm_cleanup(
    child, monkeypatch, operation, error
):
    start = linux._process_start_time(child.pid)

    def fail(*args):
        raise OSError(error, "controlled unavailable kernel operation")

    monkeypatch.setattr(linux, operation, fail)
    assert not linux._confirm_worker_terminated(child.pid, start, timeout_s=0.01)
    assert child.poll() is None


def test_missing_process_is_already_terminated(monkeypatch):
    def missing(pid):
        raise ProcessLookupError(errno.ESRCH, "process no longer exists")

    monkeypatch.setattr(linux, "_open_worker_pidfd", missing)
    assert linux._confirm_worker_terminated(123, "100", timeout_s=0.1)


@pytest.mark.parametrize("comm", ["python", "has spaces", "has)close", "line\nbreak)"])
def test_process_identity_parser_handles_parenthesized_comm(comm, monkeypatch):
    # Fields after comm start at field 3; starttime is field 22.
    record = f"123 ({comm}) " + " ".join(["S"] + ["0"] * 18 + ["456", "0"])
    monkeypatch.setattr(Path, "read_text", lambda *args, **kwargs: record)
    assert linux._process_start_time(123) == "456"


@pytest.mark.parametrize(
    "record",
    [
        "",
        "456 (wrong-pid) S 1",
        "123 (short) S 1",
        "123 (bad) " + " ".join(["0"] * 19 + ["１２"]),
    ],
)
def test_process_identity_parser_rejects_malformed_fields(record, monkeypatch):
    monkeypatch.setattr(Path, "read_text", lambda *args, **kwargs: record)
    with pytest.raises(ValueError, match="invalid_process_identity"):
        linux._process_start_time(123)


def test_poll_error_does_not_certify_exit(child, monkeypatch):
    start = linux._process_start_time(child.pid)

    class Poll:
        def register(self, descriptor, flags):
            self.descriptor = descriptor

        def poll(self, timeout):
            return [(self.descriptor, linux.select.POLLERR)]

    monkeypatch.setattr(linux, "_kill_worker_pidfd", lambda descriptor: None)
    monkeypatch.setattr(linux.select, "poll", Poll)
    assert not linux._confirm_worker_terminated(child.pid, start, timeout_s=0.1)
    assert child.poll() is None
