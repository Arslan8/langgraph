"""Trusted startup shim for the Linux sandbox executor.

This module is an implementation detail. It applies resource and syscall
restrictions before importing the operator-selected tool entry point.
"""

from __future__ import annotations

import asyncio
import contextlib
import ctypes
import errno
import inspect
import io
import json
import os
import resource
import sys
from collections.abc import Mapping
from types import ModuleType
from typing import Any

_MAX_FRAME = 1_048_576
_ALLOWED_SYSCALLS = (
    "access",
    "arch_prctl",
    "brk",
    "clock_gettime",
    "clock_nanosleep",
    "close",
    "dup",
    "dup2",
    "dup3",
    "epoll_create1",
    "epoll_ctl",
    "epoll_pwait",
    "epoll_wait",
    "eventfd2",
    "exit",
    "exit_group",
    "faccessat",
    "faccessat2",
    "fcntl",
    "fdatasync",
    "fstat",
    "fsync",
    "ftruncate",
    "futex",
    "getcwd",
    "getdents64",
    "getegid",
    "geteuid",
    "getgid",
    "getpid",
    "getppid",
    "getrandom",
    "gettid",
    "getuid",
    "lseek",
    "madvise",
    "mkdir",
    "mkdirat",
    "mmap",
    "mprotect",
    "mremap",
    "munmap",
    "nanosleep",
    "newfstatat",
    "open",
    "openat",
    "pipe",
    "pipe2",
    "poll",
    "ppoll",
    "pread64",
    "prlimit64",
    "pselect6",
    "read",
    "readlink",
    "readlinkat",
    "readv",
    "restart_syscall",
    "rmdir",
    "rseq",
    "rt_sigaction",
    "rt_sigprocmask",
    "rt_sigreturn",
    "sched_getaffinity",
    "sched_yield",
    "select",
    "set_robust_list",
    "set_tid_address",
    "sigaltstack",
    "stat",
    "statx",
    "sysinfo",
    "truncate",
    "uname",
    "unlink",
    "unlinkat",
    "write",
    "writev",
)
_KILL_SYSCALLS = (
    "bpf",
    "process_vm_readv",
    "ptrace",
    "unshare",
)


def main() -> int:
    """Run one request after a parent-verified startup barrier."""
    protocol_output = sys.stdout
    event_loop: asyncio.AbstractEventLoop | None = None
    try:
        request = _read_request()
        ruleset_fd = request.get("landlock_ruleset_fd")
        broker_fd = request.get("broker_fd")
        if ruleset_fd is not None:
            if type(ruleset_fd) is not int or ruleset_fd < 3:
                raise ValueError("invalid Landlock ruleset descriptor")
            if broker_fd is not None and (type(broker_fd) is not int or broker_fd < 3):
                raise ValueError("invalid broker descriptor")
            _apply_landlock(
                ruleset_fd,
                frozenset({broker_fd}) if isinstance(broker_fd, int) else frozenset(),
            )
        _apply_limits(request.get("limits"))
        if bool(request.get("asynchronous")):
            event_loop = asyncio.new_event_loop()
        _apply_seccomp()
        _write(
            protocol_output,
            {
                "plan_digest": request["plan_digest"],
                "startup_challenge": request["startup_challenge"],
                "status": "ready",
            },
        )
        if sys.stdin.readline(16) != "GO\n":
            return 73
        result = _invoke(request, event_loop)
        _write(protocol_output, {"result": _json_value(result), "status": "ok"})
        return 0
    except BaseException as exc:
        try:
            _write(
                protocol_output,
                {"error_type": type(exc).__name__, "status": "error"},
            )
        except BaseException:
            pass
        return 70
    finally:
        if event_loop is not None:
            event_loop.close()


def _read_request() -> Mapping[str, Any]:
    line = sys.stdin.readline(_MAX_FRAME + 1)
    if not line or len(line) > _MAX_FRAME or not line.endswith("\n"):
        raise ValueError("invalid request frame")
    value = json.loads(line)
    if not isinstance(value, dict):
        raise ValueError("request must be an object")
    required = {
        "args",
        "artifact_path",
        "call_id",
        "entrypoint",
        "plan_digest",
        "runtime_roots",
        "startup_challenge",
        "tool_name",
    }
    if not required.issubset(value):
        raise ValueError("request is missing required fields")
    return value


def _apply_limits(raw: object) -> None:
    limits = raw if isinstance(raw, Mapping) else {}
    cpu_ms = limits.get("cpu_ms")
    if isinstance(cpu_ms, int):
        if cpu_ms % 1000:
            raise ValueError("cpu_ms must use whole-second RLIMIT_CPU granularity")
        seconds = cpu_ms // 1000
        resource.setrlimit(resource.RLIMIT_CPU, (seconds, seconds))
    address_space = limits.get("address_space_bytes")
    if isinstance(address_space, int):
        resource.setrlimit(resource.RLIMIT_AS, (address_space, address_space))
    file_size = limits.get("file_size_bytes")
    if isinstance(file_size, int):
        resource.setrlimit(resource.RLIMIT_FSIZE, (file_size, file_size))
    nofile = limits.get("nofile")
    if isinstance(nofile, int):
        resource.setrlimit(resource.RLIMIT_NOFILE, (nofile, nofile))
    pids = limits.get("pids")
    if isinstance(pids, int):
        resource.setrlimit(resource.RLIMIT_NPROC, (pids, pids))


def _apply_landlock(
    ruleset_fd: int, preserve_fds: frozenset[int] = frozenset()
) -> None:
    """Enter the parent-built ruleset with no ambient resource descriptors."""
    descriptors: list[int] = []
    try:
        descriptors = [int(name) for name in os.listdir("/proc/self/fd")]
    except (OSError, ValueError):
        soft_limit = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        maximum = 65_536 if soft_limit == resource.RLIM_INFINITY else int(soft_limit)
        descriptors = list(range(3, maximum))
    for descriptor in descriptors:
        if descriptor <= 2 or descriptor == ruleset_fd or descriptor in preserve_fds:
            continue
        try:
            os.close(descriptor)
        except OSError:
            pass
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS failed")
    ctypes.set_errno(0)
    if libc.syscall(446, ruleset_fd, 0) != 0:
        raise OSError(ctypes.get_errno(), "landlock_restrict_self failed")
    os.close(ruleset_fd)


def _apply_seccomp() -> None:
    library = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    library.seccomp_init.argtypes = [ctypes.c_uint32]
    library.seccomp_init.restype = ctypes.c_void_p
    library.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    library.seccomp_syscall_resolve_name.restype = ctypes.c_int
    library.seccomp_rule_add.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_int,
        ctypes.c_uint,
    ]
    library.seccomp_rule_add.restype = ctypes.c_int
    library.seccomp_load.argtypes = [ctypes.c_void_p]
    library.seccomp_load.restype = ctypes.c_int
    library.seccomp_release.argtypes = [ctypes.c_void_p]
    allow = ctypes.c_uint32(0x7FFF0000)
    deny = ctypes.c_uint32(0x00050000 | errno.EPERM)
    kill = ctypes.c_uint32(0x80000000)
    context = library.seccomp_init(deny)
    if not context:
        raise OSError("seccomp initialization failed")
    try:
        for name in _KILL_SYSCALLS:
            number = library.seccomp_syscall_resolve_name(name.encode())
            if number < 0:
                continue
            if library.seccomp_rule_add(context, kill, number, 0) != 0:
                raise OSError(f"seccomp kill rule failed:{name}")
        for name in _ALLOWED_SYSCALLS:
            number = library.seccomp_syscall_resolve_name(name.encode())
            if number < 0:
                continue
            if library.seccomp_rule_add(context, allow, number, 0) != 0:
                raise OSError(f"seccomp rule failed:{name}")
        if library.seccomp_load(context) != 0:
            raise OSError("seccomp activation failed")
    finally:
        library.seccomp_release(context)


def _invoke(
    request: Mapping[str, Any], event_loop: asyncio.AbstractEventLoop | None
) -> Any:
    entrypoint = str(request["entrypoint"])
    module_name, _, attribute_path = entrypoint.partition(":")
    artifact_path = str(request["artifact_path"])
    runtime_roots = request["runtime_roots"]
    if not isinstance(runtime_roots, list) or any(
        type(item) is not str for item in runtime_roots
    ):
        raise TypeError("runtime_roots must be a list of paths")
    tool_import_roots = request.get("tool_import_roots", [])
    if not isinstance(tool_import_roots, list) or any(
        type(item) is not str for item in tool_import_roots
    ):
        raise TypeError("tool_import_roots must be a list of paths")
    fixed_runtime_roots = list(sys.path)
    sys.path[:] = tool_import_roots + runtime_roots + fixed_runtime_roots
    module = ModuleType(module_name)
    module.__file__ = artifact_path
    module.__package__ = module_name.rpartition(".")[0]
    sys.modules[module_name] = module
    with open(artifact_path, "rb") as source:
        code = compile(source.read(), artifact_path, "exec", dont_inherit=True)
    exec(code, module.__dict__)
    target: Any = module
    for part in attribute_path.split("."):
        target = getattr(target, part)
    args = request["args"]
    if not isinstance(args, dict):
        raise TypeError("tool arguments must be an object")
    call = {
        "args": args,
        "id": str(request["call_id"]),
        "name": str(request["tool_name"]),
        "type": "tool_call",
    }
    with (
        contextlib.redirect_stdout(io.StringIO()),
        contextlib.redirect_stderr(io.StringIO()),
    ):
        if bool(request.get("asynchronous")) and hasattr(target, "ainvoke"):
            if event_loop is None:
                raise RuntimeError("async worker event loop is unavailable")
            return event_loop.run_until_complete(target.ainvoke(call))
        if hasattr(target, "invoke"):
            return target.invoke(call)
        result = target(**args)
        if inspect.isawaitable(result):
            if event_loop is None:
                raise RuntimeError("async result requires an async worker")
            return event_loop.run_until_complete(result)
        return result


def _json_value(value: object) -> Any:
    if value is None or type(value) in {bool, int, float, str}:
        return value
    if isinstance(value, list | tuple) and type(value) in {list, tuple}:
        return [_json_value(item) for item in value]
    if isinstance(value, dict) and type(value) is dict:
        if any(type(key) is not str for key in value):
            raise ValueError("result mappings require string keys")
        return {key: _json_value(item) for key, item in value.items()}
    raise TypeError(f"result type is not supported:{type(value).__name__}")


def _write(stream: Any, value: Mapping[str, Any]) -> None:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
    if len(encoded) > _MAX_FRAME:
        raise ValueError("response frame exceeds limit")
    stream.write(encoded + "\n")
    stream.flush()


if __name__ == "__main__":
    raise SystemExit(main())
