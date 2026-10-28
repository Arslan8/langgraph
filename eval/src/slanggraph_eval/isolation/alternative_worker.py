"""Evaluation-only worker: Landlock plus production seccomp, or container seccomp."""

import ctypes
import importlib.util
import json
import os
import resource
import sys
import time
from typing import ClassVar


def landlock(readable, writable):
    """Install ABI>=3 filesystem restrictions; metadata visibility is not hidden."""
    libc = ctypes.CDLL(None, use_errno=True)

    def checked(value):
        if value < 0:
            raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
        return value

    class Rules(ctypes.Structure):
        _fields_: ClassVar = [("handled_access_fs", ctypes.c_uint64)]

    class Beneath(ctypes.Structure):
        _pack_ = 1
        _fields_: ClassVar = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]

    abi = checked(libc.syscall(444, 0, 0, 1))
    if abi < 3:
        raise RuntimeError("Landlock ABI 3 or later required")
    mask = (1 << 15) - 1  # All filesystem rights through TRUNCATE, ABI 3.
    attr = Rules(mask)
    fd = checked(libc.syscall(444, ctypes.byref(attr), ctypes.sizeof(attr), 0))
    try:
        for path, access in [*((p, 1 | 4 | 8) for p in readable), *((p, mask) for p in writable)]:
            if not os.path.exists(path):
                raise FileNotFoundError(path)
            flags = access if os.path.isdir(path) else access & (1 | 2 | 4 | (1 << 14))
            pathfd = os.open(path, os.O_PATH | os.O_CLOEXEC)
            try:
                entry = Beneath(flags, pathfd)
                checked(libc.syscall(445, fd, 1, ctypes.byref(entry), 0))
            finally:
                os.close(pathfd)
        checked(libc.prctl(38, 1, 0, 0, 0))
        checked(libc.syscall(446, fd, 0))
    finally:
        os.close(fd)
    return abi


def main():
    request = json.load(sys.stdin)
    os.sched_setaffinity(0, {request["cpu"]})
    sys.path[:0] = request.get("python_paths", [])
    # Load the exact production syscall policy before restricting filesystem access.
    spec = importlib.util.spec_from_file_location("production_worker", request["seccomp_source"])
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # Apply resource ceilings to each fresh worker, including subprocess baselines.
    resource.setrlimit(resource.RLIMIT_FSIZE, (1048576, 1048576))
    resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_AS, (1073741824, 1073741824))
    activation = time.perf_counter_ns()
    abi = None
    if request["mode"] == "landlock":
        abi = landlock(request["readable"], request["writable"])
    if request["mode"] != "plain":
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(38, 1, 0, 0, 0):
            raise OSError(ctypes.get_errno(), "no_new_privs")
        module._apply_seccomp()
    activation_ns = time.perf_counter_ns() - activation
    namespace = {"p": request["p"], "result": None}
    start = time.perf_counter_ns()
    try:
        exec(compile(request["source"], "<fixed-evaluation-operation>", "exec"), namespace)
        result = {"phase": "executed", "value": namespace.get("result")}
    except Exception as exc:
        result = {
            "phase": "operation",
            "error": type(exc).__name__,
            "errno": getattr(exc, "errno", None),
        }
    result.update(
        execution_ns=time.perf_counter_ns() - start,
        activation_ns=activation_ns,
        landlock_abi=abi,
        mechanism=request["mode"],
        cpu_affinity=sorted(os.sched_getaffinity(0)),
        seccomp=request["mode"] != "plain",
    )
    if "_operation_elapsed_ns" in namespace:
        result["operation_elapsed_ns"] = namespace["_operation_elapsed_ns"]
    print(json.dumps(result))


if __name__ == "__main__":
    main()
