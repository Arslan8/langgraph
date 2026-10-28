"""Real kernel capability restriction: deny Landlock syscalls with inherited seccomp."""

import argparse
import ctypes
import ctypes.util
import hashlib
import json
import platform
import subprocess
import sys
import tempfile
import time
from dataclasses import replace
from pathlib import Path

from evidence_utils import serial

ROOT = Path(__file__).resolve().parents[2]


def restrict_landlock():
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "no_new_privs")
    library = ctypes.CDLL(ctypes.util.find_library("seccomp"))
    library.seccomp_init.restype = ctypes.c_void_p
    library.seccomp_init.argtypes = [ctypes.c_uint32]
    library.seccomp_rule_add.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_int,
        ctypes.c_uint,
    ]
    library.seccomp_load.argtypes = [ctypes.c_void_p]
    library.seccomp_release.argtypes = [ctypes.c_void_p]
    library.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    context = library.seccomp_init(0x7FFF0000)
    if not context:
        raise RuntimeError("seccomp_init")
    try:
        for name in [b"landlock_create_ruleset", b"landlock_add_rule", b"landlock_restrict_self"]:
            syscall = library.seccomp_syscall_resolve_name(name)
            if syscall < 0 or library.seccomp_rule_add(context, 0x00050001, syscall, 0) != 0:
                raise RuntimeError("rule add")
        if library.seccomp_load(context) != 0:
            raise RuntimeError("seccomp load")
    finally:
        library.seccomp_release(context)


def child(configuration):
    if configuration == "landlock_denied_by_kernel_seccomp":
        restrict_landlock()
    sys.path.insert(0, str(ROOT / "libs/prebuilt"))
    from langgraph.prebuilt.security.capabilities import probe_landlock_abi
    from tests.security.test_object_broker import setup

    probe = probe_landlock_abi()
    rows = []
    for case in ["authorized", "wrong_grant"]:
        with tempfile.TemporaryDirectory(prefix="slg-capability-") as tmp:
            dispatcher, principal, call, grant, seen = setup.__wrapped__(Path(tmp))
            if case == "wrong_grant":
                grant = replace(grant, call_id="wrong")
            start = time.perf_counter()
            result = None
            error = None
            try:
                result = serial(dispatcher.invoke(principal, call, grant))
            except Exception as exc:
                error = dict(type=type(exc).__name__, message=str(exc))
            rows.append(
                dict(
                    case_id=case,
                    mode=configuration,
                    concrete_executor="ObjectBrokerDispatcher",
                    host=platform.node(),
                    principal=serial(principal),
                    grant=serial(grant),
                    grant_identity=grant.digest,
                    authorization="preconstructed fixture grant",
                    lowering=serial(dispatcher.lowering_records()),
                    activation=result["receipt"] if result else "not-applicable",
                    result=result,
                    error=error,
                    resource_state=seen,
                    observed_effect=bool(seen),
                    elapsed_ms=(time.perf_counter() - start) * 1000,
                    probe_landlock_abi=probe,
                    seccomp_status=[
                        line
                        for line in Path("/proc/self/status").read_text().splitlines()
                        if line.startswith("Seccomp")
                    ],
                )
            )
    print(json.dumps(rows))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--child")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.child:
        child(args.child)
        return
    args.output.mkdir(parents=True, exist_ok=False)
    with (args.output / "trials.jsonl").open("w") as stream:
        for repeat in range(20):
            for mode in ["native_landlock", "landlock_denied_by_kernel_seccomp"]:
                p = subprocess.run(
                    [sys.executable, __file__, "--child", mode],
                    capture_output=True,
                    text=True,
                    timeout=20,
                )
                (args.output / f"{mode}-{repeat}.log").write_text(p.stdout + p.stderr)
                if p.returncode:
                    raise RuntimeError(p.stderr)
                for row in json.loads(p.stdout):
                    row.update(
                        repeat=repeat,
                        session=repeat,
                        source_revision=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    )
                    stream.write(json.dumps(row) + "\n")
                    stream.flush()


if __name__ == "__main__":
    main()
