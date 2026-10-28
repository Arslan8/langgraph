"""Separate intrusive attribution runs; never pool with uninstrumented headline timings."""

import json
import runpy
import sys
import threading
import time
from pathlib import Path

records = []
active = {}


def profile(frame, event, arg):
    if event not in {"call", "return"}:
        return
    file = frame.f_code.co_filename
    name = frame.f_code.co_name
    if "/langgraph/prebuilt/security/" not in file or name not in {
        "_authorize",
        "authorize",
        "invoke",
        "write",
        "assess",
        "activate",
        "evaluate",
        "is_authorized",
        "__init__",
    }:
        return
    key = (threading.get_ident(), id(frame))
    if event == "call":
        active[key] = time.perf_counter()
    elif key in active:
        start = active.pop(key)
        records.append(
            dict(
                file=file,
                function=name,
                thread=key[0],
                start=start,
                elapsed_ms=(time.perf_counter() - start) * 1000,
                boundary="inclusive/nested; do not sum across functions or threads",
            )
        )


def main():
    script, request, output = sys.argv[1:]
    original_argv = sys.argv
    original_path = sys.path[:]
    original_profile = sys.getprofile()
    original_thread_profile = threading.getprofile()
    records.clear()
    active.clear()
    sys.argv = [script, request]
    sys.path.insert(0, str(Path(script).parent))
    sys.setprofile(profile)
    threading.setprofile(profile)
    try:
        # The application must not overwrite the profiler's globals (including
        # records, active, output, and the callback itself).
        runpy.run_path(script, run_name="__main__")
    finally:
        sys.setprofile(original_profile)
        threading.setprofile(original_thread_profile)
        sys.argv = original_argv
        sys.path[:] = original_path
        Path(output).write_text(json.dumps(records, indent=2))


if __name__ == "__main__":
    main()
