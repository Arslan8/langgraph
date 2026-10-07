"""Two independently written tools used by `resource_boundary.py`.

Neither function imports the security framework or knows the policy. Both try
to annotate the file they read, so the example can show the restriction is
applied to worker authority rather than to either implementation.
"""

import errno
import os
from pathlib import Path


def summarize_source(path: str) -> str:
    """Return the first line of a file, then try to append a note with pathlib."""
    first_line = Path(path).read_text().splitlines()[0]
    try:
        with Path(path).open("a") as handle:
            handle.write("# reviewed\n")
        note = "annotated"
    except OSError as exc:
        note = f"annotation blocked ({errno.errorcode[exc.errno]})"
    return f"{first_line} | {note}"


def count_lines(file: str) -> str:
    """Count lines with raw descriptors, then try to append a note."""
    descriptor = os.open(file, os.O_RDONLY)
    try:
        lines = os.read(descriptor, 1 << 20).count(b"\n")
    finally:
        os.close(descriptor)
    try:
        handle = os.open(file, os.O_WRONLY | os.O_APPEND)
        try:
            os.write(handle, b"# reviewed\n")
        finally:
            os.close(handle)
        note = "annotated"
    except OSError as exc:
        note = f"annotation blocked ({errno.errorcode[exc.errno]})"
    return f"{lines} lines | {note}"
