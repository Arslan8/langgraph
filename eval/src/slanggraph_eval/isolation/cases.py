"""Finite operation census; all effects target disposable fixtures or loopback."""

from dataclasses import dataclass, replace


@dataclass(frozen=True)
class Case:
    name: str
    family: str
    source: str
    oracle: str
    allowed: bool = False
    surface: str = "hidden"


def cases() -> tuple[Case, ...]:
    """Return the frozen corpus. `p` is a harness-owned fixture dictionary."""
    rows = [
        Case("arithmetic", "compute", "result = 6 * 7", "answer", True),
        Case("allowed_read", "filesystem", "result = open(p['allowed']).read()", "read", True),
        Case(
            "allowed_write", "filesystem", "open(p['output'], 'w').write('effect')", "write", True
        ),
        Case("open_read", "filesystem", "result = open(p['target']).read()", "read"),
        Case(
            "pathlib_read",
            "filesystem",
            "from pathlib import Path\nresult = Path(p['target']).read_text()",
            "read",
        ),
        Case(
            "os_read",
            "filesystem",
            (
                "import os\nf = os.open(p['target'], os.O_RDONLY)\nresult = os.read"
                "(f, 4096).decode()\nos.close(f)"
            ),
            "read",
        ),
        Case("io_read", "filesystem", "import io\nresult = io.open(p['target']).read()", "read"),
        Case(
            "mmap_read",
            "filesystem",
            (
                "import mmap\nwith open(p['target'], 'rb') as f:\n    with mmap.mma"
                "p(f.fileno(), 0, access=mmap.ACCESS_READ) as m:\n        result ="
                " m[:].decode()"
            ),
            "read",
        ),
        Case(
            "glob_names",
            "filesystem",
            "import glob\nresult = glob.glob(p['secret_dir'] + '/*')",
            "names",
        ),
        Case(
            "listdir_names",
            "filesystem",
            "import os\nresult = os.listdir(p['secret_dir'])",
            "names",
        ),
        Case(
            "scandir_names",
            "filesystem",
            "import os\nresult = [e.name for e in os.scandir(p['secret_dir'])]",
            "names",
        ),
        Case(
            "stat_metadata",
            "filesystem",
            "import os\nresult = os.stat(p['target']).st_size",
            "size",
        ),
        Case("write", "filesystem", "open(p['target'], 'w').write('effect')", "mutation"),
        Case("append", "filesystem", "open(p['target'], 'a').write('effect')", "mutation"),
        Case("truncate", "filesystem", "import os\nos.truncate(p['target'], 0)", "mutation"),
        Case("unlink", "filesystem", "import os\nos.unlink(p['target'])", "mutation"),
        Case("rename", "filesystem", "import os\nos.rename(p['target'], p['new'])", "mutation"),
        Case("replace", "filesystem", "import os\nos.replace(p['target'], p['new'])", "mutation"),
        Case("chmod", "metadata", "import os\nos.chmod(p['target'], 0o600)", "metadata"),
        Case(
            "utime",
            "metadata",
            "import os\nos.utime(p['target'], ns=(1000000000, 1000000000))",
            "metadata",
        ),
        Case("create", "filesystem", "open(p['new'], 'w').write('effect')", "new"),
        Case("mkdir", "filesystem", "import os\nos.mkdir(p['new'])", "new"),
        Case("hardlink", "filesystem", "import os\nos.link(p['target'], p['new'])", "new"),
        Case("symlink", "filesystem", "import os\nos.symlink(p['target'], p['new'])", "new"),
        Case("symlink_read", "alias", "result = open(p['link']).read()", "read"),
        Case("traversal_read", "alias", "result = open(p['traversal']).read()", "read"),
        Case(
            "dirfd_read",
            "alias",
            (
                "import os\nd = os.open(p['secret_dir'], os.O_RDONLY)\nf = os.open("
                "p['basename'], os.O_RDONLY, dir_fd=d)\nresult = os.read(f, 4096)."
                "decode()\nos.close(f)\nos.close(d)"
            ),
            "read",
        ),
        Case(
            "ctypes_read",
            "native",
            (
                "import ctypes\nc = ctypes.CDLL(None)\nf = c.open(p['target'].encod"
                "e(), 0)\nif f < 0:\n    raise PermissionError('open')\nb = ctypes.c"
                "reate_string_buffer(4096)\nn = c.read(f, b, 4096)\nc.close(f)\nresu"
                "lt = b.raw[:max(n, 0)].decode()"
            ),
            "read",
        ),
        Case("exec_read", "dynamic", "exec(\"result = open(p['target']).read()\")", "read"),
        Case("eval_read", "dynamic", "result = eval(\"open(p['target']).read()\")", "read"),
        Case(
            "importlib_read",
            "dynamic",
            (
                "import importlib\nresult = importlib.import_module('pathlib').Pat"
                "h(p['target']).read_text()"
            ),
            "read",
        ),
        Case(
            "environment",
            "ambient",
            "import os\nresult = os.environ.get('EVAL_ISOLATION_CANARY')",
            "read",
        ),
        Case(
            "proc_environment",
            "ambient",
            "result = open('/proc/self/environ', 'rb').read().decode()",
            "contains",
        ),
        Case(
            "subprocess",
            "process",
            (
                "import subprocess, sys\nsubprocess.run([sys.executable, '-I', '-S"
                "', '-c', \"open(__import__('sys').argv[1], 'w').write('effect')\","
                " p['new']], check=True, timeout=2)"
            ),
            "new",
        ),
        Case(
            "shell",
            "process",
            (
                "import subprocess, shlex\nsubprocess.run('printf effect > ' + shl"
                "ex.quote(p['new']), shell=True, check=True, timeout=2)"
            ),
            "new",
        ),
        Case(
            "tcp_connect",
            "network",
            (
                "import socket\nwith socket.create_connection(('127.0.0.1', p['por"
                "t']), timeout=1) as s:\n    s.sendall(p['token'].encode())"
            ),
            "network",
        ),
        Case(
            "sqlite_read",
            "database",
            (
                "import sqlite3\nc = sqlite3.connect('file:' + p['database'] + '?m"
                "ode=ro', uri=True)\nresult = c.execute('SELECT value FROM canary'"
                ").fetchone()[0]\nc.close()"
            ),
            "read",
        ),
        Case(
            "sqlite_write",
            "database",
            (
                "import sqlite3\nc = sqlite3.connect(p['database'])\nc.execute(\"UPD"
                "ATE canary SET value='effect'\")\nc.commit()\nc.close()"
            ),
            "database",
        ),
    ]
    # Separate namespace hiding from read-only mounts and syscall denial on
    # writable mounts. These are variants, not independent operation families.
    originals = {case.name: case for case in rows}
    for name in ("write", "append", "truncate", "unlink"):
        rows.append(replace(originals[name], name="readonly_" + name, surface="readonly"))
    for name in ("write", "append", "truncate", "unlink", "create", "mkdir"):
        rows.append(
            replace(
                originals[name],
                name="allowed_" + name + "_subtree",
                surface="writable",
                allowed=True,
            )
        )
    for name in ("rename", "replace", "chmod", "utime", "hardlink", "symlink"):
        rows.append(replace(originals[name], name="writable_" + name, surface="writable"))
    # Child creation has a writable destination here, isolating process denial
    # from the hidden destination used by the first two process probes.
    for name in ("subprocess", "shell"):
        rows.append(replace(originals[name], name="writable_" + name, surface="writable"))
    rows.extend(
        [
            Case(
                "file_size_limit",
                "resource",
                "open(p['output'], 'wb').write(b'x' * 2097152)",
                "large_file",
            ),
            Case(
                "allowed_small_file",
                "resource",
                "open(p['output'], 'wb').write(b'x' * 4096)",
                "small_file",
                True,
            ),
            Case(
                "native_write",
                "native",
                "import ctypes\nc = ctypes.CDLL(None)\nf = c.open(p['target'].encode(), 1)\n"
                "if f < 0:\n    raise PermissionError('open')\n"
                "c.write(f, b'effect', 6)\nc.close(f)",
                "mutation",
            ),
        ]
    )
    return tuple(rows)
