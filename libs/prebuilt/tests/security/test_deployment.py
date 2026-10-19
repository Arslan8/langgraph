"""OSTree deployment identity and retained-selection tests."""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock

import pytest
from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import START, MessagesState, StateGraph
from langgraph.types import Command

from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.security import (
    BundleManifest,
    DacOverrides,
    Decision,
    DeploymentError,
    Effect,
    EscalationRequest,
    LinuxSandboxExecutor,
    LinuxToolSpec,
    OstreeDeploymentManager,
    Principal,
    RuntimeManifest,
    SecurityConfig,
    SecurityModule,
    TypedPolicyBackend,
    Verdict,
    dac,
    effects,
    parse_profiles,
    with_principal,
)


def _fake_ostree(tmp_path: Path) -> Path:
    executable = tmp_path / "ostree"
    executable.write_text(
        f"""#!{sys.executable}
import hashlib
import os
import shutil
import stat
import sys
from pathlib import Path

repo = Path(sys.argv[1].removeprefix("--repo="))
command = sys.argv[2]
arguments = sys.argv[3:]

def tree_digest(root):
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        mode = stat.S_IMODE(path.stat().st_mode)
        digest.update(f"{{relative}}:{{mode:o}}:".encode())
        if path.is_file():
            digest.update(path.read_bytes())
    return digest.hexdigest()

def ref_path(name):
    return repo / "refs" / name

if command == "init":
    (repo / "commits").mkdir(parents=True)
    (repo / "refs").mkdir(parents=True)
elif command == "rev-parse":
    selection = arguments[0]
    candidate = repo / "commits" / selection
    reference = ref_path(selection)
    if candidate.is_dir():
        print(selection)
    elif reference.is_file():
        print(reference.read_text())
    else:
        raise SystemExit(1)
elif command == "commit":
    branch = next(item.split("=", 1)[1] for item in arguments if item.startswith("--branch="))
    source = Path(next(item.removeprefix("--tree=dir=") for item in arguments if item.startswith("--tree=dir=")))
    commit = tree_digest(source)
    destination = repo / "commits" / commit
    if not destination.exists():
        shutil.copytree(source, destination, copy_function=shutil.copy2)
    reference = ref_path(branch)
    reference.parent.mkdir(parents=True, exist_ok=True)
    reference.write_text(commit)
    print(commit)
elif command == "checkout":
    commit, destination = arguments[-2:]
    shutil.copytree(repo / "commits" / commit, destination, dirs_exist_ok=True, copy_function=shutil.copy2)
elif command == "refs":
    if "--revision" in arguments:
        for reference in sorted((repo / "refs").rglob("*")):
            if reference.is_file():
                print(reference.read_text(), reference.relative_to(repo / "refs").as_posix())
    elif "--delete" in arguments:
        ref_path(arguments[-1]).unlink()
    else:
        name = next(item.removeprefix("--create=") for item in arguments if item.startswith("--create="))
        commit = arguments[-1]
        reference = ref_path(name)
        reference.parent.mkdir(parents=True, exist_ok=True)
        reference.write_text(commit)
elif command == "prune":
    pass
elif command == "remote" and arguments[0] == "add":
    name, url = arguments[-2:]
    remote = repo / "remotes" / name
    remote.parent.mkdir(parents=True, exist_ok=True)
    if remote.exists():
        raise SystemExit(1)
    remote.write_text(url)
elif command == "pull":
    remote_name, remote_ref = arguments[-2:]
    remote_url = (repo / "remotes" / remote_name).read_text()
    remote_repo = Path(remote_url.removeprefix("file://"))
    commit = (remote_repo / "refs" / remote_ref).read_text()
    destination = repo / "commits" / commit
    if not destination.exists():
        shutil.copytree(remote_repo / "commits" / commit, destination)
    reference = ref_path(f"{{remote_name}}:{{remote_ref}}")
    reference.parent.mkdir(parents=True, exist_ok=True)
    reference.write_text(commit)
elif command == "diff":
    commit, checkout = [item for item in arguments if not item.startswith("--")]
    expected = repo / "commits" / commit
    checkout = Path(checkout)
    if tree_digest(expected) != tree_digest(checkout):
        print("M /tool")
elif command == "fsck":
    pass
else:
    raise SystemExit(2)
"""
    )
    executable.chmod(0o755)
    return executable


def _bundle(root: Path, helper_value: str) -> None:
    root.mkdir()
    (root / "bundle.json").write_text(
        json.dumps(
            {
                "format_version": 1,
                "tool_id": "demo",
                "entrypoint": "tool:run",
                "primary_file": "tool.py",
                "import_roots": ["."],
            }
        )
    )
    (root / "tool.py").write_text(
        "from helper import VALUE\n\ndef run():\n    return VALUE\n"
    )
    (root / "helper.py").write_text(f"VALUE = {helper_value!r}\n")


def _write_probe_bundle(root: Path) -> None:
    root.mkdir()
    (root / "bundle.json").write_text(
        json.dumps(
            {
                "format_version": 1,
                "tool_id": "demo",
                "entrypoint": "tool:run",
                "primary_file": "tool.py",
                "import_roots": ["."],
            }
        )
    )
    (root / "tool.py").write_text(
        "from pathlib import Path\n\n"
        "def run():\n"
        "    try:\n"
        "        Path(__file__).with_name('helper.py').write_text('changed')\n"
        "    except OSError as exc:\n"
        "        return type(exc).__name__\n"
        "    return 'WRITTEN'\n"
    )
    (root / "helper.py").write_text("unchanged\n")


def _runtime(root: Path) -> None:
    (root / "usr" / "bin").mkdir(parents=True)
    (root / "usr" / "lib" / "python-test").mkdir(parents=True)
    (root / "runtime.json").write_text(
        json.dumps(
            {
                "format_version": 1,
                "runtime_id": "python-test",
                "interpreter": "usr/bin/python-test",
                "import_roots": ["usr/lib/python-test"],
            }
        )
    )
    interpreter = root / "usr" / "bin" / "python-test"
    interpreter.write_text("#!/bin/sh\nexit 0\n")
    interpreter.chmod(0o755)


def _host_python_runtime(root: Path) -> None:
    interpreter = Path(sys.executable).resolve()
    version = f"python{sys.version_info.major}.{sys.version_info.minor}"
    stdlib = interpreter.parent.parent / "lib" / version
    shutil.copytree(stdlib, root / "usr" / "lib" / version)
    target_interpreter = root / "usr" / "bin" / version
    target_interpreter.parent.mkdir(parents=True)
    shutil.copy2(interpreter, target_interpreter)
    target_interpreter.chmod(0o755)

    seccomp = next(
        Path(line.rpartition("=>")[2].strip().split()[0]).resolve()
        for line in subprocess.run(
            ["ldconfig", "-p"], check=True, capture_output=True, text=True
        ).stdout.splitlines()
        if "libseccomp.so.2" in line and "=>" in line
    )
    binaries = [interpreter, seccomp, *(stdlib / "lib-dynload").glob("*.so")]
    libraries = {seccomp: seccomp}
    for binary in binaries:
        output = subprocess.run(
            ["ldd", os.fspath(binary)], check=True, capture_output=True, text=True
        ).stdout
        for line in output.splitlines():
            candidate = (
                line.rpartition("=>")[2].strip().split()[0]
                if "=>" in line
                else line.strip().split()[0]
            )
            if candidate.startswith("/"):
                library_path = Path(candidate)
                libraries[library_path] = library_path.resolve()
    for library_path, source in libraries.items():
        destination = root / library_path.relative_to("/")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    seccomp_destination = root / "lib" / "x86_64-linux-gnu" / "libseccomp.so.2"
    seccomp_destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(seccomp, seccomp_destination)
    (root / "runtime.json").write_text(
        json.dumps(
            {
                "format_version": 1,
                "runtime_id": version,
                "interpreter": f"usr/bin/{version}",
                "import_roots": [f"usr/lib/{version}"],
            }
        )
    )


def test_manifest_rejects_duplicate_and_escaping_fields() -> None:
    with pytest.raises(DeploymentError, match="duplicate manifest field"):
        BundleManifest.from_bytes(
            b'{"format_version":1,"tool_id":"a","tool_id":"b",'
            b'"entrypoint":"tool:run","primary_file":"tool.py",'
            b'"import_roots":["."]}'
        )

    with pytest.raises(DeploymentError, match="duplicate runtime manifest field"):
        RuntimeManifest.from_bytes(
            b'{"format_version":1,"runtime_id":"a","runtime_id":"b",'
            b'"interpreter":"usr/bin/python","import_roots":["usr/lib"]}'
        )
    with pytest.raises(DeploymentError, match="escapes"):
        BundleManifest.from_bytes(
            b'{"format_version":1,"tool_id":"a","entrypoint":"tool:run",'
            b'"primary_file":"../tool.py","import_roots":["."]}'
        )


def test_runtime_is_an_independent_exact_commit(tmp_path: Path) -> None:
    manager = OstreeDeploymentManager(
        tmp_path / "store", ostree_path=_fake_ostree(tmp_path)
    )
    source = tmp_path / "runtime"
    _runtime(source)

    runtime = manager.publish_runtime(source, "runtimes/python-test/releases/A")
    source_b = tmp_path / "runtime-b"
    _runtime(source_b)
    (source_b / "usr" / "lib" / "python-test" / "version.txt").write_text("B\n")
    runtime_b = manager.publish_runtime(source_b, "runtimes/python-test/releases/B")

    assert runtime.binding.runtime_commit != runtime_b.binding.runtime_commit
    assert runtime.binding.runtime_id == "python-test"
    assert runtime.interpreter_path.stat().st_mode & 0o111
    assert runtime.guest_interpreter_path == Path("/usr/bin/python-test")
    assert runtime.guest_import_roots == (Path("/usr/lib/python-test"),)
    assert manager.materialize_runtime(runtime.binding.runtime_commit) == runtime
    retained = manager.bind_runtime_invocation(
        runtime=runtime,
        principal_id="alice",
        session_id="session",
        call_id="call-1",
    )
    assert retained == runtime
    restarted = OstreeDeploymentManager(manager.root, ostree_path=manager.ostree_path)
    assert (
        restarted.recover_runtime_invocation(
            runtime.binding,
            principal_id="alice",
            session_id="session",
            call_id="call-1",
        )
        == runtime
    )
    with pytest.raises(DeploymentError, match="does not match checkout"):
        restarted.recover_runtime_invocation(
            replace(runtime.binding, manifest_digest="0" * 64),
            principal_id="alice",
            session_id="session",
            call_id="call-1",
        )
    with pytest.raises(DeploymentError, match="retained by execution state"):
        manager.retire_release("runtimes/python-test/releases/A")
    lease = manager.acquire_lease(
        (runtime.binding.runtime_commit,),
        principal_id="alice",
        session_id="session",
        call_id="call-1",
    )
    assert manager.active_leases() == (lease,)
    assert manager.release_runtime_invocation(
        runtime.binding,
        principal_id="alice",
        session_id="session",
        call_id="call-1",
    )
    with pytest.raises(DeploymentError, match="retained by execution state"):
        manager.retire_release("runtimes/python-test/releases/A")
    assert manager.release_lease(lease)
    assert manager.active_leases() == ()
    manager.retire_release("runtimes/python-test/releases/A")
    assert manager.cleanup().removed_runtime_checkouts == (
        runtime.binding.runtime_commit,
    )


def test_worker_executes_from_selected_runtime_commit(tmp_path: Path) -> None:
    manager = OstreeDeploymentManager(
        tmp_path / "store", ostree_path=_fake_ostree(tmp_path)
    )
    runtime_source = tmp_path / "runtime"
    _host_python_runtime(runtime_source)
    runtime = manager.publish_runtime(runtime_source, "runtimes/python/releases/A")
    (runtime_source / "usr" / "lib" / "runtime-version").write_text("B\n")
    runtime_b = manager.publish_runtime(runtime_source, "runtimes/python/releases/B")
    manager.update_runtime_channel(
        "runtimes/python/stable", runtime.binding.runtime_commit
    )
    tool_source = tmp_path / "tool"
    _bundle(tool_source, "PACKAGED-RUNTIME")
    deployment = manager.publish_bundle(tool_source, "tools/demo/releases/A")
    profiles = parse_profiles(
        """
tool demo {
  owner analyst
  grant analyst: call
  runs linux
  syscalls @minimal
}
principal alice {
  roles analyst
}
""",
        source="runtime-deployment-test.slp",
    )
    try:
        executor = LinuxSandboxExecutor(
            profiles,
            {"demo": LinuxToolSpec.from_deployment(deployment)},
            runtime_roots=(),
            runtime_deployment=runtime,
            runtime_manager=manager,
            runtime_selection="runtimes/python/stable",
            policy_backend=TypedPolicyBackend(),
        )
    except RuntimeError as exc:
        pytest.skip(str(exc))

    @tool
    @dac(owner="analyst", grants={"analyst": "x", "*": "-"})
    def demo() -> str:
        """Trusted schema stub which must never run in process."""
        raise AssertionError("schema stub executed")

    security = SecurityConfig(
        dac_overrides=DacOverrides(profiles=profiles.tools), host_executor=executor
    )
    node = ToolNode((demo,), security=security)
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")
    runtime_context = Mock(store=None, context=None, stream_writer=lambda _: None)
    config = with_principal(
        {"configurable": {"__pregel_runtime": runtime_context}}, principal
    )

    def invoke(call_id: str) -> str:
        result = node.invoke(
            {
                "messages": [
                    AIMessage(
                        content="",
                        tool_calls=[{"name": "demo", "args": {}, "id": call_id}],
                    )
                ]
            },
            config=config,
        )
        return str(result["messages"][0].content)

    assert invoke("call-1") == "PACKAGED-RUNTIME"
    manager.update_runtime_channel(
        "runtimes/python/stable", runtime_b.binding.runtime_commit
    )
    assert invoke("call-2") == "PACKAGED-RUNTIME"
    assert invoke("call-1") == "PACKAGED-RUNTIME"
    receipts = executor.activation_receipts()
    assert {receipt.deployment_digest for receipt in receipts} == {
        deployment.binding.tool_commit
    }
    assert [receipt.runtime_digest for receipt in receipts] == [
        runtime.binding.runtime_commit,
        runtime_b.binding.runtime_commit,
        runtime.binding.runtime_commit,
    ]
    assert manager.active_leases() == ()


def test_helper_change_changes_commit_and_selection_is_retained(tmp_path: Path) -> None:
    manager = OstreeDeploymentManager(
        tmp_path / "store", ostree_path=_fake_ostree(tmp_path)
    )
    source_a = tmp_path / "source-a"
    source_b = tmp_path / "source-b"
    _bundle(source_a, "A")
    _bundle(source_b, "B")

    release_a = manager.publish_bundle(source_a, "tools/demo/releases/A")
    release_b = manager.publish_bundle(source_b, "tools/demo/releases/B")

    assert release_a.binding.tool_commit != release_b.binding.tool_commit
    assert release_a.binding.artifact_digest == release_b.binding.artifact_digest
    manager.update_channel("tools/demo/stable", release_a.binding.tool_commit)
    selected_a = manager.bind_invocation(
        tool_id="demo",
        selection="tools/demo/stable",
        principal_id="alice",
        session_id="session",
        call_id="call-1",
    )
    manager.update_channel("tools/demo/stable", release_b.binding.tool_commit)
    retained_a = manager.bind_invocation(
        tool_id="demo",
        selection="tools/demo/stable",
        principal_id="alice",
        session_id="session",
        call_id="call-1",
    )
    selected_b = manager.bind_invocation(
        tool_id="demo",
        selection="tools/demo/stable",
        principal_id="alice",
        session_id="session",
        call_id="call-2",
    )

    assert retained_a.binding == selected_a.binding
    assert selected_b.binding == release_b.binding
    with pytest.raises(DeploymentError, match="was not issued"):
        manager.recover_invocation(
            release_b.binding,
            principal_id="alice",
            session_id="session",
            call_id="call-1",
        )
    assert stat.S_IMODE(selected_a.checkout_path.stat().st_mode) == 0o555
    assert stat.S_IMODE(selected_a.artifact_path.stat().st_mode) == 0o444


def test_checkout_tampering_and_source_symlinks_fail_closed(tmp_path: Path) -> None:
    manager = OstreeDeploymentManager(
        tmp_path / "store", ostree_path=_fake_ostree(tmp_path)
    )
    source = tmp_path / "source"
    _bundle(source, "A")
    deployment = manager.publish_bundle(source, "tools/demo/releases/A")
    helper = deployment.checkout_path / "helper.py"
    helper.chmod(0o644)
    helper.write_text("VALUE = 'tampered'\n")
    with pytest.raises(DeploymentError, match="does not match selected commit"):
        manager.recover(deployment.binding)

    invalid = tmp_path / "invalid"
    _bundle(invalid, "A")
    os.symlink("helper.py", invalid / "alias.py")
    with pytest.raises(DeploymentError, match="symlinks"):
        manager.publish_bundle(invalid, "tools/demo/releases/invalid")


def test_store_modes_exclude_other_identities_and_worker_cannot_modify(
    tmp_path: Path,
) -> None:
    manager = OstreeDeploymentManager(
        tmp_path / "store", ostree_path=_fake_ostree(tmp_path)
    )
    assert manager.root.stat().st_uid == os.geteuid()
    assert stat.S_IMODE(manager.root.stat().st_mode) == 0o700
    source = tmp_path / "source"
    _write_probe_bundle(source)
    deployment = manager.publish_bundle(source, "tools/demo/releases/A")
    profiles = parse_profiles(
        """
tool demo {
  owner analyst
  grant analyst: call
  runs linux
  syscalls @minimal
}
principal alice {
  roles analyst
}
""",
        source="deployment-write-test.slp",
    )
    try:
        executor = LinuxSandboxExecutor(
            profiles,
            {"demo": LinuxToolSpec.from_deployment(deployment)},
            runtime_roots=(Path("/usr"),),
            policy_backend=TypedPolicyBackend(),
        )
    except RuntimeError as exc:
        pytest.skip(str(exc))

    @tool
    @dac(owner="analyst", grants={"analyst": "x", "*": "-"})
    def demo() -> str:
        """Trusted schema stub which must never run in process."""
        raise AssertionError("schema stub executed")

    node = ToolNode(
        (demo,),
        security=SecurityConfig(
            dac_overrides=DacOverrides(profiles=profiles.tools),
            host_executor=executor,
        ),
    )
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")
    context = Mock(store=None, context=None, stream_writer=lambda _: None)
    config = with_principal({"configurable": {"__pregel_runtime": context}}, principal)
    result = node.invoke(
        {
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[{"name": "demo", "args": {}, "id": "call-1"}],
                )
            ]
        },
        config=config,
    )

    assert result["messages"][0].content == "OSError"
    assert (deployment.checkout_path / "helper.py").read_text() == "unchanged\n"


def test_cleanup_requires_release_and_invocation_to_be_unreferenced(
    tmp_path: Path,
) -> None:
    manager = OstreeDeploymentManager(
        tmp_path / "store", ostree_path=_fake_ostree(tmp_path)
    )
    source_a = tmp_path / "source-a"
    source_b = tmp_path / "source-b"
    _bundle(source_a, "A")
    _bundle(source_b, "B")
    release_a = manager.publish_bundle(source_a, "tools/demo/releases/A")
    release_b = manager.publish_bundle(source_b, "tools/demo/releases/B")
    manager.update_channel("tools/demo/stable", release_a.binding.tool_commit)
    selected = manager.bind_invocation(
        tool_id="demo",
        selection="tools/demo/stable",
        principal_id="alice",
        session_id="session",
        call_id="call-1",
    )

    with pytest.raises(DeploymentError, match="retained by execution state"):
        manager.retire_release("tools/demo/releases/A")
    assert manager.release_invocation(
        selected.binding,
        principal_id="alice",
        session_id="session",
        call_id="call-1",
    )
    assert not manager.release_invocation(
        selected.binding,
        principal_id="alice",
        session_id="session",
        call_id="call-1",
    )
    manager.retire_release("tools/demo/releases/A")
    assert manager.cleanup().removed_checkouts == ()

    manager.update_channel("tools/demo/stable", release_b.binding.tool_commit)
    report = manager.cleanup()
    assert report.removed_checkouts == (release_a.binding.tool_commit,)
    assert release_b.binding.tool_commit in report.retained_commits


def test_remote_configuration_is_operator_pinned_and_immutable(tmp_path: Path) -> None:
    ostree = _fake_ostree(tmp_path)
    publisher = OstreeDeploymentManager(tmp_path / "publisher", ostree_path=ostree)
    source = tmp_path / "source"
    _bundle(source, "REMOTE")
    published = publisher.publish_bundle(source, "tools/demo/releases/remote-A")
    runtime_source = tmp_path / "runtime"
    _runtime(runtime_source)
    published_runtime = publisher.publish_runtime(
        runtime_source, "runtimes/python-test/releases/remote-A"
    )
    manager = OstreeDeploymentManager(tmp_path / "store", ostree_path=ostree)
    public_key = tmp_path / "publisher.gpg"
    public_key.write_bytes(b"operator-approved-key")
    remote_url = f"file://{publisher.repo}"
    remote = manager.configure_remote(
        "publisher",
        remote_url,
        public_key=public_key,
    )

    assert remote.name == "publisher"
    assert (
        manager.configure_remote(
            "publisher",
            remote_url,
            public_key=public_key,
        )
        == remote
    )
    with pytest.raises(DeploymentError, match="immutable"):
        manager.configure_remote(
            "publisher",
            "https://attacker.example.test/repo",
            public_key=public_key,
        )
    with pytest.raises(DeploymentError, match="not trusted"):
        manager.pull_verified_release(
            "unknown", "tools/demo/stable", "tools/demo/releases/remote-A"
        )
    imported = manager.pull_verified_release(
        "publisher", "tools/demo/releases/remote-A", "tools/demo/releases/imported-A"
    )
    assert imported.binding.tool_commit == published.binding.tool_commit
    imported_runtime = manager.pull_verified_runtime_release(
        "publisher",
        "runtimes/python-test/releases/remote-A",
        "runtimes/python-test/releases/imported-A",
    )
    assert imported_runtime.binding.runtime_commit == (
        published_runtime.binding.runtime_commit
    )


def test_channel_update_preserves_bound_code_through_tool_node(
    tmp_path: Path,
) -> None:
    manager = OstreeDeploymentManager(
        tmp_path / "store", ostree_path=_fake_ostree(tmp_path)
    )
    source_a = tmp_path / "source-a"
    source_b = tmp_path / "source-b"
    _bundle(source_a, "A")
    _bundle(source_b, "B")
    release_a = manager.publish_bundle(source_a, "tools/demo/releases/A")
    release_b = manager.publish_bundle(source_b, "tools/demo/releases/B")
    manager.update_channel("tools/demo/stable", release_a.binding.tool_commit)
    profiles = parse_profiles(
        """
tool demo {
  owner analyst
  grant analyst: call
  runs linux
  syscalls @minimal
}
principal alice {
  roles analyst
}
""",
        source="deployment-test.slp",
    )
    spec = LinuxToolSpec.from_selection(
        manager, tool_id="demo", selection="tools/demo/stable"
    )
    unrelated_runtime = tmp_path / "unrelated-runtime"
    unrelated_runtime.mkdir()
    (unrelated_runtime / "helper.py").write_text("VALUE = 'HOST'\n")
    try:
        executor = LinuxSandboxExecutor(
            profiles,
            {"demo": spec},
            runtime_roots=(unrelated_runtime, Path("/usr")),
            policy_backend=TypedPolicyBackend(),
        )
    except RuntimeError as exc:
        pytest.skip(str(exc))

    @tool
    @dac(owner="analyst", grants={"analyst": "x", "*": "-"})
    def demo() -> str:
        """Trusted schema stub which must never run in process."""
        raise AssertionError("schema stub executed")

    security = SecurityConfig(
        dac_overrides=DacOverrides(profiles=profiles.tools),
        host_executor=executor,
    )
    node = ToolNode((demo,), security=security)
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")
    runtime = Mock(store=None, context=None, stream_writer=lambda _: None)
    config = with_principal({"configurable": {"__pregel_runtime": runtime}}, principal)

    def invoke(call_id: str) -> str:
        result = node.invoke(
            {
                "messages": [
                    AIMessage(
                        content="",
                        tool_calls=[{"name": "demo", "args": {}, "id": call_id}],
                    )
                ]
            },
            config=config,
        )
        return str(result["messages"][0].content)

    assert invoke("call-1") == "A"
    manager.update_channel("tools/demo/stable", release_b.binding.tool_commit)
    assert invoke("call-2") == "B"
    assert invoke("call-1") == "A"
    receipts = executor.activation_receipts()
    assert [item.deployment_digest for item in receipts] == [
        release_a.binding.tool_commit,
        release_b.binding.tool_commit,
        release_a.binding.tool_commit,
    ]


def test_approval_restart_recovers_authenticated_deployment_selection(
    tmp_path: Path,
) -> None:
    ostree = _fake_ostree(tmp_path)
    store = tmp_path / "store"
    manager = OstreeDeploymentManager(store, ostree_path=ostree)
    source_a = tmp_path / "source-a"
    source_b = tmp_path / "source-b"
    _bundle(source_a, "A")
    _bundle(source_b, "B")
    release_a = manager.publish_bundle(source_a, "tools/demo/releases/A")
    release_b = manager.publish_bundle(source_b, "tools/demo/releases/B")
    manager.update_channel("tools/demo/stable", release_a.binding.tool_commit)
    runtime_source = tmp_path / "runtime"
    _host_python_runtime(runtime_source)
    runtime_a = manager.publish_runtime(runtime_source, "runtimes/python/releases/A")
    (runtime_source / "usr" / "lib" / "runtime-version").write_text("B\n")
    runtime_b = manager.publish_runtime(runtime_source, "runtimes/python/releases/B")
    manager.update_runtime_channel(
        "runtimes/python/stable", runtime_a.binding.runtime_commit
    )
    profiles = parse_profiles(
        """
tool demo {
  owner analyst
  grant analyst: call
  runs linux
  syscalls @minimal
}
principal alice {
  roles analyst
}
""",
        source="deployment-restart-test.slp",
    )

    class ApprovalModule(SecurityModule):
        name = "deployment_approval"
        can_escalate = True

        def tool_call_permission(self, principal, call):
            return Decision(
                Verdict.ESCALATE,
                "approval_required",
                escalation=EscalationRequest(
                    "deployment-request",
                    "review deployment",
                    call.tool.name,
                    call.call_id,
                ),
            )

    @tool
    @dac(owner="analyst", grants={"analyst": "x", "*": "-"})
    @effects(Effect.WRITE)
    def demo() -> str:
        """Trusted schema stub which must never run in process."""
        raise AssertionError("schema stub executed")

    checkpoint_key = b"operator-managed-persistent-checkpoint-key"
    checkpoint_path = tmp_path / "checkpoints.sqlite3"
    approval = ApprovalModule()
    principal = Principal("alice", frozenset({"analyst"}), frozenset(), "session")

    def graph_for(current_manager: OstreeDeploymentManager, saver: SqliteSaver):
        spec = LinuxToolSpec.from_selection(
            current_manager, tool_id="demo", selection="tools/demo/stable"
        )
        executor = LinuxSandboxExecutor(
            profiles,
            {"demo": spec},
            runtime_roots=(),
            runtime_manager=current_manager,
            runtime_selection="runtimes/python/stable",
            policy_backend=TypedPolicyBackend(),
        )
        security = SecurityConfig(
            checkpoint_key=checkpoint_key,
            dac_overrides=DacOverrides(profiles=profiles.tools),
            host_executor=executor,
            modules=(approval,),
        )
        builder = StateGraph(MessagesState)
        builder.add_node("tools", ToolNode((demo,)))
        builder.add_edge(START, "tools")
        return builder.compile(checkpointer=saver, security=security), executor

    config = with_principal(
        {"configurable": {"thread_id": "deployment-restart"}},
        principal,
        modules=(approval,),
    )
    request = {
        "messages": [
            AIMessage(
                content="", tool_calls=[{"name": "demo", "args": {}, "id": "call-1"}]
            )
        ]
    }
    try:
        with SqliteSaver.from_conn_string(os.fspath(checkpoint_path)) as saver:
            graph, _ = graph_for(manager, saver)
            interrupted = graph.invoke(request, config=config)
            assert interrupted["__interrupt__"][0].value["request_id"] == (
                "deployment-request"
            )
    except RuntimeError as exc:
        pytest.skip(str(exc))

    manager.update_channel("tools/demo/stable", release_b.binding.tool_commit)
    manager.update_runtime_channel(
        "runtimes/python/stable", runtime_b.binding.runtime_commit
    )
    restarted_manager = OstreeDeploymentManager(store, ostree_path=ostree)
    with SqliteSaver.from_conn_string(os.fspath(checkpoint_path)) as saver:
        restarted_graph, restarted_executor = graph_for(restarted_manager, saver)
        result = restarted_graph.invoke(
            Command(resume={"approved": True}), config=config
        )

    assert result["messages"][-1].content == "A"
    assert restarted_executor.activation_receipts()[-1].deployment_digest == (
        release_a.binding.tool_commit
    )
    assert restarted_executor.activation_receipts()[-1].runtime_digest == (
        runtime_a.binding.runtime_commit
    )
