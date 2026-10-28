"""Alternative host backends, paired with the production verified-language path."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import shutil
import statistics
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
from collections import Counter, defaultdict
from contextlib import ExitStack, contextmanager
from pathlib import Path
from unittest.mock import patch

from langgraph.prebuilt.security import Effect, Principal, ToolCall, cedar_security
from langgraph.prebuilt.security.inprocess import ManifestAdmission
from langgraph.prebuilt.security.types import Tool, ToolDac

from . import run as census
from .cases import cases
from .operations import instrument, operations
from .run import digest
from .runtime import host_snapshot, stats, timed
from .verified import MANIFEST, POLICY, WORKLOADS, admission_census

REPO = Path(__file__).resolve().parents[4]
WORKER = Path(__file__).with_name("alternative_worker.py")
SECCOMP = REPO / "libs/prebuilt/langgraph/prebuilt/security/_linux_worker.py"
MODES = ("verified", "landlock", "container")


def execute(
    mode, source, parameters, readable, writable, image, container=None, python=None, extra_paths=()
):
    request = dict(
        mode=mode,
        cpu=min(os.sched_getaffinity(0)),
        source=source,
        p=parameters,
        readable=readable,
        writable=writable,
        seccomp_source=str(SECCOMP),
        python_paths=list(extra_paths),
    )
    environment = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "OPENBLAS_NUM_THREADS": "1",
        "OMP_NUM_THREADS": "1",
    }
    if mode == "container":
        name = "slg-eval-" + uuid.uuid4().hex
        command = [
            "docker",
            "run",
            "--rm",
            "-i",
            "--name",
            name,
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--user",
            "0:0",
            "--pids-limit=32",
            "--memory=1g",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=64m",
        ]
        for path in [str(WORKER), str(SECCOMP), *readable]:
            # Image supplies runtime libraries; only bind explicit application paths and code.
            if path in runtime_reads():
                continue
            command += ["--mount", f"type=bind,src={path},dst={path},readonly"]
        for path in writable:
            command += ["--mount", f"type=bind,src={path},dst={path}"]
        command += [
            "--entrypoint",
            "/usr/bin/taskset",
            image,
            "-c",
            str(min(os.sched_getaffinity(0))),
            "/usr/bin/python3",
            "-I",
            "-S",
            str(WORKER),
        ]
        environment = None  # Docker client must retain its rootless-daemon connection.
    else:
        name = None
        command = [python or sys.executable, "-I", "-S", str(WORKER)]
    if container is not None:
        if mode != "container":
            raise ValueError("container handle requires container mode")
        command = [
            "docker",
            "exec",
            "-i",
            "-e",
            "OPENBLAS_NUM_THREADS=1",
            "-e",
            "OMP_NUM_THREADS=1",
            container,
            "/usr/bin/taskset",
            "-c",
            str(min(os.sched_getaffinity(0))),
            python or "/usr/bin/python3",
            "-I",
            "-S",
            str(WORKER),
        ]
        name = None
    try:
        result = subprocess.run(
            command,
            input=json.dumps(request),
            capture_output=True,
            text=True,
            timeout=15,
            env=environment,
        )
    except subprocess.TimeoutExpired:
        if name:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        raise
    if result.returncode:
        raise RuntimeError(f"{mode} worker exit {result.returncode}: {result.stderr[:800]}")
    response = json.loads(result.stdout)
    if response["cpu_affinity"] != [min(os.sched_getaffinity(0))]:
        raise RuntimeError("worker affinity mismatch")
    return response


@contextmanager
def container_session(readable, writable, image, lifecycle):
    """Keep confinement alive while each invocation gets a fresh Python process."""
    name = "slg-eval-session-" + uuid.uuid4().hex
    command = [
        "docker",
        "run",
        "-d",
        "--name",
        name,
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user",
        "0:0",
        "--pids-limit=32",
        "--memory=1g",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",
    ]
    for path in [str(WORKER), str(SECCOMP), *readable]:
        if path not in runtime_reads():
            command += ["--mount", f"type=bind,src={path},dst={path},readonly"]
    for path in writable:
        command += ["--mount", f"type=bind,src={path},dst={path}"]
    command += ["--entrypoint", "/bin/sleep", image, "infinity"]
    start = time.perf_counter_ns()
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=20)
        entry = dict(
            command=command,
            container_id=result.stdout.strip(),
            launch_stderr=result.stderr,
            setup_ms=(time.perf_counter_ns() - start) / 1e6,
        )
        lifecycle.append(entry)
        yield name
    finally:
        start = time.perf_counter_ns()
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=20)
        if "entry" in locals():
            entry["teardown_ms"] = (time.perf_counter_ns() - start) / 1e6


def runtime_reads():
    return [
        p
        for p in ["/usr", "/lib", "/lib64", "/etc/ld.so.cache", "/dev/urandom"]
        if Path(p).exists()
    ]


def shared_call(executor, arguments):
    tool = Tool("run", ToolDac("analyst", {"analyst": "x", "*": "-"}), frozenset({Effect.READ}), ())
    principal = Principal("evaluator", frozenset({"analyst"}), frozenset(), "alternative-eval")
    call = ToolCall(tool, arguments, arguments, uuid.uuid4().hex, 0)
    return principal, call


def compare(output, image, session, samples, warmup):
    rows, setup, lifecycle = [], [], []
    rng = random.Random(20261101 + session)
    spans = defaultdict(float)
    with (
        tempfile.TemporaryDirectory(prefix="eval-alternative-read-") as temporary,
        ExitStack() as stack,
    ):
        root = Path(temporary)
        path = root / "allowed"
        path.write_text("")
        containers = {
            True: stack.enter_context(container_session([str(path)], [], image, lifecycle)),
            False: stack.enter_context(container_session([], [], image, lifecycle)),
        }
        executors = {}
        with patch.object(
            ManifestAdmission, "__init__", timed(spans, "admission", ManifestAdmission.__init__)
        ):
            for name, (function, _size, repeats) in WORKLOADS.items():
                for index in range(samples):
                    spans.clear()
                    start = time.perf_counter_ns()
                    security = cedar_security(
                        function, policy=POLICY, manifest=MANIFEST if repeats else "runs inprocess"
                    )
                    setup.append(
                        dict(
                            case=name,
                            session=session,
                            round=index,
                            elapsed_ms=(time.perf_counter_ns() - start) / 1e6,
                            admission_ms=spans["admission"],
                        )
                    )
                executors[name] = security.host_executor
        with (output / "comparison.jsonl").open("x") as stream:
            for index in range(1 + warmup + samples):
                jobs = [(name, mode) for name in WORKLOADS for mode in MODES]
                rng.shuffle(jobs)
                for name, mode in jobs:
                    _, size, repeats = WORKLOADS[name]
                    path = root / "allowed"
                    payload = ("0123456789abcdef" * ((size + 15) // 16))[:size]
                    path.write_text(payload)
                    arguments = {"path": str(path)} if repeats else {}
                    expected = payload if repeats else 42
                    executor = executors[name]
                    principal, call = shared_call(executor, arguments)
                    start = time.perf_counter_ns()
                    grant = executor._authorize(principal, call, ())
                    policy_ms = (time.perf_counter_ns() - start) / 1e6
                    dispatch_start = time.perf_counter_ns()
                    telemetry = None
                    if mode == "verified":
                        result = executor.dispatcher.invoke(principal, call, grant)
                        result = executor._verify_result(result, grant)
                        value = result.value
                    else:
                        reads = []
                        for line in grant.lines:
                            if line.class_name != "fs" or line.operation != "read":
                                raise RuntimeError("unhandled grant")
                            reads.append(line.selector)
                        source = "result = 42" if not repeats else "result = open(p['path']).read()"
                        if repeats == 2:
                            source += "\nresult = open(p['path']).read()"
                        telemetry = execute(
                            mode,
                            source,
                            arguments,
                            runtime_reads() + reads,
                            [],
                            image,
                            container=containers[bool(repeats)] if mode == "container" else None,
                        )
                        value = telemetry.get("value")
                    execution_ms = (time.perf_counter_ns() - dispatch_start) / 1e6
                    elapsed = (time.perf_counter_ns() - start) / 1e6
                    row = dict(
                        case=name,
                        condition=mode,
                        session=session,
                        round=index,
                        phase="first_use"
                        if index == 0
                        else "warmup"
                        if index <= warmup
                        else "measured",
                        elapsed_ms=elapsed,
                        policy_ms=policy_ms,
                        execution_ms=execution_ms,
                        valid=value == expected,
                        grant_digest=grant.digest,
                        grant_lines=[line.canonical() for line in grant.lines],
                        value_sha256=hashlib.sha256(str(value).encode()).hexdigest(),
                        expected_sha256=hashlib.sha256(str(expected).encode()).hexdigest(),
                        worker_telemetry=telemetry,
                    )
                    stream.write(json.dumps(row) + "\n")
                    stream.flush()
                    rows.append(row)
                    if not row["valid"]:
                        raise RuntimeError(f"positive control failed: {name}/{mode}: {telemetry}")
                print(f"comparison session {session} round {index}", flush=True)
        (output / "setup.json").write_text(json.dumps(setup, indent=2))
    (output / "comparison-lifecycle.json").write_text(json.dumps(lifecycle, indent=2))
    return rows


def operation_trial(case, mode, image, repetition):
    """Reuse original fixtures and independent parent effect oracles."""

    def invoke(root, arguments):
        response = execute(
            mode,
            arguments["source"],
            arguments["p"],
            [*runtime_reads(), str(root / "allowed")],
            [str(root / "output")],
            image,
        )
        # Explicitly telemetry, not a production or signed activation receipt.
        return response, {"evaluation_backend": mode, "not_a_production_receipt": True}

    with (
        patch.object(census, "make_executor", lambda root: root),
        patch.object(census, "invoke_host", invoke),
    ):
        row = census.trial(case, "host", repetition)
    row["condition"] = mode
    return row


def operation_batch(output, image, session, samples, warmup):
    rng = random.Random(20261201 + session)
    lifecycle = []
    with tempfile.TemporaryDirectory(prefix="eval-operation-") as temporary:
        root = Path(temporary)
        allowed, writable = root / "allowed", root / "output"
        allowed.write_text("")
        writable.mkdir()
        with (
            container_session([str(allowed)], [str(writable)], image, lifecycle) as container,
            (output / "operations.jsonl").open("x") as stream,
        ):
            for index in range(1 + warmup + samples):
                jobs = [
                    (instrument(case), mode)
                    for case in operations()
                    for mode in ("plain", "landlock", "container")
                ]
                rng.shuffle(jobs)
                for case, mode in jobs:
                    for child in writable.iterdir():
                        if child.is_dir() and not child.is_symlink():
                            shutil.rmtree(child)
                        else:
                            child.unlink()
                    token = uuid.uuid4().hex
                    allowed.write_text(token)
                    target = allowed if case.surface == "readonly" else writable / "target"
                    target.write_text(token)
                    (writable / "result").write_text("")
                    (writable / "link").symlink_to(target)
                    parameters = dict(
                        target=str(target),
                        allowed=str(allowed),
                        output=str(writable / "result"),
                        new=str(target.parent / "new"),
                        secret_dir=str(target.parent),
                        basename=target.name,
                        token=token,
                    )
                    before = dict(mode=target.stat().st_mode, mtime=target.stat().st_mtime_ns)
                    start = time.perf_counter_ns()
                    response = execute(
                        mode,
                        case.source,
                        {k: v for k, v in parameters.items() if k != "token"},
                        [*runtime_reads(), str(allowed)],
                        [str(writable)],
                        image,
                        container=container if mode == "container" else None,
                    )
                    elapsed = (time.perf_counter_ns() - start) / 1e6
                    effect = census.observe(case, parameters, response, before, b"")
                    row = dict(
                        case=case.name,
                        condition=mode,
                        session=session,
                        round=index,
                        phase="first_use"
                        if index == 0
                        else "warmup"
                        if index <= warmup
                        else "measured",
                        elapsed_ms=elapsed,
                        effect_observed=effect,
                        response=response,
                        evidence=dict(
                            expected_token=token,
                            target_exists=target.exists(),
                            target_sha256=digest(target) if target.is_file() else None,
                            output_size=(writable / "result").stat().st_size,
                            output_sha256=digest(writable / "result"),
                            new_exists=Path(parameters["new"]).exists(),
                        ),
                    )
                    stream.write(json.dumps(row) + "\n")
                    stream.flush()
                    if not effect:
                        raise RuntimeError(
                            f"positive operation failed: {case.name}/{mode}: {response}"
                        )
                print(f"operations session {session} round {index}", flush=True)
    (output / "operations-lifecycle.json").write_text(json.dumps(lifecycle, indent=2))


def application_batch(output, image, session, samples, warmup):
    upstream = Path("/data/slanggraph-eval-upstreams/ai-data-science-team")
    python = (upstream / ".venv/bin/python").resolve()
    runtime = python.parent.parent
    site = next((upstream / ".venv/lib").glob("python*/site-packages"))
    sandbox = upstream / "ai_data_science_team/utils/sandbox.py"
    wrapper = REPO / "eval/apps/pandas/worker.py"
    trace = REPO / "eval/results/pandas-runtime-20261026-v1/trace.json"
    payload = json.loads(trace.read_text())
    readable = [*runtime_reads(), str(runtime), str(site), str(sandbox), str(wrapper)]
    lifecycle = []
    rng = random.Random(20261301 + session)
    source = (
        "import importlib.util\n"
        "spec = importlib.util.spec_from_file_location('application_worker', p['wrapper'])\n"
        "module = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(module)\n"
        "result = module.compute(p['sandbox'], p['payload'])\n"
    )
    plan = dict(
        python=str(python),
        python_sha256=digest(python),
        source_hashes={str(p): digest(p) for p in (sandbox, wrapper, trace)},
        payload=payload,
        source=source,
        modes=["plain", "landlock", "container"],
    )
    (output / "application-plan.json").write_text(json.dumps(plan, indent=2))
    with (
        container_session(readable, [], image, lifecycle) as container,
        (output / "application.jsonl").open("x") as stream,
    ):
        for index in range(1 + warmup + samples):
            order = ["plain", "landlock", "container"]
            rng.shuffle(order)
            for mode in order:
                start = time.perf_counter_ns()
                response = execute(
                    mode,
                    source,
                    dict(wrapper=str(wrapper), sandbox=str(sandbox), payload=payload),
                    readable,
                    [],
                    image,
                    container=container if mode == "container" else None,
                    python=str(python),
                    extra_paths=[str(site)],
                )
                elapsed = (time.perf_counter_ns() - start) / 1e6
                value = response.get("value")
                valid = (
                    isinstance(value, dict)
                    and not value.get("error")
                    and value.get("result") == {"total_sales": {"0": 120}}
                )
                # The upstream runner returns records rather than a frame in some pinned versions.
                if isinstance(value, dict) and not value.get("error"):
                    valid = value.get("result") in (
                        {"total_sales": {"0": 120}},
                        [{"total_sales": 120}],
                        {"total_sales": [120]},
                    )
                row = dict(
                    case="pandas_february",
                    condition=mode,
                    session=session,
                    round=index,
                    phase="first_use"
                    if index == 0
                    else "warmup"
                    if index <= warmup
                    else "measured",
                    elapsed_ms=elapsed,
                    valid=valid,
                    response=response,
                )
                stream.write(json.dumps(row) + "\n")
                stream.flush()
                if not valid:
                    raise RuntimeError(f"application oracle failed: {mode}: {response}")
            print(f"application session {session} round {index}", flush=True)
    (output / "application-lifecycle.json").write_text(json.dumps(lifecycle, indent=2))


def security_batch(output, image):
    rows = []
    with (output / "security.jsonl").open("x") as stream:
        for repetition in range(3):
            for case in cases():
                for mode in ("plain", "landlock", "container"):
                    row = (
                        census.trial(case, "trusted", repetition)
                        if mode == "plain"
                        else operation_trial(case, mode, image, repetition)
                    )
                    row["condition"] = mode
                    rows.append(row)
                    stream.write(json.dumps(row) + "\n")
                    stream.flush()
            print(f"security repetition {repetition}", flush=True)
    return rows


def interval(values):
    sd = statistics.stdev(values)
    mean = statistics.mean(values)
    half = 2.7764451051977987 * sd / (5**0.5)
    return dict(
        mean_ms=mean, session_sd_ms=sd, ci95_ms=[mean - half, mean + half], session_means_ms=values
    )


def summarize(rows, modes, samples):
    result = {}
    for case in sorted({r["case"] for r in rows}):
        measured = [r for r in rows if r["case"] == case and r["phase"] == "measured"]
        assert Counter(r["condition"] for r in measured) == dict.fromkeys(modes, 5 * samples)
        for row in measured:
            assert row.get("valid", row.get("effect_observed", False))
        groups = {
            mode: {(r["session"], r["round"]): r for r in measured if r["condition"] == mode}
            for mode in modes
        }
        assert all(len(g) == 5 * samples for g in groups.values())
        assert all(g.keys() == groups[modes[0]].keys() for g in groups.values())
        summaries = {
            mode: stats([r["elapsed_ms"] for r in g.values()]) for mode, g in groups.items()
        }
        contrasts = {}
        for mode in modes[1:]:
            deltas = {
                key: groups[mode][key]["elapsed_ms"] - groups[modes[0]][key]["elapsed_ms"]
                for key in groups[mode]
            }
            means = [
                statistics.mean(v for (s, _), v in deltas.items() if s == session)
                for session in range(5)
            ]
            contrasts[mode + "-" + modes[0]] = dict(
                paired=stats(list(deltas.values())),
                interval=interval(means),
                ratio=summaries[mode]["mean_ms"] / summaries[modes[0]]["mean_ms"],
            )
        result[case] = dict(conditions=summaries, contrasts=contrasts)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--session", type=int)
    parser.add_argument("--samples", type=int, default=20)
    parser.add_argument("--warmup", type=int, default=10)
    parser.add_argument("--image", default="slg-linux-test:latest")
    args = parser.parse_args()
    os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    image = subprocess.check_output(
        ["docker", "image", "inspect", args.image, "--format", "{{.Id}}"], text=True
    ).strip()
    (output / "host.json").write_text(json.dumps(host_snapshot(), indent=2))
    if args.session is not None:
        compare(output, image, args.session, args.samples, args.warmup)
        operation_batch(output, image, args.session, args.samples, args.warmup)
        application_batch(output, image, args.session, args.samples, args.warmup)
        (output / "host-after.json").write_text(json.dumps(host_snapshot(), indent=2))
        return
    plan = dict(
        modes=MODES,
        image=image,
        sessions=5,
        samples_per_session=args.samples,
        warmup_per_session=args.warmup,
        security_repetitions=3,
        policy=POLICY,
        source_hashes={},
    )
    with tarfile.open(output / "sources.tar.gz", "w:gz") as archive:
        for root in (
            Path(__file__).parent,
            REPO / "libs/prebuilt/langgraph",
            REPO / "libs/langgraph/langgraph",
            REPO / "libs/checkpoint/langgraph",
        ):
            for path in sorted(root.rglob("*.py")):
                relative = str(path.relative_to(REPO))
                plan["source_hashes"][relative] = digest(path)
                archive.add(path, arcname=relative)
    plan["container_security"] = subprocess.check_output(
        ["docker", "info", "--format", "{{json .SecurityOptions}}"], text=True
    ).strip()
    plan["container_lifecycle"] = (
        "persistent per grant/session; fresh Python worker per invocation; setup/teardown separate"
    )
    plan["backend_status"] = "evaluation adapters; not production LinuxSandboxExecutor"
    plan["archive_sha256"] = digest(output / "sources.tar.gz")
    (output / "plan.json").write_text(json.dumps(plan, indent=2))
    with tempfile.TemporaryDirectory() as temporary:
        (output / "admission-census.json").write_text(
            json.dumps(admission_census(Path(temporary)), indent=2)
        )
    # Validate security first; preserve exposures instead of hiding them.
    security_batch(output, image)
    for session in range(5):
        cmd = [
            sys.executable,
            "-m",
            "slanggraph_eval.isolation.alternatives",
            "--output",
            str(output / f"session-{session}"),
            "--session",
            str(session),
            "--image",
            image,
            "--samples",
            str(args.samples),
            "--warmup",
            str(args.warmup),
        ]
        with (output / f"session-{session}.log").open("w") as log:
            subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, check=True)
        print(f"completed session {session + 1}/5", flush=True)
    for name, modes in [
        ("comparison", MODES),
        ("operations", ("plain", "landlock", "container")),
        ("application", ("plain", "landlock", "container")),
    ]:
        rows = [
            json.loads(line)
            for session in range(5)
            for line in (output / f"session-{session}" / f"{name}.jsonl").read_text().splitlines()
        ]
        (output / f"{name}.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))
        (output / f"{name}-summary.json").write_text(
            json.dumps(summarize(rows, modes, args.samples), indent=2)
        )
    (output / "complete.json").write_text(
        json.dumps({"complete": True, "measured_per_cell": 5 * args.samples})
    )


if __name__ == "__main__":
    main()
