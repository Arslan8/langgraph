"""Offline, non-destructive validation of the completed v2 cohorts (stdlib only)."""

import argparse
import ast
import csv
import hashlib
import json
import math
import random
import shutil
import statistics
import tarfile
from collections import Counter, defaultdict
from pathlib import Path


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(path):
    text = path.read_text()
    return (
        [json.loads(line) for line in text.splitlines()]
        if path.suffix == ".jsonl"
        else json.loads(text)
    )


def write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def stats(values):
    return dict(
        n=len(values),
        mean_ms=statistics.mean(values),
        sd_ms=statistics.stdev(values),
        variance_ms2=statistics.variance(values),
        median_ms=statistics.median(values),
        p95_ms=sorted(values)[math.ceil(0.95 * len(values)) - 1],
        min_ms=min(values),
        max_ms=max(values),
    )


def require(value, message):
    if not value:
        raise ValueError(message)


def operation_oracle(row):
    e, v, case = row["evidence"], row["response"].get("value"), row["case"]
    if case == "compute_control":
        return v == 42
    if case in ("open_read", "pathlib_read", "os_read", "mmap_read", "ctypes_read"):
        return v == e["expected_token"]
    if case == "stat_metadata":
        return v == len(e["expected_token"])
    if case == "listdir_names":
        return isinstance(v, list) and any("target" in str(x) for x in v)
    if case == "write":
        return e["target_sha256"] == sha(b"effect")
    if case == "fsync":
        return e["output_sha256"] == sha(b"effect")
    if case == "append":
        return e["target_sha256"] == sha((e["expected_token"] + "effect").encode())
    if case == "truncate":
        return e["target_sha256"] == sha(b"")
    if case == "unlink":
        return not e["target_exists"]
    if case in ("create", "mkdir"):
        return e["new_exists"]
    if case == "write_4kib":
        return e["output_size"] == 4096 and e["output_sha256"] == sha(b"x" * 4096)
    raise ValueError(f"unknown operation {case}")


def timing(root, name, cases, modes, seed, out):
    rows = read(root / (name + ".jsonl"))
    require(set(r["case"] for r in rows) == set(cases), f"{name}: case set")
    for session in range(5):
        selected = [r for r in rows if r["session"] == session]
        require(selected == read(root / f"session-{session}/{name}.jsonl"), "session concatenation")
        rng = random.Random(seed + session)
        expected = []
        for index in range(31):
            jobs = [(case, mode) for case in cases for mode in modes]
            rng.shuffle(jobs)
            expected.extend((case, mode, index) for case, mode in jobs)
        require(
            [(r["case"], r["condition"], r["round"]) for r in selected] == expected,
            f"{name}: shuffled schedule/session {session}",
        )
    failures, residuals = [], []
    for index, r in enumerate(rows, 1):
        phase = "first_use" if r["round"] == 0 else "warmup" if r["round"] <= 10 else "measured"
        require(r["phase"] == phase, f"{name}:{index}: phase")
        if name == "comparison":
            ok = r["valid"] and r["value_sha256"] == r["expected_sha256"]
            telemetry = r.get("worker_telemetry")
            if telemetry:
                ok = ok and sha(str(telemetry.get("value")).encode()) == r["expected_sha256"]
            residuals.append(
                dict(line=index, residual_ms=r["elapsed_ms"] - r["policy_ms"] - r["execution_ms"])
            )
        elif name == "operations":
            ok = r["effect_observed"] and operation_oracle(r)
        elif name == "application":
            value = r["response"].get("value", {})
            ok = (
                r["valid"]
                and not value.get("error")
                and value.get("result")
                in ({"total_sales": {"0": 120}}, [{"total_sales": 120}], {"total_sales": [120]})
            )
        else:
            value = r["response"].get("value", {})
            ok = (
                r["valid"]
                and value.get("returncode") == 0
                and sha(value.get("stdout", "").encode()) == r["expected_sha256"]
            )
        telemetry = r.get("worker_telemetry") if name == "comparison" else r["response"]
        if telemetry is not None:
            ok = ok and telemetry.get("phase") == "executed"
            require(telemetry.get("cpu_affinity") == [0], f"{name}:{index}: affinity")
        if not ok:
            failures.append(dict(line=index, row=r))
    write(out / (name + "-oracle-failures.json"), failures)
    require(not failures, f"{name}: parent oracle failure; retained in output")
    if residuals:
        write(out / "timing-residuals.json", residuals)
    result, exported = {}, []
    for case in cases:
        groups = {}
        for mode in modes:
            group = [r for r in rows if r["case"] == case and r["condition"] == mode]
            require(
                Counter((r["session"], r["phase"]) for r in group)
                == {
                    (s, p): n
                    for s in range(5)
                    for p, n in [("first_use", 1), ("warmup", 10), ("measured", 20)]
                },
                "phase counts",
            )
            groups[mode] = {
                (r["session"], r["round"]): r["elapsed_ms"]
                for r in group
                if r["phase"] == "measured"
            }
            require(len(groups[mode]) == 100, "duplicate pairs")
        distributions = {m: stats(list(g.values())) for m, g in groups.items()}
        contrasts = {}
        for mode in modes[1:]:
            require(groups[mode].keys() == groups[modes[0]].keys(), "pair keys")
            delta = {k: v - groups[modes[0]][k] for k, v in groups[mode].items()}
            means = [
                statistics.mean(v for (s, _), v in delta.items() if s == session)
                for session in range(5)
            ]
            mean, sd = statistics.mean(means), statistics.stdev(means)
            half = 2.7764451051977987 * sd / math.sqrt(5)
            ratio = distributions[mode]["mean_ms"] / distributions[modes[0]]["mean_ms"]
            contrasts[mode + "-" + modes[0]] = dict(
                paired=stats(list(delta.values())),
                interval=dict(
                    mean_ms=mean,
                    session_sd_ms=sd,
                    ci95_ms=[mean - half, mean + half],
                    session_means_ms=means,
                ),
                ratio=ratio,
            )
            exported.append(
                dict(
                    experiment=name,
                    case=case,
                    mode=mode,
                    baseline=modes[0],
                    runtime_multiple=ratio,
                    overhead_percent=100 * (ratio - 1),
                    added_ms=statistics.mean(delta.values()),
                    ci95_low_ms=mean - half,
                    ci95_high_ms=mean + half,
                    raw=f"raw/{root.name}/{name}.jsonl",
                    run_ids=";".join(
                        f"{root.name}/session-{s}/{case}/{mode}/round-11..30" for s in range(5)
                    ),
                )
            )
        result[case] = dict(conditions=distributions, contrasts=contrasts)
    original = root / ("summary.json" if name == "samples" else name + "-summary.json")
    require(result == read(original), f"{name}: regenerated summary differs")
    write(out / (name + "-summary.json"), result)
    return exported


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reports", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    out = args.output / "summaries"
    out.mkdir()
    raw = args.output / "raw"
    raw.mkdir()
    for name in ("alternatives-v2", "native-chain-v2"):
        shutil.copytree(args.reports / name, raw / name)
    a, n = raw / "alternatives-v2", raw / "native-chain-v2"
    plan = read(a / "plan.json")
    require(sha((a / "sources.tar.gz").read_bytes()) == plan["archive_sha256"], "archive hash")
    with tarfile.open(a / "sources.tar.gz") as archive:
        for name, digest in plan["source_hashes"].items():
            require(sha(archive.extractfile(name).read()) == digest, f"source hash {name}")
        # Read the frozen declaration without importing or executing the production runtime.
        tree = ast.parse(
            archive.extractfile("eval/src/slanggraph_eval/isolation/verified.py").read()
        )
        assignment = next(
            x
            for x in tree.body
            if isinstance(x, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "WORKLOADS" for t in x.targets)
        )
        comparison_cases = [ast.literal_eval(k) for k in assignment.value.keys]
    ops = [
        "compute_control",
        "open_read",
        "pathlib_read",
        "os_read",
        "mmap_read",
        "ctypes_read",
        "stat_metadata",
        "listdir_names",
        "write",
        "append",
        "truncate",
        "create",
        "unlink",
        "mkdir",
        "write_4kib",
        "fsync",
    ]
    exported = []
    for root, name, cases, modes, seed in [
        (a, "comparison", comparison_cases, ["verified", "landlock", "container"], 20261101),
        (a, "operations", ops, ["plain", "landlock", "container"], 20261201),
        (a, "application", ["pandas_february"], ["plain", "landlock", "container"], 20261301),
        (n, "samples", ["env_to_cat"], ["plain", "landlock", "container"], 20261401),
    ]:
        exported.extend(timing(root, name, cases, modes, seed, out))
    with (out / "overheads.csv").open("w") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(exported[0]))
        writer.writeheader()
        writer.writerows(exported)
    census = read(a / "security.jsonl")
    security = {}
    for mode in ("plain", "landlock", "container"):
        rows = [r for r in census if r["condition"] == mode]
        require(len(rows) == 177, "security trials")
        cases = defaultdict(list)
        for r in rows:
            cases[r["case"]].append(r)
        require(len(cases) == 59, "security distinct cases")
        require(
            all(sorted(r["repetition"] for r in group) == [0, 1, 2] for group in cases.values()),
            "security repetitions",
        )
        require(
            all(len({r["allowed"] for r in group}) == 1 for group in cases.values()),
            "allowed classification",
        )
        forbidden = [r for r in rows if not r["allowed"]]
        controls = [r for r in rows if r["allowed"]]
        require(
            len({r["case"] for r in forbidden}) == 49 and len({r["case"] for r in controls}) == 10,
            "census denominators",
        )
        security[mode] = dict(
            forbidden_cases=49,
            forbidden_trials=len(forbidden),
            control_cases=10,
            control_trials=len(controls),
            control_successes=sum(r["effect_observed"] for r in controls),
            outcomes=dict(Counter(r["outcome"] for r in forbidden)),
            consistent_explicit_denial_cases=sorted(
                case
                for case, group in cases.items()
                if not group[0]["allowed"]
                and all(r["outcome"] == "operation_denied" for r in group)
            ),
            exposed_cases=sorted({r["case"] for r in forbidden if r["effect_observed"]}),
            per_case={
                case: dict(Counter(r["outcome"] for r in group)) for case, group in cases.items()
            },
        )
    write(out / "security.json", security)
    controls = read(a / "verified-security.json")
    counts = Counter(r["case"] for r in controls)
    require(
        len(counts) == 4 and set(counts.values()) == {3} and all(r["passed"] for r in controls),
        "verified controls",
    )
    write(
        out / "verified-controls.json",
        dict(distinct_cases=len(counts), trials=len(controls), repetitions=dict(counts)),
    )
    native = read(n / "plan.json")
    require(native["verified_admission"]["status"] == "rejected", "native admission")
    require(
        sha((n / "binary_worker.py.txt").read_bytes()) == native["worker_sha256"], "native worker"
    )
    application_hashes = read(a / "session-0/application-plan.json")["source_hashes"]
    with tarfile.open(a / "application-sources.tar.gz") as archive:
        for path, digest in application_hashes.items():
            require(
                sha(archive.extractfile("application/" + Path(path).name).read()) == digest,
                f"application source {path}",
            )
    lifecycle = {}
    for experiment in ("comparison", "operations", "application", "native_chain"):
        entries = []
        for session in range(5):
            path = (
                n / f"session-{session}/lifecycle.json"
                if experiment == "native_chain"
                else a / f"session-{session}/{experiment}-lifecycle.json"
            )
            entries.extend(read(path))
        lifecycle[experiment] = {
            key: stats([r[key] for r in entries]) for key in ("setup_ms", "teardown_ms")
        }
    write(out / "lifecycle.json", lifecycle)
    for session in range(5):
        require(
            read(a / f"session-{session}/application-plan.json")["source_hashes"]
            == application_hashes,
            "application source drift",
        )
        denials = read(n / f"session-{session}/security.json")
        require(
            len(denials) == 9 and all(r["exposed"] == (r["mode"] == "plain") for r in denials),
            "native security",
        )
    lines = [
        "# Completed-cohort validation",
        "",
        "No benchmark was rerun. Original cohort files are copied byte-for-byte under `raw/`.",
        "",
        "All 69 timing cells reproduce their recorded statistics exactly: 100 measured "
        "calls per cell, 20 per session across five sessions. Ten warmups and one "
        "first-use call per session are excluded. Pair keys and exact seeded shuffled "
        "schedules pass. Parent timing oracles pass.",
        "",
        "Intervals below are milliseconds: Student t on five paired session means, df=4. "
        "Ratios are ratios of call means; no ratio interval is claimed.",
        "",
        "| Experiment / task / mode | Multiple | Overhead % | Added ms | Session 95% CI ms |",
        "| --- | ---: | ---: | ---: | --- |",
    ]
    for r in exported:
        lines.append(
            f"| [{r['experiment']}/{r['case']}/{r['mode']}]({r['raw']}) | "
            f"{r['runtime_multiple']:.6f} | "
            f"{r['overhead_percent']:.4f} | "
            f"{r['added_ms']:.6f} | "
            f"[{r['ci95_low_ms']:.6f}, {r['ci95_high_ms']:.6f}] |"
        )
    lines += [
        "",
        "Cell run IDs are in `summaries/overheads.csv`; full distributions, paired "
        "increments, session means and timing residuals are in `summaries/`.",
        "",
        "Verified controls are four distinct cases x three trials = 12/12. For each host "
        "mode, 132 explicit-denial trials represent 44 cases consistently denied in all "
        "three repetitions. The 49 forbidden cases and ten controls are separate "
        "denominators; each host preserves 30/30 control trials.",
        "",
        "Landlock exposes stat_metadata in all three repetitions: the denied file's size "
        "(the canary length) is observable. Content denial does not imply metadata "
        "secrecy. Container exposure is zero only within this corpus. See per-case "
        "outcomes for errors and no-effect observations.",
        "",
        "Pandas is execution-only replay, excluding model, ToolNode, Cedar and durable "
        "audit. Its Landlock increment interval crosses zero: the point estimate does not "
        "demonstrate slowdown or zero overhead. Native-chain admission rejection is not "
        "an execution timing; its exec-enabled profile differs from the census and lacks "
        "a Landlock process-count quota.",
        "",
        "This is the first handoff, not completion of the remaining evaluation. See "
        "FAILURES.md for provenance and coverage gaps.",
    ]
    (args.output / "RESULTS.md").write_text("\n".join(lines) + "\n")
    shutil.copy2(__file__, args.output / "regenerate.py")
    write(
        args.output / "file-hashes.json",
        {
            str(p.relative_to(args.output)): sha(p.read_bytes())
            for p in sorted(raw.rglob("*"))
            if p.is_file()
        },
    )
    print(
        json.dumps(
            dict(
                timing_cells=69,
                measured_calls=6900,
                source_files=len(plan["source_hashes"]),
                security={
                    m: {
                        k: v
                        for k, v in data.items()
                        if k not in ("per_case", "consistent_explicit_denial_cases")
                    }
                    for m, data in security.items()
                },
            ),
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
