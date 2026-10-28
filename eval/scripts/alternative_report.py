"""Validate and publish the completed alternative-backend evaluation."""

import csv
import hashlib
import json
import tarfile
from collections import Counter
from pathlib import Path

from slanggraph_eval.isolation.alternatives import MODES, summarize
from slanggraph_eval.isolation.runtime import stats

ROOT = Path(__file__).resolve().parents[1] / "reports/alternatives-v2"


def read(name):
    path = ROOT / name
    return (
        [json.loads(line) for line in path.read_text().splitlines()]
        if path.suffix == ".jsonl"
        else json.loads(path.read_text())
    )


def timing_table(summary, baseline):
    lines = [
        "| Workload / mode | Mean ms | SD ms | Median ms | P95 ms | Added ms | Paired"
        " SD ms | Session 95% CI ms |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for case, data in summary.items():
        for mode, values in data["conditions"].items():
            delta = data["contrasts"].get(mode + "-" + baseline)
            if delta:
                paired = delta["paired"]
                lo, hi = delta["interval"]["ci95_ms"]
                tail = f"{paired['mean_ms']:.3f} | {paired['sd_ms']:.3f} | [{lo:.3f}, {hi:.3f}]"
            else:
                tail = "— | — | —"
            lines.append(
                f"| {case} / {mode} | {values['mean_ms']:.3f} | {values['sd_ms']:.3f} | "
                f"{values['median_ms']:.3f} | {values['p95_ms']:.3f} | {tail} |"
            )
    return lines


def main():
    plan = read("plan.json")
    complete = read("complete.json")
    assert complete == {"complete": True, "measured_per_cell": 100}
    assert (
        plan["sessions"] == 5
        and plan["samples_per_session"] == 20
        and plan["warmup_per_session"] == 10
    )
    assert (
        hashlib.sha256((ROOT / "sources.tar.gz").read_bytes()).hexdigest() == plan["archive_sha256"]
    )
    with tarfile.open(ROOT / "sources.tar.gz") as archive:
        for name, expected in plan["source_hashes"].items():
            assert hashlib.sha256(archive.extractfile(name).read()).hexdigest() == expected
    summaries = {}
    all_rows = {}
    for name, modes in [
        ("comparison", MODES),
        ("operations", ("plain", "landlock", "container")),
        ("application", ("plain", "landlock", "container")),
    ]:
        rows = read(name + ".jsonl")
        all_rows[name] = rows
        for case in {r["case"] for r in rows}:
            for mode in modes:
                for session in range(5):
                    group = [
                        r
                        for r in rows
                        if r["case"] == case and r["condition"] == mode and r["session"] == session
                    ]
                    assert Counter(r["phase"] for r in group) == {
                        "first_use": 1,
                        "warmup": 10,
                        "measured": 20,
                    }
                    assert len({r["round"] for r in group}) == 31
        summaries[name] = summarize(rows, modes, 20)
        assert summaries[name] == read(name + "-summary.json")
    for name, rows in all_rows.items():
        for row in rows:
            telemetry = row.get("worker_telemetry") if name == "comparison" else row["response"]
            if telemetry is not None:
                assert telemetry["cpu_affinity"] == [0]
    for row in all_rows["comparison"]:
        assert row["valid"] and row["value_sha256"] == row["expected_sha256"]
        assert row["policy_ms"] + row["execution_ms"] <= row["elapsed_ms"]
    for row in all_rows["operations"]:
        assert row["effect_observed"] and row["response"]["phase"] == "executed"
        assert row["response"]["operation_elapsed_ns"] / 1e6 <= row["elapsed_ms"]
        e = row["evidence"]
        name = row["case"]
        expected = {"write": "effect", "append": e["expected_token"] + "effect", "truncate": ""}
        if name in expected:
            assert e["target_sha256"] == hashlib.sha256(expected[name].encode()).hexdigest()
        if name == "write_4kib":
            assert e["output_sha256"] == hashlib.sha256(b"x" * 4096).hexdigest()
        if name == "fsync":
            assert e["output_sha256"] == hashlib.sha256(b"effect").hexdigest()
    security = read("security.jsonl")
    assert len(security) == 59 * 3 * 3
    security_metrics = {}
    for mode in ("plain", "landlock", "container"):
        rows = [r for r in security if r["condition"] == mode]
        assert len(rows) == 177
        assert len({(r["case"], r["repetition"]) for r in rows}) == 177
        forbidden = [r for r in rows if not r["allowed"]]
        exposed = sorted({r["case"] for r in forbidden if r["effect_observed"]})
        positives = [r for r in rows if r["allowed"]]
        security_metrics[mode] = dict(
            exposed=exposed,
            forbidden_cases=49,
            positive_pass=sum(r["effect_observed"] for r in positives),
            positive_trials=30,
            outcomes=dict(Counter(r["outcome"] for r in forbidden)),
        )
    baseline = security_metrics["plain"]["exposed"]
    assert len(baseline) == 49
    for row in security:
        if row["condition"] != "plain" and row["case"] == "file_size_limit":
            assert row["evidence"]["output_size"] <= 1048576
    lines = [
        "# Verified language, Landlock, and rootless-container evaluation",
        "",
        "Completed fixed protocol: **100 measured calls per workload and mode**, across five fresh "
        "benchmark-process sessions (20 measured calls each). Each session has ten "
        "excluded warmups "
        "and one separately retained first-use call. Calls and modes are shuffled "
        "within matched rounds. "
        "All positive timing results must pass the parent oracle. No failed calls are"
        " silently replaced.",
        "",
        "[Comparison figure](comparison.pdf), [operation figure](operations.pdf), "
        "and [full-precision CSV](timings.csv).",
        "",
        "## Configurations and scope",
        "",
        "- **verified:** actual cedar_security / ManifestAdmission source checking at"
        " setup; production "
        "Cedar object authorization, binding validation and grant-checked read_text at invocation.",
        "- **landlock:** an evaluation adapter applies Landlock filesystem rules, the"
        " production minimal "
        "seccomp allowlist, cleared environment and process resource limits to a "
        "fresh Python child.",
        "- **container:** an evaluation adapter uses rootless Docker with a read-only"
        " root, no network, "
        "no capabilities, no-new-privileges, explicit read-only/read-write mounts, "
        "and memory/PID ceilings. "
        "Each invocation starts a fresh Python process inside a persistent, "
        "grant-specific container "
        "and applies the same minimal seccomp allowlist. Container creation and "
        "teardown are separately timed.",
        "- **plain:** fresh Python child with resource ceilings for the raw-operation"
        " and application "
        "ablation; it is not the verified-language comparator.",
        "",
        "The two host adapters are evaluation implementations, **not** the production"
        " Bubblewrap executor. "
        "Their records are parent observations and worker telemetry, not signed "
        "production activation receipts. "
        "The paired read comparison uses the same production Cedar authorizer in all "
        "three modes; its "
        "grants are translated into the allowed filesystem paths. The raw-operation "
        "and application "
        "experiments measure execution with explicit fixture/runtime grants and "
        "exclude Cedar authorization.",
        "",
        "## Verified-language versus host: matched useful work",
        "",
        "Constant return, three read sizes, and a two-read workload are supported in all modes. "
        "Sizes are workload variants, not distinct API operations. Static admission is outside "
        "the invocation timer and measured separately. Whole-call timing includes "
        "common authorization "
        "plus execution/transport and validation. It excludes fixture reset and "
        "container lifecycle.",
        "",
    ]
    lines += timing_table(summaries["comparison"], "verified")
    lines += [
        "",
        "### Where the time goes",
        "",
        "| Workload / mode | Policy mean ms | Execution/transport mean ms |",
        "| --- | ---: | ---: |",
    ]
    for case in summaries["comparison"]:
        for mode in MODES:
            rows = [
                r
                for r in all_rows["comparison"]
                if r["phase"] == "measured" and r["case"] == case and r["condition"] == mode
            ]
            lines.append(
                f"| {case} / {mode} | {stats([r['policy_ms'] for r in rows])['mean_ms']:.3f} | "
                f"{stats([r['execution_ms'] for r in rows])['mean_ms']:.3f} |"
            )
    setup = [r for session in range(5) for r in read(f"session-{session}/setup.json")]
    lines += [
        "",
        "| Tool workload | Admission n | Admission mean ms | Admission SD ms |",
        "| --- | ---: | ---: | ---: |",
    ]
    for case in summaries["comparison"]:
        values = stats([r["admission_ms"] for r in setup if r["case"] == case])
        assert values["n"] == 100
        lines.append(f"| {case} | 100 | {values['mean_ms']:.3f} | {values['sd_ms']:.3f} |")
    lines += [
        "",
        "## Per-operation microbenchmarks",
        "",
        "Sixteen operation/API variants, 100 measured calls per mode. These compare a"
        " plain process "
        "against the two host adapters. The current built-in verified file API exposes read_text; "
        "the real admission checker rejects the raw-API programs (diagnostics are "
        "saved), so rejected "
        "programs are never assigned a successful-operation timing. Registered "
        "typed-resource ports "
        "would be needed for a broader verified-language operation comparison.",
        "",
    ]
    lines += timing_table(summaries["operations"], "plain")
    lines += [
        "",
        "### Operation body only",
        "",
        "The inner timer surrounds the original operation statements after imports. It excludes "
        "worker startup, policy, activation and transport; it is not pure syscall time.",
        "",
        "| Operation | Plain mean µs | Landlock mean µs | Container mean µs |",
        "| --- | ---: | ---: | ---: |",
    ]
    body = {}
    for case in summaries["operations"]:
        body[case] = {}
        for mode in ("plain", "landlock", "container"):
            body[case][mode] = stats(
                [
                    r["response"]["operation_elapsed_ns"] / 1e6
                    for r in all_rows["operations"]
                    if r["phase"] == "measured" and r["case"] == case and r["condition"] == mode
                ]
            )
        lines.append(
            "| "
            + case
            + " | "
            + " | ".join(f"{v['mean_ms'] * 1000:.3f}" for v in body[case].values())
            + " |"
        )
    lines += [
        "",
        "## Application replay",
        "",
        "This runs the actual recorded Pandas February computation, original input, and unmodified "
        "upstream sandbox runner. The independent expected result is total_sales=120. All modes "
        "use the pinned application Python 3.13 runtime and dependencies. Plain "
        "retains the upstream "
        "sandbox; Landlock/container add host restrictions around that same sandbox "
        "program. This is "
        "a computation replay, not a model-driven full workflow or a "
        "verified-language application port. "
        "No model calls, ToolNode dispatch, durable audit sink, or Cedar "
        "authorization are included.",
        "",
    ]
    lines += timing_table(summaries["application"], "plain")
    lines += [
        "",
        "| Application mode | Worker activation ms | Application body ms | "
        "Startup/transport residual ms |",
        "| --- | ---: | ---: | ---: |",
    ]
    application_stages = {}
    for mode in ("plain", "landlock", "container"):
        selected = [
            r
            for r in all_rows["application"]
            if r["phase"] == "measured" and r["condition"] == mode
        ]
        activation = [r["response"]["activation_ns"] / 1e6 for r in selected]
        body = [r["response"]["execution_ns"] / 1e6 for r in selected]
        residual = [
            r["elapsed_ms"] - a - b for r, a, b in zip(selected, activation, body, strict=True)
        ]
        assert min(residual) >= 0
        application_stages[mode] = {
            "activation": stats(activation),
            "application_body": stats(body),
            "startup_transport": stats(residual),
        }
        lines.append(
            f"| {mode} | {stats(activation)['mean_ms']:.3f} | "
            f"{stats(body)['mean_ms']:.3f} | {stats(residual)['mean_ms']:.3f} |"
        )
    # Verify and preserve the exact external application sources named during each session.
    application_hashes = read("session-0/application-plan.json")["source_hashes"]
    for session in range(5):
        assert (
            read(f"session-{session}/application-plan.json")["source_hashes"] == application_hashes
        )
    with tarfile.open(ROOT / "application-sources.tar.gz", "w:gz") as archive:
        for path, expected in application_hashes.items():
            source = Path(path)
            assert hashlib.sha256(source.read_bytes()).hexdigest() == expected
            archive.add(source, arcname="application/" + source.name)

    lines += [
        "",
        "## Security and exposure reduction",
        "",
        "The frozen census has **59 cases: 49 forbidden operation/surface "
        "combinations and 10 allowed "
        "controls**, each repeated three times per mode. Repetitions are not independent attacks. "
        "Baseline effects are checked on disposable fixtures. Reduction is relative "
        "to the 49 baseline "
        "cases with observed effects. No-effect outcomes are not all explicit kernel denials.",
        "",
        "| Mode | Forbidden cases with observed effect | Allowed control successes | "
        "Observed reduction |",
        "| --- | ---: | ---: | ---: |",
    ]
    for mode, data in security_metrics.items():
        reduction = 100 * (49 - len(data["exposed"])) / 49
        lines.append(
            f"| {mode} | {len(data['exposed'])}/49 | {data['positive_pass']}/30 | "
            f"{reduction:.2f}% |"
        )
    for mode in ("landlock", "container"):
        lines += [
            "",
            f"{mode} remaining exposures: "
            f"{', '.join(security_metrics[mode]['exposed']) or 'none in this corpus'}. "
            "Forbidden-trial outcomes: "
            f"`{json.dumps(security_metrics[mode]['outcomes'], sort_keys=True)}`.",
        ]
    lines += [
        "",
        "Landlock does not hide filesystem names/metadata merely by denying file-content access. "
        "The census reports such differences rather than asserting equivalent "
        "guarantees. Both minimal "
        "profiles deny child creation/exec; their rejection does not demonstrate "
        "useful opaque-binary "
        "chain support. Kernel exploits, races, and cross-host generalization are "
        "outside this corpus.",
        "",
        "## Container lifecycle and uncertainty",
        "",
        "Container initialization is amortized across calls in a session. The "
        "following are separately "
        "observed setup/teardown costs (not 100 invocation measurements); include "
        "them when modeling "
        "one-shot execution. All workers are fresh even when the containing namespace persists.",
        "",
        "| Experiment | Containers | Setup mean ms | Setup SD ms | Teardown mean ms |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    lifecycle = {}
    for name in ("comparison", "operations", "application"):
        entries = [
            r for session in range(5) for r in read(f"session-{session}/{name}-lifecycle.json")
        ]
        creation = stats([r["setup_ms"] for r in entries])
        teardown = stats([r["teardown_ms"] for r in entries])
        lifecycle[name] = dict(setup=creation, teardown=teardown)
        lines.append(
            f"| {name} | {len(entries)} | {creation['mean_ms']:.3f} | "
            f"{creation['sd_ms']:.3f} | {teardown['mean_ms']:.3f} |"
        )
    controls = read("verified-security.json")
    assert len(controls) == 12 and all(row["passed"] for row in controls)
    assert Counter(row["case"] for row in controls) == {
        "permitted_read": 3,
        "ungranted_path_argument": 3,
        "changed_callable_binding": 3,
        "missing_read_manifest": 3,
    }
    lines += [
        "",
        "## Verified-mode security controls",
        "",
        "The production verified path passes 12/12 controls: permitted reads, denied "
        "ungranted path arguments, rejection of changed callable bindings before execution, "
        "and admission rejection of missing read permissions, each repeated three times. "
        "These complement the raw-API rejection census; they are not equivalent to the "
        "host's 49-case syscall/resource corpus. [Control evidence](verified-security.json).",
    ]
    native_root = ROOT.parent / "native-chain-v2"
    native_plan = json.loads((native_root / "plan.json").read_text())
    native_rows = [
        json.loads(line) for line in (native_root / "samples.jsonl").read_text().splitlines()
    ]
    assert (
        hashlib.sha256((native_root / "binary_worker.py.txt").read_bytes()).hexdigest()
        == native_plan["worker_sha256"]
    )
    assert native_plan["samples"] == 20 and native_plan["warmup"] == 10
    for mode in ("plain", "landlock", "container"):
        for session in range(5):
            group = [
                row for row in native_rows if row["condition"] == mode and row["session"] == session
            ]
            assert Counter(row["phase"] for row in group) == {
                "first_use": 1,
                "warmup": 10,
                "measured": 20,
            }
            assert len({row["round"] for row in group}) == 31
            assert all(row["valid"] for row in group)
    native = summarize(native_rows, ("plain", "landlock", "container"), 20)
    assert native == json.loads((native_root / "summary.json").read_text())
    assert all(r["response"]["cpu_affinity"] == [0] for r in native_rows)
    native_denials = [
        row
        for session in range(5)
        for row in json.loads((native_root / f"session-{session}/security.json").read_text())
    ]
    assert len(native_denials) == 45
    for row in native_denials:
        assert row["response"]["phase"] == "executed"
        if row["mode"] != "plain":
            assert row["response"]["value"]["returncode"] != 0
            assert row["response"]["value"]["stderr"]
    assert all(row["exposed"] == (row["mode"] == "plain") for row in native_denials)
    assert native_plan["verified_admission"]["status"] == "rejected"
    lines += [
        "",
        "## Opaque native tool chains: separate exec-enabled profile",
        "",
        "A separate profile permits process creation, exec and waiting, while retaining "
        "Landlock/container filesystem restrictions and the remaining seccomp policy. "
        "The fixed native chain is /usr/bin/env invoking /bin/cat; source verification "
        "of those binaries is not used. All host timing calls must successfully return "
        "the allowed canary. The actual language verifier rejects this raw subprocess "
        "tool, so no verified-language runtime is invented for it. Registering a trusted "
        "native wrapper would add an implementation assumption; it would not verify "
        "the opaque binary internals.",
        "",
    ]
    lines += timing_table(native, "plain")
    lines += [
        "",
        "In 15 hidden-file checks per mode (three per session), the plain chain reads "
        "the canary and both host profiles prevent its disclosure. This demonstrates "
        "useful execution plus confinement across this two-binary chain, not all native "
        "programs. The exec-enabled Landlock profile does not enforce a process-count "
        "quota; Docker has a PID ceiling. This is explicitly a different profile from "
        "the minimal census. "
        "[Native-chain plan and admission diagnostic](../native-chain-v2/plan.json), "
        "[raw timing](../native-chain-v2/samples.jsonl), "
        "[summary](../native-chain-v2/summary.json).",
    ]
    host = read("host.json")
    cpu = {
        item["field"].rstrip(":"): item["data"]
        for item in json.loads(host["lscpu"]["stdout"])["lscpu"]
    }
    ram = int(host["memory"].splitlines()[0].split()[1]) / 1024 / 1024
    lines += [
        "",
        "| Host field | Value |",
        "| --- | --- |",
        f"| CPU | {cpu['Model name']} |",
        f"| Logical CPUs | {cpu['CPU(s)']} |",
        f"| RAM | {ram:.2f} GiB |",
        f"| OS / kernel | {host['platform']} |",
        f"| Timing CPU affinity | {host['affinity']} |",
        "| Application runtime | Pinned CPython 3.13; sandbox source hashes retained per session |",
    ]
    lines += [
        "",
        "Intervals use Student t on five session mean paired differences (df=4), not "
        "100 independent "
        "calls. They assume approximately normal independent session means; adjacent "
        "same-host sessions "
        "may remain correlated. SD/variance and P95 are descriptive within this fixed"
        " corpus. Negative "
        "small operation-body deltas do not establish a speed advantage.",
        "",
        "## Host, artifacts and reproduction",
        "",
        f"Platform: `{host['platform']}`. Python: `{host['python'].splitlines()[0]}`. "
        f"CPU affinity: `{host['affinity']}`. Container image: `{plan['image']}`. "
        f"Container security options: `{plan['container_security']}`.",
        "",
        "Full CPU/memory/kernel/storage/GPU details and load are in [host.json](host.json); "
        "each session also records before/after host state. The container "
        "image/runtime and host Python "
        "environment differ where documented. CPU frequency and OS caches are uncontrolled. Read "
        "fixtures are cache-warm. Sources are hashed and archived before execution. "
        "Docker cpuset is unavailable on this host. The container launcher uses taskset "
        "before Python startup; workers also enforce and report affinity [0]. Every "
        "recorded worker affinity is checked. The superseded v1 cohort is not pooled.",
        "",
        "[Plan](plan.json), [sources](sources.tar.gz), [comparison "
        "observations](comparison.jsonl), "
        "[operation observations](operations.jsonl), [application "
        "observations](application.jsonl), "
        "[security observations](security.jsonl), [admission diagnostics](admission-census.json).",
        "",
        "```sh",
        "uv run --project eval python -m slanggraph_eval.isolation.alternatives \\",
        "  --output eval/reports/alternatives-new",
        "uv run --project eval python eval/scripts/alternative_report.py",
        "```",
    ]
    (ROOT / "report.md").write_text("\n".join(lines) + "\n")
    metrics = dict(
        timings=summaries,
        native_chain=native,
        verified_security_controls=controls,
        application_stages_ms=application_stages,
        security=security_metrics,
        operation_body_ms=body,
        lifecycle=lifecycle,
        validated=True,
        measured_per_cell=100,
        worker_affinity_verified=[0],
        native_source_sha256=native_plan["worker_sha256"],
        source_archive_verified=True,
        hashes={
            name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
            for name in (
                "plan.json",
                "comparison.jsonl",
                "operations.jsonl",
                "application.jsonl",
                "security.jsonl",
                "sources.tar.gz",
                "verified-security.json",
                "application-sources.tar.gz",
            )
        },
    )
    exported = []
    for experiment, cases in {**summaries, "native_chain": native}.items():
        baseline = "verified" if experiment == "comparison" else "plain"
        for case, values in cases.items():
            for mode, distribution in values["conditions"].items():
                contrast = values["contrasts"].get(mode + "-" + baseline)
                exported.append(
                    {
                        "experiment": experiment,
                        "workload": case,
                        "mode": mode,
                        **distribution,
                        "paired_added_ms": contrast["paired"]["mean_ms"] if contrast else None,
                        "paired_sd_ms": contrast["paired"]["sd_ms"] if contrast else None,
                        "ci95_low_ms": contrast["interval"]["ci95_ms"][0] if contrast else None,
                        "ci95_high_ms": contrast["interval"]["ci95_ms"][1] if contrast else None,
                        "ratio_of_means": contrast["ratio"] if contrast else 1,
                    }
                )
    with (ROOT / "timings.csv").open("w") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(exported[0]))
        writer.writeheader()
        writer.writerows(exported)
    (ROOT / "validated-metrics.json").write_text(json.dumps(metrics, indent=2) + "\n")
    print("Validated all timing cells, parent oracles, security census and source archive.")


if __name__ == "__main__":
    main()
