"""Regenerate campaign aggregates from immutable records; no experiment execution."""

import argparse
import base64
import collections
import csv
import hashlib
import json
import math
import random
import statistics
import struct
from pathlib import Path

COHORTS = [
    "production-repeats",
    "grant-matrix",
    "capability-configurations",
    "container-lifecycle",
    "manifest-mac",
    "broker-mac",
    "sqlite-composition",
    "pump-composition",
    "producer-integrated",
    "native-comparators",
    "progent-focused",
    "camel-focused",
    "camel-interpreted",
    "sql-adversarial-v2",
    "notebook-disposition",
    "sqlite-alias-setup",
]


def read(p):
    return [json.loads(line) for line in p.read_text().splitlines()]


def dump(p, v):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(v, indent=2, sort_keys=True) + "\n")


def csvwrite(p, rows):
    if not rows:
        return
    with p.open("w") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def mean(v):
    return statistics.mean(v)


def stats(v):
    return dict(
        n=len(v),
        mean_ms=mean(v),
        sd_ms=statistics.stdev(v) if len(v) > 1 else 0,
        median_ms=statistics.median(v),
        p95_ms=sorted(v)[math.ceil(len(v) * 0.95) - 1],
    )


def interval(v):
    half = 2.7764451051977987 * statistics.stdev(v) / math.sqrt(5)
    return [mean(v) - half, mean(v) + half]


def bootstrap(a, b):
    rng = random.Random(20261026)
    d = []
    ratios = []
    for _ in range(10000):
        idx = [rng.randrange(len(a)) for _ in a]
        av = mean([a[i] for i in idx])
        bv = mean([b[i] for i in idx])
        d.append(bv - av)
        ratios.append(bv / av)
    d.sort()
    ratios.sort()
    return dict(
        added_ms_95=[d[249], d[9749]],
        ratio_95=[ratios[249], ratios[9749]],
        method="paired resampling of 10 task means, 10000 bootstrap draws; fixed task corpus",
    )


def main(root):
    raw = root / "raw"
    out = root / "summaries"
    out.mkdir(exist_ok=True)
    cells = []
    validation = []
    for name in COHORTS:
        p = raw / name / "trials.jsonl"
        if not p.exists():
            continue
        rows = read(p)
        groups = collections.defaultdict(list)
        for i, r in enumerate(rows, 1):
            groups[
                (
                    r.get("mode", "unspecified"),
                    r.get("case_id", r.get("fixture_id", "unspecified")),
                    str(r.get("control", "not-applicable")),
                )
            ].append((i, r))
        for (mode, case, control), rs in groups.items():
            cells.append(
                dict(
                    experiment=name,
                    mode=mode,
                    case_id=case,
                    control=control,
                    trials=len(rs),
                    legitimate_success=sum(r.get("legitimate_result") is True for _, r in rs),
                    legitimate_failure=sum(r.get("legitimate_result") is False for _, r in rs),
                    observed_effect=sum(r.get("observed_effect") is True for _, r in rs),
                    effect_not_recorded=sum("observed_effect" not in r for _, r in rs),
                    outcomes=json.dumps(
                        dict(
                            collections.Counter(
                                str(
                                    r.get(
                                        "classification",
                                        r.get(
                                            "status", r.get("outcome", r.get("error", "see raw"))
                                        ),
                                    )
                                )
                                for _, r in rs
                            )
                        )
                    ),
                    raw_ids=json.dumps([f"raw/{name}/trials.jsonl:{i}" for i, _ in rs]),
                )
            )
        validation.append(
            dict(
                experiment=name,
                trials=len(rows),
                distinct_cases=len({g[1] for g in groups}),
                scope="see coverage.csv; contract units are not end-to-end effects",
            )
        )
    csvwrite(out / "mechanisms.csv", cells)
    dump(out / "cohort-counts.json", validation)
    micro = []
    for name, baseline in [("typed-costs-v3", "plain"), ("cold-container", "plain")]:
        rows = [r for p in sorted((raw / name).glob("session-*.jsonl")) for r in read(p)]
        for session_id in range(5):
            expected_order = []
            seed = 20261028 if name == "typed-costs-v3" else 20261029
            rng = random.Random(seed + session_id)
            initial = (
                ["plain", "verified", "broker"]
                if name == "typed-costs-v3"
                else ["plain", "container"]
            )
            for round_id in range(31):
                shuffled = initial.copy()
                rng.shuffle(shuffled)
                expected_order.extend((round_id, mode) for mode in shuffled)
            actual_order = [(r["round"], r["mode"]) for r in rows if r["session"] == session_id]
            assert actual_order == expected_order, (name, session_id, "pairing/shuffled schedule")
        assert all(r["legitimate_result"] for r in rows), (name, "parent oracle")
        modes = sorted({r["mode"] for r in rows})
        groups = {
            m: [r for r in rows if r["mode"] == m and r["phase"] == "measured"] for m in modes
        }
        for m, rs in groups.items():
            assert len(rs) == 100 and collections.Counter(
                r["session"] for r in rs
            ) == dict.fromkeys(range(5), 20), (name, m, "denominator")
            assert all(r["legitimate_result"] for r in rs), (name, m, "oracle")
            assert len([r for r in rows if r["mode"] == m and r["phase"] == "warmup"]) == 50
            assert len([r for r in rows if r["mode"] == m and r["phase"] == "first_use"]) == 5
            v = [r["elapsed_ms"] for r in rs]
            base = groups[baseline]
            bv = [r["elapsed_ms"] for r in base]
            means = [mean([r["elapsed_ms"] for r in rs if r["session"] == s]) for s in range(5)]
            bmeans = [mean([r["elapsed_ms"] for r in base if r["session"] == s]) for s in range(5)]
            micro.append(
                dict(
                    experiment=name,
                    mode=m,
                    baseline=baseline,
                    **stats(v),
                    session_mean_ci95=json.dumps(interval(means)),
                    added_ms=mean(v) - mean(bv),
                    paired_increment_ci95=json.dumps(
                        interval([x - y for x, y in zip(means, bmeans, strict=False)])
                    ),
                    runtime_multiple=mean(v) / mean(bv),
                    overhead_percent=100 * (mean(v) / mean(bv) - 1),
                    source="raw/" + name + "/session-{0..4}.jsonl",
                    timer=(
                        "parent invocation including launch/transport; typed set"
                        "up excluded; cold includes one-shot launch/removal"
                    ),
                    host_load=(
                        "concurrent application/build/other-host jobs; descripti"
                        "ve shared-host cohort"
                    ),
                )
            )
    csvwrite(out / "microbenchmarks.csv", micro)
    appcells = []
    appcost = []
    classifications = []
    matched = []
    for name in ["pandas-full", "sql-full"]:
        rows = read(raw / name / "trials.jsonl")
        assert len(rows) == 150, (name, len(rows))
        tasks = sorted({r["case_id"] for r in rows})
        assert len(tasks) == 10
        for task in tasks:
            for mode in "ABC":
                rs = [r for r in rows if r["case_id"] == task and r["mode"] == mode]
                assert len(rs) == 5
                appcells.append(
                    dict(
                        application=name,
                        task=task,
                        mode=mode,
                        trials=5,
                        success=sum(r["legitimate_result"] for r in rs),
                        completed=sum(r["status"] == "completed" for r in rs),
                        canary_in_model_input=sum(
                            r.get("canary_in_model_input", False) for r in rs
                        ),
                        **{k: v for k, v in stats([r["wall_ms"] for r in rs]).items() if k != "n"},
                        run_ids=json.dumps([r["run_id"] for r in rs]),
                    )
                )
        for mode in "ABC":
            rs = [r for r in rows if r["mode"] == mode]
            a = [
                mean([r["wall_ms"] for r in rows if r["mode"] == "A" and r["case_id"] == t])
                for t in tasks
            ]
            b = [mean([r["wall_ms"] for r in rs if r["case_id"] == t]) for t in tasks]
            appcost.append(
                dict(
                    application=name,
                    mode=mode,
                    baseline="A",
                    trials=50,
                    tasks=10,
                    success=sum(r["legitimate_result"] for r in rs),
                    mean_wall_ms=mean(b),
                    mean_model_ms=mean([r["model_ms"] for r in rs]),
                    model_calls=sum(r["model_calls"] for r in rs),
                    added_ms=mean(b) - mean(a),
                    runtime_multiple=mean(b) / mean(a),
                    overhead_percent=100 * (mean(b) / mean(a) - 1),
                    uncertainty=json.dumps(bootstrap(a, b)),
                    scope=(
                        "full workflow, all results including failures; shared-h"
                        "ost load; SQL includes durable C audit; Pandas B/C dura"
                        "ble audit"
                    ),
                )
            )
        good = {
            (r["case_id"], r["repeat"]) for r in rows if r["mode"] == "A" and r["legitimate_result"]
        }
        for mode in "ABC":
            rs = [r for r in rows if r["mode"] == mode and (r["case_id"], r["repeat"]) in good]
            matched.append(
                dict(
                    application=name,
                    mode=mode,
                    baseline_success_matched_trials=len(rs),
                    success=sum(r["legitimate_result"] for r in rs),
                    pairs=json.dumps(sorted(good)),
                )
            )
        if name == "pandas-full":
            for r in rows:
                p = raw / name / r["run_id"] / "output.json"
                text = p.read_text() if p.exists() else ""
                o = json.loads(text) if text else {}
                reason = (
                    "oracle pass"
                    if r["legitimate_result"]
                    else "output differs from frozen requested table/series"
                )
                if not r["legitimate_result"]:
                    if "not JSON serializable" in text:
                        reason = "common upstream sandbox serialization failure (e.g. Timestamp)"
                    elif o.get("table") is None and o.get("plot") is None:
                        reason = (
                            "graph completed without usable output; inspect process/model/tool logs"
                        )
                series = []
                if r["case_id"] == "monthly_chart":
                    plot = o.get("plot", {})
                    plot = json.loads(plot) if isinstance(plot, str) else plot
                    for trace in (plot or {}).get("data", []):
                        y = trace.get("y")
                        x = trace.get("x")
                        if (
                            isinstance(y, dict)
                            and y.get("dtype") in ["f8", "f4", "i4", "i8"]
                            and "bdata" in y
                        ):
                            fmt = {"f8": "d", "f4": "f", "i4": "i", "i8": "q"}[y["dtype"]]
                            b = base64.b64decode(y["bdata"])
                            y = list(struct.unpack("<" + fmt * (len(b) // struct.calcsize(fmt)), b))
                        series.append(dict(x=x, y=y))
                classifications.append(
                    dict(
                        run_id=r["run_id"],
                        mode=r["mode"],
                        case_id=r["case_id"],
                        original_oracle=r["legitimate_result"],
                        classification=reason,
                        independently_decoded_chart_series=series,
                        expected=r["expected"],
                    )
                )
    csvwrite(out / "application-tasks.csv", appcells)
    csvwrite(out / "application-costs.csv", appcost)
    csvwrite(out / "baseline-success-subset.csv", matched)
    dump(out / "pandas-failures-and-series.json", classifications)
    dump(
        out / "validation.json",
        dict(
            status="counts and microbenchmark oracles validated",
            raw_hashes={
                str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in raw.rglob("*.jsonl")
            },
            limitations=[
                "Historical cohort provenance gaps remain in completed-v2/FAILURES.md",
                "Parent output/snapshot oracles are not universal kernel read traces",
                (
                    "No independently measured per-phase policy/audit spans "
                    "for every application; nested SQL mediator/dispatch spa"
                    "ns retained"
                ),
                "No idle-host performance claim",
                "Failed pilots retained and excluded from final cohort aggregations",
            ],
        ),
    )
    print(
        "Regenerated mechanisms, application utility, task-boots"
        "trap costs, session-t microbenchmarks and validation."
    )


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("root", type=Path)
    main(p.parse_args().root)
