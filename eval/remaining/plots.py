# ruff: noqa: E501
# Retain evidence captions and policy literals verbatim.
"""Vector figures; Times-compatible STIX fonts; raw-derived summaries only."""

import argparse
import csv
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

p = argparse.ArgumentParser()
p.add_argument("root", type=Path)
root = p.parse_args().root
out = root / "plots"
out.mkdir(exist_ok=True)
plt.rcParams.update(
    {
        "font.family": "STIXGeneral",
        "mathtext.fontset": "stix",
        "pdf.fonttype": 42,
        "svg.fonttype": "none",
        "font.size": 10,
    }
)


def save(name):
    plt.tight_layout()
    plt.savefig(out / (name + ".svg"))
    plt.savefig(out / (name + ".pdf"))
    plt.close()


def read(name):
    return list(csv.DictReader((root / "summaries" / name).open()))


rows = read("application-costs.csv")
fig, axes = plt.subplots(1, 2, figsize=(9, 3.4))
for ax, app in zip(axes, ["pandas-full", "sql-full"], strict=False):
    rs = [r for r in rows if r["application"] == app]
    ax.bar(
        [r["mode"] for r in rs],
        [int(r["success"]) for r in rs],
        color=["#999999", "#6baed6", "#238b45"],
    )
    ax.set_ylim(0, 55)
    ax.set_ylabel("Task successes / 50")
    ax.set_title(app.replace("-full", "").title())
    for i, r in enumerate(rs):
        ax.text(i, int(r["success"]) + 1, r["success"], ha="center")
fig.suptitle("All 10 tasks x 5 repeats; failures retained")
save("application-utility")
fig, ax = plt.subplots(figsize=(8, 3.7))
labels = []
values = []
errors = []
for r in rows:
    if r["mode"] == "A":
        continue
    labels.append(r["application"].replace("-full", "") + " " + r["mode"])
    v = float(r["runtime_multiple"])
    ci = json.loads(r["uncertainty"])["ratio_95"]
    values.append(v)
    errors.append((v - ci[0], ci[1] - v))
ax.errorbar(values, range(len(values)), xerr=list(zip(*errors, strict=False)), fmt="o", capsize=4)
ax.set_yticks(range(len(labels)), labels)
ax.axvline(1, color="gray", ls="--")
ax.set_xlabel("Full-workflow mean / A baseline (paired task bootstrap 95% interval)")
ax.set_title("Shared-host application costs; model and configured audit included")
save("application-overhead")
fig, axes = plt.subplots(1, 2, figsize=(10, 3.7))
for ax, name in zip(axes, ["typed-costs-v3", "cold-container"], strict=False):
    raw = [
        json.loads(line)
        for p in (root / "raw" / name).glob("session-*.jsonl")
        for line in p.read_text().splitlines()
    ]
    modes = sorted({r["mode"] for r in raw})
    ax.boxplot(
        [
            [r["elapsed_ms"] for r in raw if r["mode"] == m and r["phase"] == "measured"]
            for m in modes
        ],
        tick_labels=modes,
    )
    ax.set_yscale("log")
    ax.set_ylabel("Invocation wall time (ms, log scale)")
    ax.set_title(name + "; n=100/mode")
save("overhead-distributions")
rows = read("mechanisms.csv")
fig, axes = plt.subplots(1, 2, figsize=(10, 4))
for ax, name in zip(axes, ["sqlite-composition", "pump-composition"], strict=False):
    rs = [r for r in rows if r["experiment"] == name]
    modes = sorted({r["mode"] for r in rs})
    effects = [sum(int(r["observed_effect"]) for r in rs if r["mode"] == m) for m in modes]
    controls = [
        sum(
            int(r["legitimate_success"])
            for r in rs
            if r["mode"] == m and r["case_id"].startswith("allowed")
        )
        for m in modes
    ]
    y = list(range(len(modes)))
    ax.barh([i + 0.17 for i in y], effects, height=0.32, label="Forbidden effects", color="#cb181d")
    ax.barh(
        [i - 0.17 for i in y], controls, height=0.32, label="Allowed successes", color="#238b45"
    )
    ax.set_yticks(y, [m.replace("_", " ") for m in modes], fontsize=8)
    ax.set_xlabel("Trials (counts; see case denominators)")
    ax.set_title(name)
    ax.legend(fontsize=7)
save("composition-effects-and-utility")
# Measured lifecycle pair costs, distinct from any amortization model.
rs = [
    json.loads(line)
    for line in (root / "raw/container-lifecycle/trials.jsonl").read_text().splitlines()
]
cases = sorted({r["case_id"] for r in rs})
fig, ax = plt.subplots(figsize=(7, 3.5))
ax.boxplot(
    [[r["elapsed_ms"] for r in rs if r["case_id"] == c] for c in cases],
    tick_labels=[c.replace("_", " ") for c in cases],
)
ax.set_ylabel("Two-invocation recreation sequence (ms)")
ax.set_title("Evaluation adapter: measured recreation, 20 pairs/case")
save("container-recreation")
# Original v2 lifecycle model: this curve is derived, not measured one-shot latency.
prior = root / "completed-v2/summaries"
life = json.loads((prior / "lifecycle.json").read_text())["comparison"]
comp = json.loads((prior / "comparison-summary.json").read_text())["constant_control"][
    "conditions"
]["container"]
ns = list(range(1, 101))
setup = life["setup_ms"]["mean_ms"]
teardown = life["teardown_ms"]["mean_ms"]
invoke = comp["mean_ms"]
fig, ax = plt.subplots(figsize=(7, 3.5))
ax.plot(
    ns,
    [invoke + (setup + teardown) / n for n in ns],
    label="v2 setup / N + invocation + teardown / N",
)
ax.axhline(invoke, ls="--", color="gray", label="v2 warm invocation")
ax.set_xlabel("Invocations per container")
ax.set_ylabel("Modeled mean cost per invocation (ms)")
ax.set_title("Derived v2 amortization model; cold-container is a separate measured cohort")
ax.legend(fontsize=8)
save("lifecycle-amortization-model")
# Capability outcomes are observed route dispositions, not simulated host claims.
rows = [
    json.loads(line)
    for line in (root / "raw/capability-configurations/trials.jsonl").read_text().splitlines()
]
fig, ax = plt.subplots(figsize=(7, 3.2))
modes = sorted({r["mode"] for r in rows})
cases = sorted({r["case_id"] for r in rows})
for y, mode in enumerate(modes):
    for x, case in enumerate(cases):
        selected = [r for r in rows if r["mode"] == mode and r["case_id"] == case]
        passed = sum(
            (r.get("result") or {}).get("value") == "inspected"
            and r.get("resource_state") == [["inspect", "pump-1"]]
            for r in selected
        )
        effects = sum(
            r.get("observed_effect") is True
            and not (r["case_id"] == "authorized" and r["mode"] == "native_landlock")
            for r in selected
        )
        ax.add_patch(
            plt.Rectangle(
                (x - 0.5, y - 0.5), 1, 1, color="#c7e9c0" if passed else "#deebf7", ec="white"
            )
        )
        ax.text(
            x,
            y,
            f"{passed}/{len(selected)} authorized results\n{effects} forbidden effects",
            ha="center",
            va="center",
        )
ax.set_xlim(-0.5, len(cases) - 0.5)
ax.set_ylim(-0.5, len(modes) - 0.5)
ax.set_xticks(range(len(cases)), cases)
ax.set_yticks(range(len(modes)), modes)
ax.set_title("Real Linux capability configurations: normal control succeeds; others refuse")
save("capability-outcomes")
