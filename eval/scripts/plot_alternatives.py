"""Figures for validated fixed-count alternative backend measurements."""

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[1] / "reports/alternatives-v2"
data = json.loads((ROOT / "validated-metrics.json").read_text())
assert data["validated"]
plt.rcParams.update({"font.size": 9, "pdf.fonttype": 42, "ps.fonttype": 42})
fig, (left, right) = plt.subplots(1, 2, figsize=(10, 4.4), layout="constrained")
colors = {"verified": "#228833", "plain": "#777777", "landlock": "#4477AA", "container": "#AA3377"}
for ax, experiment in [(left, "comparison"), (right, "application")]:
    summary = data["timings"][experiment]
    cases = list(summary)
    modes = list(summary[cases[0]]["conditions"])
    for index, mode in enumerate(modes):
        positions = [v + (index - 1) * 0.24 for v in range(len(cases))]
        ax.bar(
            positions,
            [summary[c]["conditions"][mode]["mean_ms"] for c in cases],
            width=0.23,
            yerr=[summary[c]["conditions"][mode]["sd_ms"] for c in cases],
            capsize=2,
            color=colors[mode],
            label=mode,
        )
    ax.set_xticks(range(len(cases)), [c.replace("_", "\n") for c in cases])
    ax.set_ylabel("Whole-call latency (ms), mean ± SD")
    ax.set_title(
        "Matched verified-language comparison"
        if experiment == "comparison"
        else "Pandas computation replay"
    )
    ax.legend(loc="upper left", ncol=3 if experiment == "comparison" else 1)
    if experiment == "comparison":
        ax.set_ylim(0, max(summary[c]["conditions"]["container"]["p95_ms"] for c in cases) * 1.25)
    ax.grid(axis="y", alpha=0.2)
    ax.set_axisbelow(True)
    ax.spines[["top", "right"]].set_visible(False)
fig.suptitle("100 measured calls per mode/workload; five process sessions")
fig.supxlabel("Fresh worker per call; container setup and teardown reported separately", fontsize=9)
fig.savefig(ROOT / "comparison.pdf")
fig.savefig(ROOT / "comparison.png", dpi=180)
fig, ax = plt.subplots(figsize=(8, 6), layout="constrained")
summary = data["timings"]["operations"]
cases = list(summary)
for index, mode in enumerate(("landlock", "container")):
    values = [summary[c]["contrasts"][mode + "-plain"] for c in cases]
    ax.barh(
        [v + (index - 0.5) * 0.32 for v in range(len(cases))],
        [v["paired"]["mean_ms"] for v in values],
        height=0.3,
        xerr=[v["paired"]["sd_ms"] for v in values],
        capsize=2,
        label=mode,
        color=colors[mode],
    )
ax.set_yticks(range(len(cases)), cases)
ax.invert_yaxis()
ax.legend(loc="center left", bbox_to_anchor=(1.01, 0.5))
ax.set_xlabel("Added whole-call latency over plain Python (ms), mean ± paired SD")
ax.set_title("16 operation/API variants; 100 measured pairs each")
ax.grid(axis="x", alpha=0.2)
ax.set_axisbelow(True)
ax.spines[["top", "right"]].set_visible(False)
fig.savefig(ROOT / "operations.pdf")
fig.savefig(ROOT / "operations.png", dpi=180)
