"""Publication figure using measured distributions and exclusive timing spans."""

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[1]
metrics = json.loads((ROOT / "reports/evaluation-metrics.json").read_text())
macro = [
    json.loads(line)
    for line in (
        ROOT
        / (
            "reports/repeated-v2/pandas/samples.jsonl"
            if metrics.get("standardized_protocol_complete")
            else "results/pandas-runtime-20261026-v1/samples.jsonl"
        )
    )
    .read_text()
    .splitlines()
]
backend = [
    json.loads(line)
    for line in (
        ROOT
        / (
            "reports/repeated-v2/runtime/samples.jsonl"
            if metrics.get("standardized_protocol_complete")
            else "reports/e6/runtime-v1/samples.jsonl"
        )
    )
    .read_text()
    .splitlines()
]
plt.rcParams.update({"font.size": 9, "pdf.fonttype": 42, "ps.fonttype": 42})
fig, axes = plt.subplots(2, 2, figsize=(10, 7), layout="constrained")
colors = ["#777777", "#4477AA", "#AA3377", "#228833"]


def boxes(ax, groups, labels, title):
    artists = ax.boxplot(
        groups,
        tick_labels=labels,
        patch_artist=True,
        widths=0.5,
        medianprops={"color": "black"},
        flierprops={"marker": ".", "markersize": 3},
    )
    for artist, color in zip(artists["boxes"], colors, strict=False):
        artist.set_facecolor(color)
        artist.set_alpha(0.65)
    ax.set_title(title)
    ax.set_ylabel("Dispatch latency (ms)")
    ax.set_ylim(bottom=0)


boxes(
    axes[0, 0],
    [
        [r["elapsed_ms"] for r in macro if r["phase"] == "measured" and r["configuration"] == c]
        for c in "ABC"
    ],
    ["A: upstream", "B: dispatch", "C: host"],
    "Pandas matched replay (n=100 each)",
)
conditions = ["trusted", "language_helper", "host", "host_language_helper"]
boxes(
    axes[0, 1],
    [
        [
            r["elapsed_ms"]
            for r in backend
            if r["phase"] == "measured" and r["case"] == "allowed_read" and r["condition"] == c
        ]
        for c in conditions
    ],
    ["Trusted", "Helper", "Host", "Host+helper"],
    "E6 matched read (n=100 each)",
)
ax = axes[1, 0]
workloads = list(metrics["runtime"])
bottom = [0.0] * len(workloads)
stages = ["grant", "policy", "attest", "negotiate", "worker", "other_invoke", "outside_invoke"]
for stage in stages:
    values = [
        metrics["runtime"][w]["conditions"]["host"]["stages"][stage]["mean_ms"] for w in workloads
    ]
    ax.bar(range(len(workloads)), values, bottom=bottom, label=stage)
    bottom = [a + b for a, b in zip(bottom, values, strict=True)]
ax.set_xticks(range(len(workloads)), ["Arithmetic", "Read", "4 KiB write"])
ax.set_ylabel("Mean host dispatch latency (ms)")
ax.set_title("Measured backend stages (exclusive)")
ax.set_ylim(0, max(bottom) * 1.28)
ax.legend(fontsize=7, ncol=2, loc="upper right")
ax = axes[1, 1]
ax.bar([0, 1], [49, 0], color=[colors[0], colors[2]])
ax.set_xticks([0, 1], ["Trusted/helper", "Host/combined"])
ax.set_ylim(0, 59)
ax.set_ylabel("Distinct forbidden probes with observed effect")
ax.set_title("E6 reachability (49 fixed probes)")
ax.text(0, 50, "49/49", ha="center")
ax.text(1, 1, "0/49", ha="center")
ax.text(0.5, 56, "45 explicit denials; 4 other no-effect outcomes", ha="center", fontsize=8)
for ax in axes.flat:
    ax.grid(axis="y", alpha=0.2)
    ax.set_axisbelow(True)
    ax.spines[["top", "right"]].set_visible(False)
if not metrics.get("standardized_protocol_complete"):
    fig.suptitle("Preliminary single-session observations", fontsize=13)
fig.savefig(ROOT / "reports/evaluation-summary.pdf")
fig.savefig(ROOT / "reports/evaluation-summary.png", dpi=180)
