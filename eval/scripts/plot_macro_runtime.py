"""Paper figure from recorded samples; no synthetic timing observations."""

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[1]
rows = [
    json.loads(line)
    for line in (ROOT / "results/pandas-runtime-20261026-v1/samples.jsonl").read_text().splitlines()
]
local = [
    [r["elapsed_ms"] for r in rows if r["phase"] == "measured" and r["configuration"] == c]
    for c in "ABC"
]
launches = [
    json.loads(line)
    for line in (ROOT / "results/pandas-e2e-repetitions-20261026-attempt2/launches.jsonl")
    .read_text()
    .splitlines()
]
results = [json.loads(Path(json.loads(row["stdout"])["result"]).read_text()) for row in launches]
macro = [
    [
        r["elapsed_seconds"]
        for r in results
        if r["case_id"] == "february" and r["configuration"] == c
    ]
    for c in "ABC"
]
plt.rcParams.update({"font.size": 10, "pdf.fonttype": 42, "ps.fonttype": 42})
fig, axes = plt.subplots(1, 2, figsize=(7.2, 3.0), layout="constrained")
colors = ["#9A9A9A", "#4477AA", "#AA3377"]
for ax, data, title, ylabel in zip(
    axes,
    [local, macro],
    ["Recorded computation replay (n=100 each)", "Full workflow, one task (n=5 each)"],
    ["Latency (ms)", "Recorded runtime (s)"],
    strict=True,
):
    boxes = ax.boxplot(
        data,
        tick_labels=["A", "B", "C"],
        patch_artist=True,
        showfliers=ax is axes[0],
        widths=0.45,
        medianprops={"color": "black"},
        flierprops={"marker": ".", "markersize": 3},
    )
    for box, color in zip(boxes["boxes"], colors, strict=True):
        box.set_facecolor(color)
        box.set_alpha(0.6)
    ax.set_title(title, fontsize=10)
    ax.set_ylabel(ylabel)
    ax.set_ylim(bottom=0)
    ax.grid(axis="y", alpha=0.2)
    ax.set_axisbelow(True)
    ax.spines[["top", "right"]].set_visible(False)
for i, data in enumerate(macro, 1):
    axes[1].scatter(
        [i + (j - 2) * 0.035 for j in range(len(data))], data, s=13, c="black", zorder=3
    )
fig.savefig(ROOT / "reports/macro-runtime.pdf")
fig.savefig(ROOT / "reports/macro-runtime.png", dpi=180)
