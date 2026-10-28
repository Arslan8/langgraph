"""Per-operation overhead and inner-body medians from recorded observations."""

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

EVAL = Path(__file__).resolve().parents[1]
METRICS = json.loads((EVAL / "reports/evaluation-metrics.json").read_text())
ROOT = EVAL / (
    "reports/repeated-v2/operations"
    if METRICS.get("standardized_protocol_complete")
    else "reports/e6/operations-v1"
)
summary = json.loads((ROOT / "summary.json").read_text())
names = list(summary)
plt.rcParams.update({"font.size": 9, "pdf.fonttype": 42, "ps.fonttype": 42})
fig, (left, right) = plt.subplots(1, 2, figsize=(10, 6), layout="constrained", sharey=True)
y = list(range(len(names)))
left.barh(
    y,
    [summary[n]["paired_dispatch_ms"]["mean_ms"] for n in names],
    xerr=[summary[n]["paired_dispatch_ms"]["sd_ms"] for n in names],
    color="#4477AA",
    alpha=0.8,
    capsize=2,
)
left.set_yticks(y, names)
left.invert_yaxis()
left.set_xlabel("Added whole-call latency (ms), mean +/- SD")
left.set_title(f"Host minus plain Python (n={summary[names[0]]['paired_dispatch_ms']['n']})")
for condition, color, marker, offset in [
    ("trusted", "#777777", "o", -0.12),
    ("host", "#AA3377", "s", 0.12),
]:
    right.scatter(
        [summary[n]["conditions"][condition]["body_ms"]["median_ms"] * 1000 for n in names],
        [v + offset for v in y],
        color=color,
        marker=marker,
        label="Plain Python" if condition == "trusted" else "Host isolated",
        s=24,
    )
right.set_xscale("log")
right.set_xlabel("Operation body median (microseconds, log scale)")
right.set_title("Imports/startup/policy excluded")
right.legend(loc="upper right")
for ax in (left, right):
    ax.grid(axis="x", alpha=0.2)
    ax.set_axisbelow(True)
    ax.spines[["top", "right"]].set_visible(False)
if not METRICS.get("standardized_protocol_complete"):
    fig.suptitle("Preliminary single-session observations", fontsize=13)
fig.savefig(ROOT / "operations.pdf")
fig.savefig(ROOT / "operations.png", dpi=180)
