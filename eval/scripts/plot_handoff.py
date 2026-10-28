"""Plot regenerated paired overheads and census outcomes; no benchmark execution."""

import argparse
import csv
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("package", type=Path)
args = parser.parse_args()
root = args.package
out = root / "plots"
out.mkdir(exist_ok=True)
plt.rcParams.update(
    {
        "font.family": "serif",
        "font.serif": ["STIXGeneral"],
        "mathtext.fontset": "stix",
        "pdf.fonttype": 42,
    }
)
rows = list(csv.DictReader((root / "summaries/overheads.csv").open()))
fig, axes = plt.subplots(1, 3, figsize=(13, 4), layout="constrained")
for ax, experiment in zip(axes, ["comparison", "application", "samples"], strict=True):
    selected = [r for r in rows if r["experiment"] == experiment]
    for i, r in enumerate(selected):
        mean, lo, hi = [float(r[k]) for k in ("added_ms", "ci95_low_ms", "ci95_high_ms")]
        ax.errorbar(
            mean,
            i,
            xerr=[[mean - lo], [hi - mean]],
            fmt="o",
            color="#4477AA" if r["mode"] == "landlock" else "#AA3377",
        )
    ax.set_yticks(range(len(selected)), [r["case"] + "/" + r["mode"] for r in selected], fontsize=7)
    ax.axvline(0, color="black", linewidth=0.5)
    ax.set_title(experiment)
    ax.set_xlabel("Paired added ms; 95% t CI, five sessions (df=4)")
fig.savefig(out / "paired-overheads.pdf")
plt.close(fig)
security = json.loads((root / "summaries/security.json").read_text())
fig, ax = plt.subplots(figsize=(8, 3), layout="constrained")
left = [0, 0, 0]
modes = ["plain", "landlock", "container"]
for outcome in ["operation_denied", "operation_error", "no_effect_observed", "effect_observed"]:
    values = [security[m]["outcomes"].get(outcome, 0) for m in modes]
    ax.barh(modes, values, left=left, label=outcome)
    left = [a + b for a, b in zip(left, values, strict=True)]
ax.set_xlabel("Forbidden trials (49 cases x 3); descriptive counts, no uncertainty interval")
ax.legend(fontsize=7, loc="upper center", bbox_to_anchor=(0.5, 1.3), ncol=2)
fig.savefig(out / "census-outcomes.pdf")
