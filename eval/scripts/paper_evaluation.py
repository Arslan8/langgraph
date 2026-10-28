"""Recompute a unified paper report from named, non-pooled evidence cohorts."""

from __future__ import annotations

import json
import statistics
from collections import Counter
from pathlib import Path

from slanggraph_eval.isolation.operations import summarize as summarize_operations
from slanggraph_eval.isolation.run import digest
from slanggraph_eval.isolation.runtime import stats, summarize
from slanggraph_eval.isolation.verified import summarize as summarize_verified

ROOT = Path(__file__).resolve().parents[1]
INPUTS = {}
PROTOCOL = ROOT / "reports/repeated-v2"
STATUS = (
    json.loads((PROTOCOL / "status.json").read_text())
    if (PROTOCOL / "status.json").exists()
    else {}
)
STANDARDIZED = all(
    isinstance(STATUS.get(name), dict) and STATUS[name].get("measured_per_cell") == 100
    for name in ("verified", "operations", "runtime", "pandas", "audit")
)
HISTORICAL = {
    "reports/repeated-v1/verified": "reports/e6/verified-v2",
    "reports/repeated-v1/operations": "reports/e6/operations-v1",
    "reports/repeated-v1/runtime": "reports/e6/runtime-v1",
    "reports/repeated-v1/pandas": "results/pandas-runtime-20261026-v1",
    "reports/repeated-v1/audit": "results/pandas-runtime-audit-profile-20261026-v1",
}


def read(relative):
    relative = str(relative)
    if STANDARDIZED:
        relative = relative.replace("reports/repeated-v1", str(PROTOCOL.relative_to(ROOT)))
    else:
        for pending, historical in HISTORICAL.items():
            relative = relative.replace(pending, historical)
    path = ROOT / relative
    INPUTS[str(relative)] = digest(path)
    if path.suffix == ".jsonl":
        return [json.loads(line) for line in path.read_text().splitlines()]
    return json.loads(path.read_text())


def matched(rows, left, right, field="elapsed_ms", condition="configuration", key="round"):
    a = {r[key]: r[field] for r in rows if r[condition] == left}
    b = {r[key]: r[field] for r in rows if r[condition] == right}
    if not a or a.keys() != b.keys():
        raise ValueError("missing matched samples")
    for label in [left, right]:
        if len([r for r in rows if r[condition] == label]) != len(a):
            raise ValueError("duplicate matched samples")
    ratio = statistics.mean(a.values()) / statistics.mean(b.values())
    return stats([a[k] - b[k] for k in sorted(a)]) | {
        "ratio_of_means": ratio,
        "overhead_percent": 100 * (ratio - 1),
    }


def validate_replay(folder):
    rows = [r for r in read(f"{folder}/samples.jsonl") if r["phase"] == "measured"]
    recorded = read(f"{folder}/summary.json")
    for config in "ABC":
        selected = [r for r in rows if r["configuration"] == config]
        assert all(r["valid"] for r in selected)
        actual = stats([r["elapsed_ms"] for r in selected])
        for key, value in actual.items():
            assert value == recorded["configurations"][config][key], (config, key)
        for stage, summary in recorded["configurations"][config]["stages"].items():
            assert stats([r["spans"][stage] for r in selected]) == summary
    for left, right in [("B", "A"), ("C", "A"), ("C", "B")]:
        recomputed = matched(rows, left, right)
        for key, value in recorded["paired_differences"][left + "-" + right].items():
            assert recomputed[key] == value
    return recorded


def publication_view(document, standardized):
    """Keep preliminary timings out of the primary evaluation's performance claims."""
    if standardized:
        return document, None
    start = document.index("## 4. Application runtime overhead and variance")
    end = document.index("## 7. Claim boundaries and reproduction")
    appendix = (
        "# Historical runtime observations — preliminary\n\n"
        "These are recorded observations, not accepted primary performance results. "
        "They have not been replicated under the fixed session protocol. "
        "The plain-Python experiments do not measure verified-language isolation. "
        "Ratios describe only their named workload and cohort; they do not establish "
        "a general speed advantage or a pure kernel-isolation cost. Raw observations "
        "and actual sample counts are preserved for audit.\n\n" + document[start:end]
    )
    replacement = (
        "## 4. Runtime evaluation status\n\n"
        "**No primary runtime-overhead estimate is established yet.** The earlier "
        "single-session measurements are preliminary. They are retained in the "
        "[historical timing appendix](historical-runtime.md), including means, SD, "
        "variance, percentiles, stage costs and raw evidence. They must not support "
        "a headline claim that verified-language execution is generally faster by "
        "a particular factor.\n\n"
        "| Experiment | Historical measured calls per cell | Required measured calls | Status |\n"
        "| --- | ---: | ---: | --- |\n"
        "| Verified language versus host | 50, one session | 100, five sessions | "
        "Rerun required |\n"
        "| Per-operation Python versus host | 50, one session | 100, five sessions | "
        "Rerun required |\n"
        "| Backend ablations | 100, one session | 100, five sessions | Replication required |\n"
        "| Pandas recorded computation | 100, one session | 100, five sessions | "
        "Replication required |\n"
        "| Audit diagnostic | 20, one session | 100, five sessions | Rerun required |\n\n"
        "The [fixed protocol](../REPETITION_PROTOCOL.md) uses five process sessions, "
        "20 measured calls and ten excluded warmups per session. Setup and first-use "
        "costs remain separate. Confidence intervals use session means. The five-run "
        "model-driven application study remains exploratory and is not included in "
        "the primary timing comparison.\n\n"
        "The real host-isolation preflight currently fails while creating the "
        "network namespace (`Operation not permitted`). No replacement timing "
        "samples have been collected. See the [failure record](repeated-v2/preflight.json). "
        "The evaluation does not replace the confined worker with an unconfined one. "
        "[Alternative backend probes](isolation-alternatives/README.md) succeeded for "
        "rootless Docker and Landlock ABI 7. Those feasibility checks have not yet "
        "been ported into the production timing comparison.\n\n"
    )
    return document[:start] + replacement + document[end:], appendix


def main():
    verified_plan = read("reports/repeated-v1/verified/plan.json")
    verified_rows = read("reports/repeated-v1/verified/samples.jsonl")
    verified_summary = summarize_verified(verified_rows, verified_plan["samples"])
    assert verified_summary == read("reports/repeated-v1/verified/summary.json")
    read("reports/repeated-v1/verified/setup.json")
    read("reports/repeated-v1/verified/admission-census.json")
    runtime_rows = read("reports/repeated-v1/runtime/samples.jsonl")
    runtime = summarize(runtime_rows)
    assert runtime == read("reports/repeated-v1/runtime/summary.json")
    operation_plan = read("reports/repeated-v1/operations/plan.json")
    operation_rows = read("reports/repeated-v1/operations/samples.jsonl")
    operation_summary = summarize_operations(
        operation_rows,
        tuple(c["name"] for c in operation_plan["operations"]),
        operation_plan["samples"],
    )
    assert operation_summary == read("reports/repeated-v1/operations/summary.json")
    host = read("reports/repeated-v1/runtime/host-before.json")
    read("reports/repeated-v1/runtime/host-after.json")
    macro = validate_replay("reports/repeated-v1/pandas")
    audit = validate_replay("reports/repeated-v1/audit")
    security = read("reports/e6/isolation-v1/trials.jsonl")
    for condition in ("trusted", "language_helper", "host", "host_language_helper"):
        selected = [r for r in security if r["condition"] == condition]
        assert len(selected) == 177
        forbidden = [r for r in selected if not r["allowed"]]
        assert len(forbidden) == 147
        assert sum(r["effect_observed"] for r in forbidden) == (
            147 if condition in {"trusted", "language_helper"} else 0
        )
    dispatch = read("results/pandas-dispatch-20261026-v1/summary.json")
    assert len(dispatch) == 8 and all(r["passed"] for r in dispatch)
    controlled_ids = [
        "pandas-A-dataset-write-r1-c6e2c89e9c6b41288b6d2eea99270647",
        "pandas-A-extra-read-r1-aa51d13f40864b319b69cad7decf6edf",
        "pandas-A-internal-read-r1-7cb0f0c3ccde4b7ab0ba47764fff69b1",
        "pandas-B-dataset-write-r1-a4042599d8444667944ad50cd0ca7152",
        "pandas-B-extra-read-r1-1dd464a659c64d21a5c2ffcb71bb055e",
        "pandas-B-internal-read-r1-7d10c42c112143ec8cebba08c7079c1e",
        "pandas-C-dataset-write-r1-1de78e5f46f0452d9fdc45310ec5872b",
        "pandas-C-extra-read-r1-bf578b1e214645a88738ae90f925a71f",
        "pandas-C-internal-read-r1-4a580d56e6ba4b78ad088cd5e42e1841",
    ]
    controlled = [read(f"results/{name}/result.json") for name in controlled_ids]
    assert all(
        read(f"results/{name}/fixture.json")["profile"] == "narrow" for name in controlled_ids
    )
    for condition in "ABC":
        selected = [r for r in controlled if r["configuration"] == condition]
        assert len(selected) == 3 and all(r["task_success"] for r in selected)
        assert sum(r["observed_external_effect"] for r in selected) == (
            0 if condition == "C" else 3
        )
    launches = read("results/pandas-e2e-repetitions-20261026-attempt2/launches.jsonl")
    application = []
    for launch in launches:
        path = Path(json.loads(launch["stdout"])["result"])
        application.append(read(Path("results") / path.parent.name / path.name))
    clean = [r for r in application if r["case_id"] == "february"]
    attacks = [r for r in application if r["case_id"] == "csv-injection"]
    assert len(clean) == len(attacks) == 15
    assert all(r["task_success"] for r in clean)
    assert all(
        not r.get("actual_attempted_operation") and not r.get("observed_external_effect")
        for r in attacks
    )
    for row in clean:
        row["elapsed_ms"] = row["elapsed_seconds"] * 1000
    cpu = {r["field"].rstrip(":"): r["data"] for r in json.loads(host["lscpu"]["stdout"])["lscpu"]}
    memory_kib = int(host["memory"].splitlines()[0].split()[1])
    lines = [
        "# Security, ports, exposure reduction, and runtime overhead",
        "",
        "This report separates application evidence, deterministic operation coverage, "
        "and timing experiments. It supersedes the E6-only narrative as the evaluation "
        "entry point. The evidence supports one experimental protected application "
        "integration, two further baseline adaptations, and five blocked candidates; "
        "it does not support eight completed ports.",
        "",
        "Timing counts follow the [fixed repetition protocol](../REPETITION_PROTOCOL.md): "
        "100 measured calls per cell, five sequential process sessions, 20 measured calls "
        "and ten warmups per session. Older cohorts remain archived and are not pooled. "
        "Full model-driven workflows and injection runs remain historical pilot evidence; "
        "they are excluded from standardized timing claims.",
        "",
        "## 1. Experimental configurations and host",
        "",
        "Application A retains the released Pandas Python sandbox; B adds a ToolNode "
        "authorization boundary; C adds the Linux executor to that boundary while retaining "
        "the upstream sandbox program. E6 uses separate synthetic trusted/restricted-language "
        "conditions. The two sets must not be equated or pooled.",
        "",
        "| Host field | Measured value |",
        "| --- | --- |",
        f"| CPU | {cpu['Model name']}; {cpu['Socket(s)']} socket; "
        f"{cpu['Core(s) per socket']} cores/socket; {cpu['CPU(s)']} logical CPUs |",
        f"| RAM | {memory_kib / 1024**2:.2f} GiB |",
        f"| OS/kernel | {host['platform']} |",
        f"| E6 runtime Python | {host['python'].splitlines()[0]} |",
        "| Application Python | 3.13.11 (Pandas/SQL); 3.12.3 (Notebook) |",
        "| GPUs | 2 x NVIDIA RTX A4000, 16,376 MiB each; driver 580.178.04 |",
        f"| bubblewrap | {host['bubblewrap']['stdout'].strip()} |",
        f"| Timing CPU affinity | {host['affinity']} (inherited by workers) |",
        "| Evidence disk | ext4 on /dev/sda2, rotating ST12000NM000J |",
        "| Model | local Ollama 0.32.14; Pandas qwen3:8b, Q4_K_M, temperature 0 |",
        "| Benchmark clock | perf_counter_ns; monotonic wall duration |",
        "| OS cache / CPU frequency | uncontrolled; no cache flush or fixed frequency |",
        "",
        "[Current E6 host capture](repeated-v1/runtime/host-before.json) records CPU, memory, "
        "affinity, load, block device, filesystem, GPU, and clock details. "
        "[Application host capture](../reports/repeated-v1/pandas/host.json) "
        "belongs to its own cohort. The older HARDWARE.md describes an earlier kernel "
        "and must not override these run-level records. Runtime experiments make no "
        "model calls; GPUs are relevant only to application inference. The machine "
        "was not exclusively reserved; variation is measured, not assumed absent.",
        "",
        "## 2. Port descriptions and evaluation scope",
        "",
        "| Application / pin | Original execution and adaptation | Measured statu"
        "s / remaining boundary |",
        "| --- | --- | --- |",
        "| [Pandas](../apps/pandas/README.md), 4ffeb7f38178 | Original PandasDataAnalyst, "
        "wrangling and visualization graphs; local provider, fixture and backend adapter; "
        "B inserts dispatch, C runs original sandbox program in Linux worker | "
        "One experimental A/B/C integration; 1/3 original clean tasks succeeds in each "
        "condition; repeated February task succeeds. Parent/model/UI effects excluded. |",
        "| [SQL](../apps/sql/README.md), 4ffeb7f38178 | Original SQLDatabaseAgent.ainvoke_agent, "
        "SQLAlchemy connection and safe_mode; synthetic sales/payroll DB | "
        "3/3 baseline tasks pass; no protected port. Schema sampling and arbitrary SQL "
        "need mediation beyond the fixed-record broker. |",
        "| [Notebook](../apps/notebook/README.md), a0f6f3081ae0 | Original ingestion API/worker, "
        "source_chat_graph, native Ollama and dedicated SurrealDB | "
        "1/1 baseline smoke; no protected port. API/worker/DB authority is outsid"
        "e client confinement. |",
        "| [Email](../apps/email/README.md), 758db7174223 | Archived Executive AI Assistant; "
        "Gmail integration | No completed smoke/port; dependency and dedicated-account blockers. |",
        "| [Research](../apps/research/README.md), 1b7d2e80db9f | Archived Open Deep Research; "
        "search and structured model calls | No completed smoke/port; reproducibl"
        "e search/local model route missing. |",
        "| [Coding](../apps/coding/README.md), ff4e713c094c | Open SWE, remote execution and "
        "GitHub/MDA services | No completed smoke/port; dedicated services and ex"
        "ecution-host instrumentation missing. |",
        "| [Newspaper](../apps/newspaper/README.md), 1c447b5672dd | GPT Newspaper search, "
        "writing and output workflow | No completed smoke/port; search service or"
        " frozen contract-preserving fixture missing. |",
        "| [Finance](../apps/finance/README.md), 6c41ae8cf5fb | Historical LangGraph workflow "
        "selected after upstream removal | No verified smoke/port; provider fixtu"
        "re/local execution incomplete; no trading. |",
        "",
        "Full immutable revisions and installation evidence are in the [intake le"
        "dger](../apps.csv). "
        "Pandas C replaces the outer subprocess launch because the host profile prohibits "
        "child creation; it retains AST/import/builtin/network checks and JSON transport. "
        "The original upstream files are unchanged, but adapters are substantive work, "
        "not zero-cost ports. SQL and Notebook retain their original graphs; replacing "
        "either with a demo broker would not constitute a faithful port. Engineering "
        "hours were not recorded. No overhead or security reduction is assigned t"
        "o an unported app.",
        "",
        "## 3. Security evaluation and exposure reduction",
        "",
        "For a fixed eligible probe set P, observed reachability is the number of distinct "
        "probes producing the forbidden effect. Reduction is (baseline reachability - "
        "protected reachability) / baseline reachability. Repetitions test stability; "
        "they do not increase the number of independent probes.",
        "",
        "This section retains historical application and E6 evidence. The current "
        "Landlock/container census and production verified-language controls are in "
        "Section 4; the historical host results below are not measurements of those adapters.",
        "",
        "| Evidence / denominator | Baseline | Protected | Exposure reduction and interpretation |",
        "| --- | ---: | ---: | --- |",
        "| Pandas controlled effects: two narrow reads + read-only dataset overwrite | "
        "A 3/3; B 3/3 | C 0/3 | 100% observed probe-reachability reduction for C; 0% for B |",
        "| Historical E6 forbidden operation/surface cases | trusted 49/49; helper 49/49 | "
        "host 0/49; combined 0/49 | 100% observed reduction; explicit denial esta"
        "blished for 45/49 cases |",
        "| Pandas frozen CSV injection, five runs/configuration | 0/5 effects, 0 attempts | "
        "0/5 effects, 0 attempts | Enforcement success and relative reduction und"
        "efined: no eligible attempts |",
        "| E1 static headline sink projection | 8 exposed | host-model 4; composed-model 0 | "
        "50% / 100% projected reduction; not measured runtime enforcement |",
        "",
        "The [application controlled-effect evidence](application-pilot.md) preserves the "
        "legitimate February computation while adding one operation. Narrow/broad supplementary "
        "read policies supply a matched permitted control. Private-/tmp shadow writes are "
        "reported as host containment, not as proof of a guest-wide output-only policy. "
        "The three-probe denominator excludes that unsupported restriction. The four "
        "[dispatch checks](../results/pandas-dispatch-20261026-v1/summary.json) distinguish "
        "authorization from containment of an already-authorized tool; B/C each pass 4/4.",
        "",
        "The historical E6 cohort exercises filesystem APIs, metadata, aliases, "
        "native/dynamic code, environment, "
        "processes, loopback networking, SQLite, and a bounded file-size limit on hidden, "
        "read-only and writable surfaces. All 49 baseline effects reproduce in all three "
        "repetitions. Both host conditions preserve 30/30 positive controls. Of 147 forbidden "
        "trials per host condition, 135 have an explicit denial, six generic SQLite errors, "
        "and six empty/absent results. The last 12 are not credited as explicit runtime "
        "blocking. The synthetic direct-language frontend rejects 27/30 controls; its zero "
        "effects are not evidence of useful complete mediation. See the "
        "[per-case matrix](e6/isolation-v1/report.md) and [protocol](../ISOLATION.md).",
        "",
        "[E1](e1/exposure.md) projects adapter capabilities onto a static sink report. "
        "In particular, its host model includes capabilities that must not be attributed "
        "to the measured Linux filesystem adapter. Static sink counts, observed operation "
        "effects, and prompt-injection outcomes are different metrics.",
        "",
        "## 4. Application runtime overhead and variance",
        "",
        "These costs come from replaying the same recorded, successful February "
        "computation and inputs through A/B/C—not from E6 or a no-op. Each configuration "
        "has 100 measured calls across five fresh process sessions (20 each), with ten "
        "warmups and a separately retained first-use call per session; order is randomized "
        "by round. Fixture setup and integration initialization are excluded; dispatch, "
        "subprocess/host execution, synchronous audit, and integration evidence IO are "
        "included. Every result is checked to equal 120. Raw samples and nested spans "
        "were recomputed and checked against the saved summaries.",
        "",
        "| Configuration | n | Mean ms | SD ms | Variance ms² | Median ms | P95 ms |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for condition, values in macro["configurations"].items():
        lines.append(
            f"| {condition} | {values['n']} | {values['mean_ms']:.2f} | "
            f"{values['sd_ms']:.2f} | {values['variance_ms2']:.2f} | "
            f"{values['median_ms']:.2f} | {values['p95_ms']:.2f} |"
        )
    lines += [
        "",
        "| Paired contrast | Mean increment ms | SD ms | Variance ms² | Ratio of means |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for name, values in macro["paired_differences"].items():
        lines.append(
            f"| {name} | {values['mean_ms']:.2f} | {values['sd_ms']:.2f} | "
            f"{values['variance_ms2']:.2f} | {values['ratio_of_means']:.3f}x |"
        )
    lines += [
        "",
        f"C adds {macro['paired_differences']['C-A']['mean_ms']:.2f} ms relative to A "
        f"({100 * (macro['paired_differences']['C-A']['ratio_of_means'] - 1):.1f}% overhead). "
        f"C versus B adds {macro['paired_differences']['C-B']['mean_ms']:.2f} ms.",
        "",
        "### Where the application overhead comes from",
        "",
        "All replay and audit-diagnostic values below are recomputed from 100 measured "
        "calls per configuration across five sessions. Nested spans are not additive. "
        "The per-stage tables and session intervals are linked below; residual time is "
        "not attributed to kernel enforcement.",
        "",
        "[Replay session intervals](repeated-v1/pandas/report.md), "
        "[audit session intervals](repeated-v1/audit/report.md), and "
        "[full stage statistics](repeated-v1/pandas/summary.json).",
        "",
        "Historical pilot only: five full-workflow clean repetitions include model inference, "
        "setup, strace, "
        "and the oracle. These are separately reported in seconds:",
        "",
        "| Condition | n | Mean s | SD s | Variance s² | Median s | Min-max s |",
        "| --- | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    stage_table = [
        "| Replay configuration / measured scope | Mean ms | SD ms |",
        "| --- | ---: | ---: |",
    ]
    for configuration, data in macro["configurations"].items():
        for scope, values in data["stages"].items():
            stage_table.append(
                f"| {configuration} / {scope} | {values['mean_ms']:.2f} | {values['sd_ms']:.2f} |"
            )
    for configuration in "BC":
        value = audit["configurations"][configuration]["stages"]["audit_write_ms"]
        stage_table.append(
            f"| {configuration} / audit write (separate diagnostic) | "
            f"{value['mean_ms']:.2f} | {value['sd_ms']:.2f} |"
        )
    stage_table.append("")
    stage_index = next(
        i for i, line in enumerate(lines) if line.startswith("Historical pilot only:")
    )
    lines[stage_index:stage_index] = stage_table
    for condition in "ABC":
        values = stats([r["elapsed_seconds"] for r in clean if r["configuration"] == condition])
        lines.append(
            f"| {condition} | {values['n']} | {values['mean_ms']:.3f} | "
            f"{values['sd_ms']:.3f} | {values['variance_ms2']:.3f} | "
            f"{values['median_ms']:.3f} | {values['min_ms']:.3f}-{values['max_ms']:.3f} |"
        )
    lines += [
        "",
        "Full-workflow C/A is 1.202x (+20.2%), with paired increment 2.577 s "
        "(SD 1.446 s). This is an observed total-workflow difference, not isolated "
        "enforcement overhead. The first A run includes post-restart model loading "
        "and is retained. Five runs of one task do not estimate across-application "
        "variance. [Raw replay](../reports/repeated-v1/pandas/), "
        "[audit diagnostic](../reports/repeated-v1/audit/), "
        "and [full-workflow cohort](../results/pandas-e2e-repetitions-20261026-attempt2/) "
        "remain separate. Thirty earlier server-unavailable launches are retained "
        "as infrastructure failures, not as successful defenses.",
        "",
        "## 5. Matched backend overhead: new E6 runtime experiment",
        "",
        "The previous median over mixed successes and rejections was not a valid "
        "overhead estimate. This new experiment uses only three successful workloads: "
        "arithmetic, canary-file read, and 4 KiB write. For each workload/condition "
        "there are 100 measured calls across five sessions, each with ten warm-ups and a "
        "first-use call. Order is shuffled within each paired round with seed 20261026. "
        "Each call starts a fresh worker; executor construction/preflight is outside "
        "the dispatch timer and recorded separately. No model or durable audit sink "
        "is involved. The same positive oracle must pass for every timing sample.",
        "",
        "| Workload | Condition | n | Mean ms | SD ms | Variance ms² | Median ms | P95 ms |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for workload, result in runtime.items():
        for condition, data in result["conditions"].items():
            v = data["dispatch"]
            lines.append(
                f"| {workload} | {condition} | {v['n']} | {v['mean_ms']:.2f} | "
                f"{v['sd_ms']:.2f} | {v['variance_ms2']:.2f} | "
                f"{v['median_ms']:.2f} | {v['p95_ms']:.2f} |"
            )
    lines += [
        "",
        "| Workload | Paired contrast | Increment ms | SD ms | Variance ms² | Overhead |",
        "| --- | --- | ---: | ---: | ---: | ---: |",
    ]
    for workload, result in runtime.items():
        for name, v in result["paired"].items():
            lines.append(
                f"| {workload} | {name} | {v['mean_ms']:.2f} | {v['sd_ms']:.2f} | "
                f"{v['variance_ms2']:.2f} | {v['overhead_percent']:.1f}% |"
            )
    lines += [
        "",
        "### Measured source of backend cost",
        "",
        "The following exclusive partition sums to the host dispatch total. Each stage "
        "is measured by wrapping the production method without changing enforcement. "
        "Policy is the CedarPolicyBackend.filter span: the production backend writes "
        "policy/request files, validates with the Cedar CLI, and launches an authorize "
        "command for each evaluated rule. This is policy-engine/serialization/process "
        "cost, not kernel sandbox overhead. See "
        "[the measured implementation](../../libs/prebuilt/langgraph/prebuilt/security/cedar.py). "
        "Other-invoke is an arithmetic residual, not a named measured mechanism. Worker "
        "includes launch, confinement activation, execution, result handling and teardown. "
        "The combined language/host stage results are retained in summary.json.",
        "",
        "| Workload | Stage | Mean ms | SD ms | Share of dispatch |",
        "| --- | --- | ---: | ---: | ---: |",
    ]
    for workload, result in runtime.items():
        data = result["conditions"]["host"]
        for name, v in data["stages"].items():
            lines.append(
                f"| {workload} | {name} | {v['mean_ms']:.3f} | {v['sd_ms']:.3f} | "
                f"{100 * v['mean_ms'] / data['dispatch']['mean_ms']:.1f}% |"
            )
    read_data = runtime["allowed_read"]["conditions"]["host"]
    policy = read_data["stages"]["policy"]
    worker = read_data["stages"]["worker"]
    total = read_data["dispatch"]["mean_ms"]
    lines += [
        "",
        f"For the matched read workload, policy filtering accounts for "
        f"{policy['mean_ms']:.2f} ms ({100 * policy['mean_ms'] / total:.1f}%) "
        f"of host dispatch; worker execution/supervision accounts for "
        f"{worker['mean_ms']:.2f} ms ({100 * worker['mean_ms'] / total:.1f}%). "
        "The dominant measured backend cost is policy filtering, not simply "
        "worker launch. Across these tiny operations host latency is nearly "
        "constant, so fixed per-call work dominates useful computation.",
        "",
        "Policy and worker spans also have the largest stage-level SDs. Their "
        "variances must not be added: correlated timing fluctuations contribute "
        "covariance. Paired-overhead SD is computed from same-round differences. "
        "Small negative host+helper versus host differences are within variation "
        "and do not establish a speedup. This pinned-CPU, instrumented cohort "
        "differs from the earlier unrestricted-affinity security census; its "
        "timings are not pooled with the old mixed-outcome medians.",
    ]
    lines += ["", "| Workload | Host setup/preflight mean ms | SD ms |", "| --- | ---: | ---: |"]
    for workload, result in runtime.items():
        v = result["conditions"]["host"]["setup"]
        lines.append(f"| {workload} | {v['mean_ms']:.2f} | {v['sd_ms']:.2f} |")
    lines += [
        "",
        "[Runtime plan](repeated-v1/runtime/plan.json), "
        "[raw samples](repeated-v1/runtime/samples.jsonl), "
        "[derived statistics](repeated-v1/runtime/summary.json), and "
        "[source archive](repeated-v1/runtime/sources.tar.gz) identify the exact experiment. "
        "Small instrumentation costs are included; no uninstrumented speedup is inferred. "
        "These are sequential within-host timing observations, not independent tasks; "
        "SD/variance describe observed jitter. No unsupported IID confidence interval "
        "or population-level ASR is reported.",
        "",
        "![Security reachability and paired runtime distributions](evaluation-summary.png)",
        "",
        "## 7. Claim boundaries and reproduction",
        "",
        "The remaining publication gaps are substantive: multiple fully protected "
        "application ports, a frozen multi-task workload, successful model-driven "
        "attack attempts, broader verified-language operation coverage, capability-degradation "
        "tests, races, and multi-host measurements. The existing evidence does not "
        "justify filling those cells with zeroes or calling candidates completed ports. "
        "Kernel exploits, service authorization and cross-session flow are not covered "
        "by file-operation denial. Every number here refers to its stated finite corpus.",
        "",
        "```sh",
        "cd eval",
        "uv run python -m slanggraph_eval.isolation.runtime \\",
        "  --samples 100 --warmup 10 --output reports/e6/runtime-new",
        "uv run python scripts/paper_evaluation.py",
        "```",
        "",
        "The report builder uses the named frozen cohorts above, checks the old replay "
        "statistics against raw samples, recomputes the E6 summary and paired deltas, "
        "and writes input hashes to evaluation-metrics.json. To analyze another cohort, "
        "select its path explicitly; never overwrite an existing run directory.",
    ]
    operation_section = [
        "## 6. Per-operation microbenchmarks",
        "",
        "The expanded backend microbenchmark uses 16 operation/API variants and 100 "
        "matched samples per variant across five process sessions (20 each; ten warmups each). "
        "Every call must complete "
        "its intended operation in both modes. The baseline is a plain Python "
        "subprocess; it is neither statically verified language mode nor the "
        "Pandas application sandbox. Every host invocation launches a fresh worker. "
        "The table measures whole-call overhead, not overhead added to each syscall.",
        "",
        "| Operation | Python mean ms | Host mean ms | Paired overhead ms | "
        "Overhead SD ms | Overhead variance ms² | Host/Python |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name, data in operation_summary.items():
        plain = data["conditions"]["trusted"]["dispatch_ms"]
        host_data = data["conditions"]["host"]["dispatch_ms"]
        delta = data["paired_dispatch_ms"]
        operation_section.append(
            f"| {name} | {plain['mean_ms']:.2f} | {host_data['mean_ms']:.2f} | "
            f"{delta['mean_ms']:.2f} | {delta['sd_ms']:.2f} | "
            f"{delta['variance_ms2']:.2f} | {data['ratio_of_means']:.2f}x |"
        )
    operation_section += [
        "",
        "The inner timer separately measures operation statements after imports, "
        "excluding compilation, startup, policy evaluation and transport. It includes "
        "Python wrappers, open/close and user-space work; it is not pure syscall time. "
        "[Body timing, stage breakdown and scope](repeated-v1/operations/report.md) and "
        "[full-precision CSV](repeated-v1/operations/operations.csv) accompany the "
        "[raw samples](repeated-v1/operations/samples.jsonl). No denial is passed off as "
        "a faster successful operation; unsupported child-exec chains, network "
        "operations and metadata mutations are listed explicitly in the report.",
        "",
        "![Per-operation overhead and body time](repeated-v1/operations/operations.png)",
        "",
    ]
    index = lines.index("## 7. Claim boundaries and reproduction")
    lines[index:index] = operation_section
    verified_section = [
        "## 6a. Actual source-verified language execution versus Linux",
        "",
        "This is the direct production-mode comparison. The verified condition uses "
        "cedar_security admission, runtime binding validation and grant-checked read_text. "
        "Both conditions use real Cedar authorization. One hundred paired samples "
        "span five sessions (20 each), with ten "
        "warmups per session. Setup/static admission is timed separately. Executors are reused; "
        "host workers are fresh. Read sizes are workload variants, not distinct APIs.",
        "",
        "| Workload | Verified mean ms | Host mean ms | Paired added ms | Added SD ms | "
        "Host/verified |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name, data in verified_summary.items():
        a, b = [data["conditions"][c]["elapsed_ms"]["mean_ms"] for c in ("verified", "host")]
        d = data["paired_added_ms"]
        verified_section.append(
            f"| {name} | {a:.3f} | {b:.3f} | {d['mean_ms']:.3f} | "
            f"{d['sd_ms']:.3f} | {data['host_over_verified']:.2f}x |"
        )
    verified_section += [
        "",
        "[Full production comparison, static admission costs and policy/execution "
        "breakdown](repeated-v1/verified/report.md). The two executors have different policy "
        "frontends; their total difference is implementation overhead, not a pure kernel "
        "isolation tax. Raw API probes from the previous 16-operation experiment are "
        "submitted to the actual verifier and rejection diagnostics are saved. Rejected "
        "operations receive no successful-operation runtime. Broad typed-resource ports "
        "and a verified-mode application port remain necessary for broader claims.",
        "",
    ]
    index = lines.index("## 7. Claim boundaries and reproduction")
    lines[index:index] = verified_section
    intervals = {
        name: read(f"reports/repeated-v1/{name}/session-inference.json")
        for name in (
            ("verified", "operations", "runtime", "pandas", "audit") if STANDARDIZED else ()
        )
    }
    interval_section = [
        "## 6b. Uncertainty between sessions",
        "",
        "Intervals are approximate 95% Student t intervals on five session mean paired "
        "differences (4 degrees of freedom), not on 100 assumed-independent calls. "
        "They require approximately normal independent session means. Sequential sessions "
        "on one host may remain correlated; these are not cross-host confidence intervals.",
        "",
        "| Experiment / workload / contrast | Mean added ms | Session SD ms | 95% CI ms |",
        "| --- | ---: | ---: | --- |",
    ]
    for experiment, cases in intervals.items():
        for case, contrasts in cases.items():
            for contrast, data in contrasts.items():
                low, high = data["ci95_ms"]
                interval_section.append(
                    f"| {experiment} / {case} / {contrast} | {data['mean_ms']:.2f} | "
                    f"{data['between_session_sd_ms']:.2f} | [{low:.2f}, {high:.2f}] |"
                )
    interval_section.append("")
    index = lines.index("## 7. Claim boundaries and reproduction")
    if STANDARDIZED:
        lines[index:index] = interval_section
    else:
        # Never publish planned counts as observations or read incomplete cohorts.
        for i, line in enumerate(lines):
            if line.startswith("Timing counts follow"):
                lines[i] = (
                    "The [fixed repetition protocol](../REPETITION_PROTOCOL.md) is implemented, "
                    "but its rerun is blocked by host namespace permissions. This report "
                    "links historical measurements separately with their original counts: "
                    "verified and "
                    "operation benchmarks n=50; backend and Pandas replay n=100; audit n=20; "
                    "full workflow n=5. No 5-session results or confidence intervals are claimed."
                )
            elif line.startswith("All replay and audit-diagnostic"):
                lines[i] = (
                    "Historical replay uses 100 measured calls per configuration; its audit "
                    "diagnostic uses 20. These are separate single-session cohorts. Stage "
                    "statistics remain in the raw summaries; no new session intervals exist."
                )
            elif line.startswith("[Replay session intervals]"):
                lines[i] = "[Replay statistics](../results/pandas-runtime-20261026-v1/summary.json)"
            elif line.startswith("The expanded backend microbenchmark"):
                lines[i] = (
                    "Historical backend microbenchmark: 16 operation/API variants, 50 measured "
                    "pairs each, five warmups and one first-use pair in one session. The baseline "
                    "is plain Python, not verified language execution."
                )
            elif line.startswith("This is the direct production-mode comparison."):
                lines[i] = (
                    "Historical production comparison: 50 measured pairs per workload after five "
                    "warmups in one session. Actual source admission, runtime binding checks and "
                    "Cedar authorization are retained. Setup uses ten repeats per workload. "
                    "These measurements have not yet been rerun under the new protocol."
                )
            else:
                lines[i] = line.replace(
                    "has 100 measured calls across five fresh process sessions (20 each), with ten "
                    "warmups and a separately retained first-use call per session; "
                    "order is randomized ",
                    "has 100 measured calls, ten warmups and one first-use call in one session; "
                    "A/B/C order rotates ",
                ).replace(
                    "there are 100 measured calls across five sessions, each with "
                    "ten warm-ups and a ",
                    "there are 100 measured calls and ten warmups in one session, plus a ",
                )
        for i, line in enumerate(lines):
            for pending, historical in HISTORICAL.items():
                target = (
                    historical.removeprefix("reports/")
                    if historical.startswith("reports/")
                    else "../" + historical
                )
                line = line.replace(pending.removeprefix("reports/"), target)
            lines[i] = line
    output = {
        "runtime_claim_status": "standardized_measurements" if STANDARDIZED else "preliminary_only",
        "headline_runtime_estimate": None,
        "standardized_protocol_complete": STANDARDIZED,
        "rerun_status": STATUS,
        "session_intervals": intervals,
        "verified_language": verified_summary,
        "runtime": runtime,
        "per_operation": operation_summary,
        "application_replay": macro,
        "audit_diagnostic": audit,
        "controlled_run_ids": controlled_ids,
        "full_workflow_ms": {
            c: stats([r["elapsed_ms"] for r in clean if r["configuration"] == c]) for c in "ABC"
        },
        "full_workflow_paired_ms": {
            f"{a}-{b}": matched(clean, a, b, key="repetition_id")
            for a, b in [("B", "A"), ("C", "A"), ("C", "B")]
        },
        "security": {},
        "input_sha256": INPUTS,
    }
    for condition in sorted({r["condition"] for r in security}):
        rows = [r for r in security if r["condition"] == condition and not r["allowed"]]
        output["security"][condition] = {
            "trials": len(rows),
            "exposed_cases": sorted({r["case"] for r in rows if r.get("effect_observed")}),
            "outcomes": dict(Counter(r["outcome"] for r in rows)),
        }
    document = (
        "\n".join(lines)
        .replace("../reports/e6/", "e6/")
        .replace("../reports/../results/", "../results/")
    )
    document, historical_appendix = publication_view(document, STANDARDIZED)
    if historical_appendix is not None:
        (ROOT / "reports/historical-runtime.md").write_text(historical_appendix)
    alternative_root = ROOT / "reports/alternatives-v2"
    validated = alternative_root / "validated-metrics.json"
    if validated.exists():
        alternative = json.loads(validated.read_text())
        assert alternative["validated"] and alternative["measured_per_cell"] == 100
        for name, expected in alternative["hashes"].items():
            assert digest(alternative_root / name) == expected
        start = document.index("## 4. Runtime evaluation status")
        end = document.index("## 7. Claim boundaries and reproduction")
        section = (alternative_root / "report.md").read_text().split("\n", 1)[1]
        # This section is generated from validated raw observations, not planned counts.
        import re

        section = re.sub(r"(?m)^## ", "### ", section)
        section = re.sub(
            r"\]\(([^):]+)\)",
            lambda match: "](alternatives-v2/" + match.group(1) + ")",
            section,
        )
        document = (
            document[:start]
            + "## 4. Completed alternative-backend evaluation\n"
            + section
            + "\n"
            + document[end:]
        )
        paragraphs = document.split("\n\n")
        paragraphs = [
            "The fixed timing protocol is completed for the new verified-language, Landlock, "
            "and rootless-container comparison: 100 measured calls per workload/mode across "
            "five process sessions. The 16-operation ablation and Pandas computation replay "
            "use the same counts. Historical Bubblewrap timings remain separate and preliminary."
            if paragraph.startswith("The [fixed repetition protocol]")
            else paragraph
            for paragraph in paragraphs
        ]
        document = "\n\n".join(paragraphs)
        output["alternative_protocol_complete"] = True
        output["alternative_evaluation"] = alternative
        output["runtime_claim_status"] = "completed_alternative_backends"
        output["headline_runtime_estimate"] = alternative["timings"]["comparison"]
    (ROOT / "reports/paper-evaluation.md").write_text(document + "\n")
    (ROOT / "reports/evaluation-metrics.json").write_text(json.dumps(output, indent=2) + "\n")


if __name__ == "__main__":
    main()
