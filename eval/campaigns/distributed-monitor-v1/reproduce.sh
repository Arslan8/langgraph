#!/usr/bin/env bash
set -euo pipefail

campaign_dir=$(cd "$(dirname "$0")" && pwd)
repo_root=$(cd "$campaign_dir/../../.." && pwd)
python_bin="$repo_root/libs/prebuilt/.venv/bin/python"
raw_dir="$campaign_dir/raw"
ace_source=${ACE_SOURCE:-/tmp/ace-llm-source}
isolategpt_source=${ISOLATEGPT_SOURCE:-/tmp/secgpt-source}
ace_python=${ACE_PYTHON:-/tmp/ace-eval-venv/bin/python}
isolategpt_python=${ISOLATEGPT_PYTHON:-/tmp/secgpt-eval-venv/bin/python}

test "$(git -C "$ace_source" rev-parse HEAD)" = \
  e88f6dc16e5404131fbefe5684c7f05f856edbdd
test "$(git -C "$isolategpt_source" rev-parse HEAD)" = \
  c6020f977d20f9f80776cae5d4e2930455733ce5

test ! -e "$raw_dir" || {
  echo "Refusing to overwrite $raw_dir" >&2
  exit 1
}
mkdir -p "$raw_dir"

cd "$repo_root"
mkdir "$raw_dir/validation"
(
  cd libs/prebuilt
  make format
  make lint
  make test
) 2>&1 | tee "$raw_dir/validation/prebuilt.log"
"$python_bin" eval/distributed/freeze_environment.py \
  --output "$raw_dir/environment" --evaluated-commit HEAD
"$python_bin" eval/distributed/component_inventory.py \
  --output "$raw_dir/environment/component-inventory.json"
"$python_bin" eval/apps/pandas/closed_campaign.py \
  --output "$raw_dir/pandas-full" --repetitions 5 --configuration all
"$python_bin" eval/apps/pandas/closed_campaign.py \
  --output "$raw_dir/pandas-attack-read" --repetitions 5 --configuration C-full \
  --pilot --attack read_bob
"$python_bin" eval/apps/pandas/closed_campaign.py \
  --output "$raw_dir/pandas-attack-write" --repetitions 5 --configuration C-full \
  --pilot --attack update_bob
"$python_bin" eval/remaining/composition.py \
  --output "$raw_dir/sqlite-composition" --repetitions 5
"$python_bin" eval/remaining/pump_composition.py \
  --output "$raw_dir/pump-composition" --repetitions 5
"$python_bin" eval/distributed/policy_conflict.py \
  --output "$raw_dir/policy-conflict" --repetitions 5
"$python_bin" eval/distributed/invocation_lifetime.py \
  --output "$raw_dir/invocation-lifetime" --repetitions 5
"$python_bin" eval/distributed/http_resource.py \
  --output "$raw_dir/http-resource" --repetitions 5
"$python_bin" eval/distributed/document_workflow.py \
  --output "$raw_dir/document-workflow" --repetitions 5
"$python_bin" eval/distributed/host_compilation.py \
  --output "$raw_dir/host-compilation"
"$python_bin" eval/distributed/tool_census.py \
  --output "$raw_dir/tool-census" --ace-root "$ace_source"
"$isolategpt_python" eval/distributed/baseline_isolategpt.py \
  --output "$raw_dir/isolategpt-sandbox-probe" --source "$isolategpt_source" \
  --python "$isolategpt_python" --repetitions 5
"$ace_python" eval/distributed/baseline_ace.py \
  --output "$raw_dir/ace-sandbox-probe" --source "$ace_source" --repetitions 5
"$python_bin" eval/distributed/fare_scenarios.py \
  --output "$raw_dir/fare-scenarios" --repetitions 20
"$python_bin" eval/distributed/common_language_costs.py \
  --output "$raw_dir/common-language" --sessions 5 --warmups 5 --measured 20
"$python_bin" eval/distributed/common_linux_costs.py \
  --output "$raw_dir/common-linux" --sessions 5 --warmups 5 --measured 20
"$python_bin" eval/campaigns/current-implementation-v1/scripts/run_container_costs.py \
  --output "$raw_dir/common-container" --sessions 5 --warmups 5 --measured 20
"$python_bin" eval/campaigns/current-implementation-v1/scripts/run_broker_costs.py \
  --output "$raw_dir/broker-costs" --sessions 5 --warmups 5 --measured 20
"$python_bin" proofs/worker-route/check.py \
  --output "$raw_dir/lean-check"
"$python_bin" eval/distributed/regenerate_results.py \
  --raw "$raw_dir" --output "$campaign_dir"

(
  cd "$campaign_dir"
  find . -type f -not -path '*/.git/*' \
    -not -path '*/framework/*' \
    -not -path '*/framework-source-blobs/*' \
    -not -path '*/harness/*' \
    -not -path '*/__pycache__/*' \
    -not -path '*/lean-check/snapshot/*' \
    -not -name workerRoute \
    -not -name SHA256SUMS -print0 \
    | sort -z \
    | xargs -0 sha256sum > SHA256SUMS
)
