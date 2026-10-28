#!/usr/bin/env bash
# Run from the frozen detached checkout. Each output directory must not exist.
set -euo pipefail

CAMPAIGN=/data/langgraph/eval/campaigns/current-implementation-v1
PYTHON=/data/langgraph/libs/prebuilt/.venv/bin/python
FROZEN=/tmp/langgraph-coherent-eval-bdb0cb9d4
PYTHONPATH="$FROZEN/eval/src:$FROZEN/eval/remaining:$FROZEN/libs/prebuilt:$FROZEN/libs/langgraph:$FROZEN/libs/checkpoint"
export PYTHONPATH

# In a separate terminal, with the pinned qwen3:8b image already present:
# OLLAMA_CONTEXT_LENGTH=40960 ollama serve

"$PYTHON" eval/remaining/application_campaign.py \
  --output "$CAMPAIGN/raw/pandas-v19-rerun" \
  --repetitions 5 --graph-retries 3 \
  --lean-worker-binary /data/langgraph/proofs/worker-route/.lake/build/bin/workerRoute \
  --lean-worker-sha256 6097be9b7b84639959c7a0b9de31c79f23486e9f01bf1b6de575dfab25c7cb08 \
  --workflow-contract preserve-request-v5 \
  --sandbox-serialization recursive-json-v2
"$PYTHON" eval/remaining/verify_pandas_campaign.py \
  "$CAMPAIGN/raw/pandas-v19-rerun"

"$PYTHON" eval/apps/pandas/closed_campaign.py \
  --output "$CAMPAIGN/raw/pandas-closed-rerun" \
  --repetitions 5 --manifest v21
# The verifier returns 1 because utility is deliberately 45/50. Its JSON report
# must show the five retained monthly_mean failures and an empty issues array.
set +e
"$PYTHON" eval/apps/pandas/verify_closed_campaign.py \
  "$CAMPAIGN/raw/pandas-closed-rerun" --expect-repetitions 5
closed_verify_status=$?
set -e
if [[ "$closed_verify_status" -ne 1 ]]; then
  echo "unexpected closed verifier status: $closed_verify_status" >&2
  exit 1
fi

"$PYTHON" "$CAMPAIGN/scripts/run_language_useful_work.py" \
  --output "$CAMPAIGN/raw/language-useful-work-v1"
"$PYTHON" "$CAMPAIGN/scripts/run_landlock_costs.py" \
  --output "$CAMPAIGN/raw/landlock-costs-v1"
"$PYTHON" "$CAMPAIGN/scripts/run_container_costs.py" \
  --output "$CAMPAIGN/raw/container-costs-v1"
"$PYTHON" "$CAMPAIGN/scripts/run_broker_costs.py" \
  --output "$CAMPAIGN/raw/broker-costs-v1"

"$PYTHON" eval/remaining/composition.py \
  --output "$CAMPAIGN/raw/sqlite-composition-v1" --repetitions 5
"$PYTHON" eval/remaining/pump_composition.py \
  --output "$CAMPAIGN/raw/pump-composition-v1" --repetitions 5
"$PYTHON" workspace/06_database/demo.py \
  >"$CAMPAIGN/raw/alice-bob-demo.log" 2>&1
"$PYTHON" "$CAMPAIGN/scripts/summarize_composition.py"

"$PYTHON" "$CAMPAIGN/regenerate.py"
