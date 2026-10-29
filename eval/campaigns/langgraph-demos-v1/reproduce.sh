#!/usr/bin/env bash
set -euo pipefail

campaign_dir=$(cd "$(dirname "$0")" && pwd)
repo_root=$(cd "$campaign_dir/../../.." && pwd)
python_bin=/data/slanggraph-eval-upstreams/ai-data-science-team/.venv/bin/python

cd "$repo_root"
"$python_bin" eval/apps/demos/summarize.py "$campaign_dir"
python3 -m json.tool "$campaign_dir/tasks.json" >/dev/null
python3 -m json.tool "$campaign_dir/statistics.json" >/dev/null
test "$(wc -l < "$campaign_dir/raw/preflight.jsonl")" -eq 25

if test -f "$campaign_dir/SHA256SUMS"; then
  (
    cd "$campaign_dir"
    sha256sum -c SHA256SUMS >/dev/null
  )
fi

echo "Regenerated RESULTS.md, statistics.json, and raw/preflight.jsonl"
