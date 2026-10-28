#!/usr/bin/env bash
set -euo pipefail

campaign_dir=$(cd "$(dirname "$0")" && pwd)
repo_root=$(cd "$campaign_dir/../../.." && pwd)
python_bin="$repo_root/libs/prebuilt/.venv/bin/python"
raw_dir="$campaign_dir/raw"

test ! -e "$raw_dir" || {
  echo "Refusing to overwrite $raw_dir" >&2
  exit 1
}

cd "$repo_root"
"$python_bin" eval/apps/pandas/closed_campaign.py \
  --output "$raw_dir" --repetitions 5 --configuration matched
"$python_bin" eval/apps/pandas/analyze_matched.py \
  --raw "$raw_dir" --output "$campaign_dir"
"$python_bin" eval/apps/pandas/validate_matched.py \
  "$raw_dir" --output "$campaign_dir/validation.json"

(
  cd "$campaign_dir"
  find . -type f -not -name SHA256SUMS -print0 \
    | sort -z | xargs -0 sha256sum > SHA256SUMS
)
