#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
vendor_dir="${root_dir}/vendor"
mkdir -p "${vendor_dir}"

clone_pin() {
  local name="$1"
  local url="$2"
  local commit="$3"
  if [[ ! -d "${vendor_dir}/${name}/.git" ]]; then
    git clone --filter=blob:none --no-checkout "${url}" "${vendor_dir}/${name}"
  fi
  git -C "${vendor_dir}/${name}" fetch --depth 1 origin "${commit}"
  git -C "${vendor_dir}/${name}" checkout --detach "${commit}"
  test "$(git -C "${vendor_dir}/${name}" rev-parse HEAD)" = "${commit}"
}

clone_pin progent https://github.com/sunblaze-ucb/progent.git 5be7b63fa96f70bc19b72fbcee81f1c0bcc1a565
clone_pin camel https://github.com/google-research/camel-prompt-injection.git f083b6b396399d3b3c7f2ddaf613a5945eaf32d8
clone_pin agentdojo https://github.com/ethz-spylab/agentdojo.git 089ed468cf3ed0322acc66b0211f26d9d90dbf60
clone_pin injecagent https://github.com/uiuc-kang-lab/InjecAgent.git f19c9f2c79a41046eb13c03c51a24c567a8ffa07
clone_pin adaptive-attack-agent https://github.com/uiuc-kang-lab/AdaptiveAttackAgent.git 7ea08cf4424e689079c6bc6348e28fbb84a090eb
clone_pin asb https://github.com/agiresearch/ASB.git 544540ff0788998072f7df463056fd17e62cc9f4
clone_pin aios https://github.com/agiresearch/AIOS.git 292d98f78c835499df18cdb6de6325bba1895862
