#!/usr/bin/env bash
set -euo pipefail

ace_source=${ACE_SOURCE:-/tmp/ace-llm-source}
isolategpt_source=${ISOLATEGPT_SOURCE:-/tmp/secgpt-source}
ace_python=${ACE_PYTHON:-/tmp/ace-eval-venv/bin/python}
isolategpt_python=${ISOLATEGPT_PYTHON:-/tmp/secgpt-eval-venv/bin/python}

if test ! -d "$ace_source/.git"; then
  git clone https://github.com/escottrose01/ace-llm "$ace_source"
fi
git -C "$ace_source" checkout --detach e88f6dc16e5404131fbefe5684c7f05f856edbdd

if test ! -d "$isolategpt_source/.git"; then
  git clone https://github.com/llm-platform-security/SecGPT "$isolategpt_source"
fi
git -C "$isolategpt_source" checkout --detach c6020f977d20f9f80776cae5d4e2930455733ce5

uv venv "$(dirname "$ace_python")" --python 3.13
uv pip install --python "$ace_python" \
  astor==0.8.1 docker==7.2.0 pydantic==2.14.1
uv venv "$(dirname "$isolategpt_python")" --python 3.13
uv pip install --python "$isolategpt_python" \
  pyseccomp==0.1.2 tldextract==5.4.0

docker build -t tool-runner-image \
  -f "$ace_source/src/ace/execute/Dockerfile.tool" \
  "$ace_source/src/ace/execute"
