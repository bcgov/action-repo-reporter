#!/usr/bin/env bash
# Use the Python supplied by gh-aw setup, never pipx's independent default Python.
set -euo pipefail
trap 'echo "::error::Semgrep install/runtime preflight failed (exit $?) at: $BASH_COMMAND; see error above" >&2' ERR
venv="${RUNNER_TEMP:?RUNNER_TEMP is required}/rsa-semgrep"
python3.12 -m venv "$venv"
"$venv/bin/python" -m pip install --disable-pip-version-check semgrep==1.95.0
"$venv/bin/semgrep" --version
# Prepend the isolated interpreter's scripts for subsequent Actions steps.
echo "$venv/bin" >> "${GITHUB_PATH:?GITHUB_PATH is required}"
