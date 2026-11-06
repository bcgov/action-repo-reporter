#!/usr/bin/env bash
# A clean scan has results=[] AND scanned paths; {} is never scan evidence.
# Usage: run-semgrep.sh outdir target [config] (config defaults to registry auto)
set -euo pipefail
out="$1"; target="$2"; config="${3:-auto}"
mkdir -p "$out"
rm -f "$out/semgrep.json" "$out/semgrep.json.tmp"
if ! command -v semgrep >/dev/null 2>&1; then
  echo "::error::Semgrep runtime unavailable: semgrep is not installed/on PATH" >&2
  exit 1
fi
if semgrep scan --config "$config" --metrics off --json -o "$out/semgrep.json.tmp" "$target" \
    2> >(tee "$out/semgrep.err" >&2); then
  :
else
  rc=$?
  echo "::error::Semgrep runtime/scan failed (exit $rc); see traceback/error above and $out/semgrep.err" >&2
  rm -f "$out/semgrep.json.tmp"
  exit "$rc"
fi
if ! jq -e 'type == "object" and (.results | type == "array") and
    (.paths.scanned | type == "array" and length > 0)' "$out/semgrep.json.tmp" >/dev/null; then
  echo "::error::Semgrep produced invalid/unusable evidence: expected results array and nonempty paths.scanned; see $out/semgrep.err" >&2
  rm -f "$out/semgrep.json.tmp"
  exit 1
fi
mv "$out/semgrep.json.tmp" "$out/semgrep.json"
