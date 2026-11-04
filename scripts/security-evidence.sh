#!/usr/bin/env bash
# Collect security evidence for one repo using the caller's own gh auth (no GitHub App).
# Usage: security-evidence.sh owner/repo [outdir]   (clones to ./target if missing)
set -uo pipefail
REPO="$1"; OUT="${2:-evidence}"; mkdir -p "$OUT"
[ -d target ] || gh repo clone "$REPO" target -- --depth 1 || exit 1

api() { # name endpoint ; failures (403/404) -> empty list + note
  if ! gh api --paginate "$2" > "$OUT/$1.json" 2> "$OUT/$1.err"; then
    echo '[]' > "$OUT/$1.json"; echo "WARN: $1 unavailable: $(head -c 200 "$OUT/$1.err")" >&2
  fi; rm -f "$OUT/$1.err"
}
api dependabot     "repos/$REPO/dependabot/alerts?state=open&per_page=100"
api code-scanning  "repos/$REPO/code-scanning/alerts?state=open&per_page=100"
api secret-scanning-raw "repos/$REPO/secret-scanning/alerts?state=open&per_page=100"
# Redact plaintext secrets before any agent sees them.
jq '[ .[]? | del(.secret) | .secret = "REDACTED" ]' "$OUT/secret-scanning-raw.json" > "$OUT/secret-scanning.json" \
  && rm -f "$OUT/secret-scanning-raw.json"

run() { command -v "$1" >/dev/null || { echo "WARN: $1 not installed" >&2; echo '{}' > "$OUT/$1.json"; return; }; shift; "$@" || true; }
run semgrep  semgrep scan --config auto --json -o "$OUT/semgrep.json" target
run gitleaks gitleaks detect -s target --redact --report-format json --report-path "$OUT/gitleaks.json" --no-banner
run osv-scanner sh -c "osv-scanner --format json -r target > '$OUT/osv-scanner.json'"
run trivy    trivy fs --scanners vuln,misconfig --format json -o "$OUT/trivy.json" target
echo "Evidence in $OUT/"; ls -la "$OUT"
