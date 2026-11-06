#!/usr/bin/env bash
# Collect security evidence for one repo using the caller's gh auth (no GitHub App).
# Usage: security-evidence.sh owner/repo [outdir] [ref]
#   ref (optional): commit SHA, branch, or tag. Empty = tip (depth-1 clone).
#   When set, clones then checks out that ref so ./target HEAD is the prove commit.
#
# Cross-repo Dependabot / code-scanning / secret-scanning require GH_TOKEN (or
# SECURITY_ALERTS_TOKEN exported as GH_TOKEN) with security-events:read on the
# target. The default GITHUB_TOKEN can only read alerts for the caller repo.
set -uo pipefail
REPO="$1"; OUT="${2:-evidence}"; REF="${3:-}"; mkdir -p "$OUT"

note() { printf '%s\n' "$*" | tee -a "$OUT/NOTES.txt" >&2; }

if [ -d target ]; then
  # Reuse only if target/ is the requested repo (and ref, when given); otherwise reject.
  url="$(git -C target remote get-url origin 2>/dev/null || true)"
  case "$url" in
    *"github.com/$REPO"|*"github.com/$REPO.git"|*"github.com:$REPO"|*"github.com:$REPO.git") ;;
    *) echo "ERROR: existing target/ origin '$url' != $REPO; remove target/ and retry" >&2; exit 1 ;;
  esac
  if [ -n "$REF" ]; then
    git -C target fetch --depth 1 origin "$REF" || exit 1
    git -C target checkout --detach FETCH_HEAD || exit 1
  fi
else
  if [ -n "$REF" ]; then
    # Enough history for a specific SHA/branch/tag — depth-1 tip alone cannot reach old SHAs.
    gh repo clone "$REPO" target -- --no-checkout || exit 1
    git -C target fetch --depth 1 origin "$REF" || exit 1
    git -C target checkout --detach FETCH_HEAD || exit 1
  else
    gh repo clone "$REPO" target -- --depth 1 || exit 1
  fi
fi
echo "target HEAD: $(git -C target rev-parse HEAD) (wanted: ${REF:-tip})"

# Record whether SECURITY_ALERTS_TOKEN-style access is in play (never print the token).
caller_repo="${GITHUB_REPOSITORY:-}"
if [ -n "${GH_TOKEN:-}" ] && [ "$REPO" != "$caller_repo" ]; then
  note "INFO: collecting cross-repo alerts for $REPO (caller=$caller_repo). Empty [] may mean no open alerts OR missing security-events:read on the token."
else
  note "INFO: using default token scope for $REPO. Cross-repo alerts need SECURITY_ALERTS_TOKEN."
fi

api() { # name endpoint ; failures (403/404) -> empty list + note
  # --paginate emits one JSON array per page; --slurp + add merges them into a single array.
  # pipefail makes a gh failure fail the whole pipeline.
  if ! gh api --paginate "$2" 2> "$OUT/$1.err" | jq -s 'add // []' > "$OUT/$1.json"; then
    echo '[]' > "$OUT/$1.json"
    note "WARN: $1 unavailable: $(head -c 200 "$OUT/$1.err" 2>/dev/null || true)"
  else
    count="$(jq 'length' "$OUT/$1.json" 2>/dev/null || echo 0)"
    note "INFO: $1 → $count item(s)"
  fi
  rm -f "$OUT/$1.err"
}
api dependabot     "repos/$REPO/dependabot/alerts?state=open&per_page=100"
api code-scanning  "repos/$REPO/code-scanning/alerts?state=open&per_page=100"
api secret-scanning-raw "repos/$REPO/secret-scanning/alerts?state=open&per_page=100"
# Redact plaintext secrets before any agent sees them.
# Fail closed: raw file is always removed; on any jq error no partial output is kept and we exit.
if ! jq -e '[ .[] | del(.secret) | .secret = "REDACTED" ]' "$OUT/secret-scanning-raw.json" > "$OUT/secret-scanning.json.tmp"; then
  rm -f "$OUT/secret-scanning-raw.json" "$OUT/secret-scanning.json.tmp" "$OUT/secret-scanning.json"
  echo "ERROR: secret-scanning redaction failed; aborting" >&2; exit 1
fi
rm -f "$OUT/secret-scanning-raw.json"; mv "$OUT/secret-scanning.json.tmp" "$OUT/secret-scanning.json"

# Always leave a JSON file for each scanner so the agent can tell "missing" from "empty".
ensure() { [ -s "$1" ] || echo "$2" > "$1"; }

run() {
  local name="$1"; shift
  if ! command -v "$name" >/dev/null 2>&1; then
    note "WARN: $name not installed"
    echo '{}' > "$OUT/$name.json"
    return 0
  fi
  if ! "$@"; then
    note "WARN: $name exited non-zero (output kept if present)"
  fi
  ensure "$OUT/$name.json" '{}'
}

export PATH="${HOME}/.local/bin:${PATH}"
run semgrep  semgrep scan --config auto --json -o "$OUT/semgrep.json" target
# gitleaks exits 1 when secrets are found — treat that as success with a report.
if command -v gitleaks >/dev/null 2>&1; then
  gitleaks detect -s target --redact --report-format json --report-path "$OUT/gitleaks.json" --no-banner
  rc=$?
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 1 ]; then
    note "WARN: gitleaks failed rc=$rc"
  fi
  ensure "$OUT/gitleaks.json" '[]'
else
  note "WARN: gitleaks not installed"
  echo '[]' > "$OUT/gitleaks.json"
fi
run osv-scanner sh -c "osv-scanner --format json -r target > '$OUT/osv-scanner.json'"
run trivy    trivy fs --scanners vuln,misconfig --format json -o "$OUT/trivy.json" target

# Summarize sizes so CI logs show whether scanners produced real evidence.
note "Evidence in $OUT/:"
ls -la "$OUT" | tee -a "$OUT/NOTES.txt" >&2
for f in dependabot.json code-scanning.json secret-scanning.json semgrep.json gitleaks.json osv-scanner.json trivy.json; do
  ensure "$OUT/$f" '{}'
  note "  $f $(wc -c < "$OUT/$f") bytes"
done
