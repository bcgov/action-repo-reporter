# Multi-Repo Security Assessments (action-repo-reporter)

Central dashboard for automated **security assessments** across Forest Digital
Services (FDS) public repositories.

The monthly (or dispatch) pipeline clones each target, runs deterministic scanners
and GitHub security-alert collection, then **scripts** compile `findings.json` and
render the Markdown report (`scripts/compile-findings.py`, `scripts/render-report.py`).
An optional cover-letter digest may be added afterward; it cannot invent findings.
Reports land in this repo under `reports/<repo>/` via a single pull request.

## What you get and where

| Output | Path |
|---|---|
| Findings (JSON) | `reports/<repo>/findings.json` |
| Bounded risk score | `reports/<repo>/score.json` (`0–100`, diminishing returns on Medium/Low) |
| Human report | `reports/<repo>/security-assessment.md` |

**How to read severity:** Critical / High / Medium / Low. Scores use a bounded 0–100 scale (`min(100, 25*C + min(40, 8*H) + min(15, round(4*ln(1+M))) + min(5, round(0.2*L)))`) so a few minor items do not inflate well-maintained repos into 100s — always read the findings table.

**Why scanners sometimes look empty**

| Source | Empty `[]` / `{}` usually means |
|---|---|
| Dependabot / code-scanning / secret-scanning | No open alerts **or** the workflow token cannot read cross-repo alerts. Cross-repo reads need repo secret `SECURITY_ALERTS_TOKEN` with `security-events: read` on each target. Without it, the default `GITHUB_TOKEN` only sees alerts for *this* repo. |
| Semgrep | Install/network failure (see workflow log / `evidence/NOTES.txt`). Usable clean scans have `results: []` and nonempty `paths.scanned`. |
| Gitleaks | No secrets found (`[]`) or tool missing. |
| Trivy / OSV | Tool missing, or a large JSON the compile script triages into dependency findings. |

Publish path: `generate-reports.yml` → download `*security-assessment` artifacts →
organize into `reports/<repo>/` →
`peter-evans/create-pull-request` on branch `chore/security-reports`.
A run that only writes files on the runner (or calls `noop` without that PR) is a
**failure** — artifacts alone are not a publish.

## How to run

**User-facing entrypoint:** Actions → **Multi-Repo Security Assessments**
(`generate-reports.yml`).

- **Schedule:** 1st of each month 14:00 UTC — all five targets.
- **workflow_dispatch:** same full set by default.
  - Optional input `repos`: comma-separated `owner/name` or bare names
    (e.g. `nr-fom,pubcode` or `bcgov/nr-fom`). Empty = all five:
    `bcgov/nr-fom`, `bcgov/nr-hydrometric-rating-curve`, `bcgov/nr-results-exam`,
    `bcgov/nr-seedtransfer-map`, `bcgov/pubcode`.

The reusable assessor (`.github/workflows/security-assessment.yml`) is
`workflow_call` only — do not dispatch it directly. Findings JSON and chapter
markdown are authored by scripts, not Copilot.

## Active security reports

After the first successful publish PR merges, browse:

* `reports/nr-fom/`
* `reports/nr-hydrometric-rating-curve/`
* `reports/nr-results-exam/`
* `reports/nr-seedtransfer-map/`
* `reports/pubcode/`

## Technical architecture

1. **Orchestrator:** [generate-reports.yml](.github/workflows/generate-reports.yml)
   selects targets, fans out, then `commit-reports` publishes one PR.
2. **Per target:** [security-assessment.yml](.github/workflows/security-assessment.yml)
   installs scanners, runs [scripts/security-evidence.sh](scripts/security-evidence.sh),
   scripts compile `reports/findings.json` + `reports/security-assessment.md`,
   [scripts/score.py](scripts/score.py) validates cites and scores.
3. **Secrets:** optional `SECURITY_ALERTS_TOKEN` for cross-repo alert APIs.

## How to add repositories

1. Add the `owner/name` slug to the `ALL` array in
   [generate-reports.yml](.github/workflows/generate-reports.yml) (`select-targets` job).
2. Ensure `SECURITY_ALERTS_TOKEN` (if used) can read security alerts on that repo.
3. Commit and merge. Next schedule/dispatch includes it when `repos` is empty.

## Honest bar

This pipeline produces consistent, citable findings with per-finding impact and
recommendation, chapter write-ups even when a scan is clean, and honest coverage
gaps (including when GitHub's own alert list was not read due to token scope). It
does **not** write a long EY consulting narrative and is **not** a full
runtime penetration test. Green CI / schema pass is not EY quality.

GitHub-alert collection reads `dependabot`, `code-scanning` (including DAST URL
alerts from `bcgov/actions/scan-url` such as OWASP ZAP and Nuclei), and
`secret-scanning` alert lists when `SECURITY_ALERTS_TOKEN` has access,
deduplicating them against the public scans (`semgrep`, `gitleaks`,
`osv-scanner`, `trivy`, and semantic domain analyzers).
