# Cover letter: bcgov/nr-hydrometric-rating-curve

This digest summarizes the scripted security assessment for `bcgov/nr-hydrometric-rating-curve`. The source of truth is the compiled report at [security-assessment.md](security-assessment.md).

Open findings: 31 (Critical 0, High 3, Medium 20, Low 8); confirmed-fixed: 0. Chapters analyzed: 16; not_assessed: 1.

Highest-priority items (by severity order in findings.json):
- CICD-001 (High): Using variable interpolation `${{...}}` with `github` context data in a `run:` step could allow an attacker to inject their own code into the runner. This would
- INFRA-002 (High): Root file system is not read-only
- INFRA-009 (High): Root file system is not read-only
- CICD-002 (Medium): GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks —
- CICD-003 (Medium): GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks —

Named coverage gaps:
- GitHub's own alert list was not read (dependabot: HTTP 403 or unavailable). Public scanner proxy used instead.
- GitHub's own alert list was not read (code-scanning: HTTP 403 or unavailable). Public scanner proxy used instead.
- GitHub's own alert list was not read (secret-scanning: HTTP 403 or unavailable). Public scanner proxy used instead.

See chapters `architecture`, `cicd`, `zero-trust`, `authn` in the full report for tool versions and counts.

This cover letter does not add findings. Green CI / schema pass is not EY consulting quality; read the scripted chapters and per-finding impact/recommendation fields.
