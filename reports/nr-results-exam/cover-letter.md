# Cover letter: bcgov/nr-results-exam

This digest summarizes the scripted security assessment for `bcgov/nr-results-exam`. The source of truth is the compiled report at [security-assessment.md](security-assessment.md).

Open findings: 56 (Critical 0, High 2, Medium 40, Low 14); confirmed-fixed: 0. Chapters analyzed: 17; not_assessed: 0.

Highest-priority items (by severity order in findings.json):
- DATA-007 (High): Potential credential or authorization token disclosure in logger call (Token)
- INJ-011 (High): Detected calls to child_process from a function argument `cmd`. This could lead to a command injection if the input is user controllable. Try to avoid calls to 
- CICD-001 (Medium): GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks —
- CICD-002 (Medium): GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks —
- CICD-003 (Medium): GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks —

Named coverage gaps:
- GitHub's own alert list was not read (dependabot: HTTP 403 or unavailable). Public scanner proxy used instead.
- GitHub's own alert list was not read (code-scanning: HTTP 403 or unavailable). Public scanner proxy used instead.
- GitHub's own alert list was not read (secret-scanning: HTTP 403 or unavailable). Public scanner proxy used instead.

See chapters `architecture`, `cicd`, `zero-trust`, `authn` in the full report for tool versions and counts.

This cover letter does not add findings. Green CI / schema pass is not EY consulting quality; read the scripted chapters and per-finding impact/recommendation fields.
