# Cover letter: bcgov/pubcode

This digest summarizes the scripted security assessment for `bcgov/pubcode`. The source of truth is the compiled report at [security-assessment.md](security-assessment.md).

Open findings: 80 (Critical 0, High 5, Medium 62, Low 13); confirmed-fixed: 0. Chapters analyzed: 17; not_assessed: 0.

Highest-priority items (by severity order in findings.json):
- AUTHZ-001 (High): Unauthenticated mutating route in Express (POST /bulk-load)
- AUTHZ-002 (High): Unauthenticated mutating route in Express (DELETE /:repo_name)
- CICD-016 (High): This workflow uses `secrets: inherit` to pass all of the calling workflow's secrets to a reusable workflow. This violates the principle of least privilege becau
- CICD-017 (High): This workflow uses `secrets: inherit` to pass all of the calling workflow's secrets to a reusable workflow. This violates the principle of least privilege becau
- CICD-019 (High): This workflow uses `secrets: inherit` to pass all of the calling workflow's secrets to a reusable workflow. This violates the principle of least privilege becau

Named coverage gaps:
- GitHub's own alert list was not read (dependabot: HTTP 403 or unavailable). Public scanner proxy used instead.
- GitHub's own alert list was not read (code-scanning: HTTP 403 or unavailable). Public scanner proxy used instead.
- GitHub's own alert list was not read (secret-scanning: HTTP 403 or unavailable). Public scanner proxy used instead.

See chapters `architecture`, `cicd`, `zero-trust`, `authn` in the full report for tool versions and counts.

This cover letter does not add findings. Green CI / schema pass is not EY consulting quality; read the scripted chapters and per-finding impact/recommendation fields.
