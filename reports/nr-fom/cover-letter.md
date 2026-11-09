# Cover letter: bcgov/nr-fom

This digest summarizes the scripted security assessment for `bcgov/nr-fom`. The source of truth is the compiled report at [security-assessment.md](security-assessment.md).

Open findings: 40 (Critical 0, High 5, Medium 34, Low 1); confirmed-fixed: 2. Chapters analyzed: 17; not_assessed: 0.

Highest-priority items (by severity order in findings.json):
- CICD-001 (High): Using variable interpolation `${{...}}` with `github` context data in a `run:` step could allow an attacker to inject their own code into the runner. This would
- CICD-010 (High): This workflow uses `secrets: inherit` to pass all of the calling workflow's secrets to a reusable workflow. This violates the principle of least privilege becau
- CICD-012 (High): This workflow uses `secrets: inherit` to pass all of the calling workflow's secrets to a reusable workflow. This violates the principle of least privilege becau
- CICD-014 (High): This workflow uses `secrets: inherit` to pass all of the calling workflow's secrets to a reusable workflow. This violates the principle of least privilege becau
- DEPS-001 (High): basic-ftp 5.3.1 affected by GHSA-c475-qrg2-pj4r

Confirmed-fixed seeds/checks: AUTH-001, CRYPTO-001.

Named coverage gaps:
- GitHub's own alert list was not read (dependabot: HTTP 403 or unavailable). Public scanner proxy used instead.
- GitHub's own alert list was not read (code-scanning: HTTP 403 or unavailable). Public scanner proxy used instead.
- GitHub's own alert list was not read (secret-scanning: HTTP 403 or unavailable). Public scanner proxy used instead.

See chapters `architecture`, `cicd`, `zero-trust`, `authn` in the full report for tool versions and counts.

This cover letter does not add findings. Green CI / schema pass is not EY consulting quality; read the scripted chapters and per-finding impact/recommendation fields.
