# Cover letter: bcgov/nr-hydrometric-rating-curve

This digest summarizes the scripted security assessment for `bcgov/nr-hydrometric-rating-curve`. The source of truth is the compiled report at [security-assessment.md](security-assessment.md).

Open findings: 24 (Critical 0, High 8, Medium 8, Low 8); confirmed-fixed: 0. Chapters analyzed: 17; not_assessed: 0.

Highest-priority items (by severity order in findings.json):
- AUTHZ-001 (High): Unprotected mutating Django view function: rctool_import
- AUTHZ-002 (High): Unprotected mutating Django view function: rctool_develop_initialize
- AUTHZ-003 (High): Unprotected mutating Django view function: rctool_develop_autofit
- AUTHZ-004 (High): Unprotected mutating Django view function: rctool_export_initialize
- AUTHZ-005 (High): Unprotected mutating Django view function: rctool_export_output

Named coverage gaps:
- GitHub's own alert list was not read (dependabot: HTTP 403 or unavailable). Public scanner proxy used instead.
- GitHub's own alert list was not read (code-scanning: HTTP 403 or unavailable). Public scanner proxy used instead.
- GitHub's own alert list was not read (secret-scanning: HTTP 403 or unavailable). Public scanner proxy used instead.

See chapters `architecture`, `cicd`, `zero-trust`, `authn` in the full report for tool versions and counts.

This cover letter does not add findings. Green CI / schema pass is not EY consulting quality; read the scripted chapters and per-finding impact/recommendation fields.
