# Cover letter: bcgov/pubcode

This digest summarizes the scripted security assessment for `bcgov/pubcode`. The source of truth is the compiled report at [security-assessment.md](security-assessment.md).

Open findings: 35 (Critical 0, High 2, Medium 20, Low 13); confirmed-fixed: 0. Chapters analyzed: 17; not_assessed: 0.

Highest-priority items (by severity order in findings.json):
- AUTHZ-001 (High): Unauthenticated mutating route in Express (POST /bulk-load)
- AUTHZ-002 (High): Unauthenticated mutating route in Express (DELETE /:repo_name)
- DEPS-001 (Medium): minimatch 10.2.6 affected by GHSA-g3hv-75wg-m249
- DEPS-002 (Medium): minimatch 10.2.6 affected by GHSA-g3hv-75wg-m249
- DEPS-003 (Medium): minimatch 10.2.6 affected by GHSA-g3hv-75wg-m249

Named coverage gaps:
- GitHub's own alert list was not read (dependabot: HTTP 403 or unavailable). Public scanner proxy used instead.
- GitHub's own alert list was not read (code-scanning: HTTP 403 or unavailable). Public scanner proxy used instead.
- GitHub's own alert list was not read (secret-scanning: HTTP 403 or unavailable). Public scanner proxy used instead.

See chapters `architecture`, `cicd`, `zero-trust`, `authn` in the full report for tool versions and counts.

This cover letter does not add findings. Green CI / schema pass is not EY consulting quality; read the scripted chapters and per-finding impact/recommendation fields.
