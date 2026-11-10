# Cover letter: bcgov/nr-results-exam

This digest summarizes the scripted security assessment for `bcgov/nr-results-exam`. The source of truth is the compiled report at [security-assessment.md](security-assessment.md).

Open findings: 27 (Critical 0, High 2, Medium 11, Low 14); confirmed-fixed: 0. Chapters analyzed: 17; not_assessed: 0.

Highest-priority items (by severity order in findings.json):
- DATA-001 (High): Potential credential or authorization token disclosure in logger call (Token)
- INJ-011 (High): Detected calls to child_process from a function argument `cmd`. This could lead to a command injection if the input is user controllable. Try to avoid calls to 
- DEPS-002 (Medium): minimatch 10.2.6 affected by GHSA-g3hv-75wg-m249
- DEPS-003 (Medium): stream-json 1.9.1 affected by GHSA-528h-pc64-c93x
- DEPS-004 (Medium): stream-json 1.9.1 affected by GHSA-hqr4-qq8f-hg3x

Named coverage gaps:
- GitHub's own alert list was not read (dependabot: HTTP 403 or unavailable). Public scanner proxy used instead.
- GitHub's own alert list was not read (code-scanning: HTTP 403 or unavailable). Public scanner proxy used instead.
- GitHub's own alert list was not read (secret-scanning: HTTP 403 or unavailable). Public scanner proxy used instead.

See chapters `architecture`, `cicd`, `zero-trust`, `authn` in the full report for tool versions and counts.

This cover letter does not add findings. Green CI / schema pass is not EY consulting quality; read the scripted chapters and per-finding impact/recommendation fields.
