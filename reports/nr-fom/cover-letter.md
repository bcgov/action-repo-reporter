# Cover letter: bcgov/nr-fom

This digest summarizes the scripted security assessment for `bcgov/nr-fom`. The source of truth is the compiled report at [security-assessment.md](security-assessment.md).

Open findings: 19 (Critical 0, High 1, Medium 14, Low 4); confirmed-fixed: 2. Chapters analyzed: 17; not_assessed: 0.

Highest-priority items (by severity order in findings.json):
- CICD-001 (High): Using variable interpolation `${{...}}` with `github` context data in a `run:` step could allow an attacker to inject their own code into the runner. This would
- CONFIG-001 (Medium): Access-Control-Allow-Origin response header is set to "*". This will disable CORS Same Origin Policy restrictions.
- CRYPTO-002 (Medium): Detected possible user input going into a `path.join` or `path.resolve` function. This could possibly lead to a path traversal vulnerability,  where the attacke
- DEPS-005 (Medium): minimatch 10.2.6 affected by GHSA-g3hv-75wg-m249
- DEPS-006 (Medium): minimatch 9.0.9 affected by GHSA-g3hv-75wg-m249

Confirmed-fixed seeds/checks: AUTH-001, CRYPTO-001.

Named coverage gaps:
- GitHub's own alert list was not read (dependabot: HTTP 403 or unavailable). Public scanner proxy used instead.
- GitHub's own alert list was not read (code-scanning: HTTP 403 or unavailable). Public scanner proxy used instead.
- GitHub's own alert list was not read (secret-scanning: HTTP 403 or unavailable). Public scanner proxy used instead.

See chapters `architecture`, `cicd`, `zero-trust`, `authn` in the full report for tool versions and counts.

This cover letter does not add findings. Green CI / schema pass is not EY consulting quality; read the scripted chapters and per-finding impact/recommendation fields.
