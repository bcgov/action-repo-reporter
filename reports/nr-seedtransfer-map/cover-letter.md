# Cover letter: bcgov/nr-seedtransfer-map

This digest summarizes the scripted security assessment for `bcgov/nr-seedtransfer-map`. The source of truth is the compiled report at [security-assessment.md](security-assessment.md).

Open findings: 10 (Critical 0, High 0, Medium 9, Low 1); confirmed-fixed: 0. Chapters analyzed: 16; not_assessed: 1.

Highest-priority items (by severity order in findings.json):
- CRYPTO-001 (Medium): Detected possible user input going into a `path.join` or `path.resolve` function. This could possibly lead to a path traversal vulnerability,  where the attacke
- CRYPTO-002 (Medium): Detected possible user input going into a `path.join` or `path.resolve` function. This could possibly lead to a path traversal vulnerability,  where the attacke
- CRYPTO-003 (Medium): Detected possible user input going into a `path.join` or `path.resolve` function. This could possibly lead to a path traversal vulnerability,  where the attacke
- INJ-001 (Medium): This tag is missing an 'integrity' subresource integrity attribute. The 'integrity' attribute allows for the browser to verify that externally hosted files (for
- INJ-002 (Medium): This tag is missing an 'integrity' subresource integrity attribute. The 'integrity' attribute allows for the browser to verify that externally hosted files (for

Named coverage gaps:
- GitHub's own alert list was not read (dependabot: HTTP 403 or unavailable). Public scanner proxy used instead.
- GitHub's own alert list was not read (code-scanning: HTTP 403 or unavailable). Public scanner proxy used instead.
- GitHub's own alert list was not read (secret-scanning: HTTP 403 or unavailable). Public scanner proxy used instead.

See chapters `architecture`, `cicd`, `zero-trust`, `authn` in the full report for tool versions and counts.

This cover letter does not add findings. Green CI / schema pass is not EY consulting quality; read the scripted chapters and per-finding impact/recommendation fields.
