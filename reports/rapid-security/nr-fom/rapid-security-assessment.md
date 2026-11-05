> Path-proof seed from Actions run 42096113013 artifacts (pre-publish-fix). Replace on next Multi-Repo Rapid Security Assessments publish.

# Rapid Security Assessment: bcgov/nr-fom

Commit `02d2cfc5fe6d60da7971bffa79b4569475495e39`

## Summary
Both seed issues (AUTH-001 JWT alg pinning, CRYPTO-001 default key) are confirmed fixed. Open: 4 high-severity dependency advisories and a weak dev key in docker-compose.

## Findings
| ID | Severity | Title | Evidence |
|---|---|---|---|
| DEPS-001 | High | joi 18.3.0 affected by GHSA-4528-x5fx-h6hg | package-lock.json:12912 |
| DEPS-002 | High | multer 2.4.0 affected by GHSA-q7qp-rjg7-q26m | package-lock.json:13972 |
| DEPS-003 | High | vite 8.3.0 affected by GHSA-587h-7wmj-h5pm | package-lock.json:17583 |
| DEPS-004 | High | basic-ftp 5.3.1 affected by GHSA-c475-qrg2-pj4r | package-lock.json:8668 |
| CRYPTO-002 | Low | Guessable DATA_ENCRYPTION_KEY=defaultkey in docker-compose | docker-compose.yml:73 |

## Confirmed fixed
| ID | Cite | Note |
|---|---|---|
| AUTH-001 | api/src/core/security/auth.service.ts:160 | ID token verify pinned to RS256 |
| AUTH-001 | api/src/core/security/auth.service.ts:173 | Access token verify pinned to RS256 |
| CRYPTO-001 | api/src/app/modules/public-comment/public-comment.service.ts:42 | Fail-closed when key unset; no default fallback |

## Questions
None.

## Coverage gaps
- code-scanning, dependabot, secret-scanning, gitleaks evidence empty (unavailable); semgrep.json missing
- Manual review limited to seed items and dependency evidence; INJ, CONFIG, INFRA (workflows/Helm), DATA, API domains not exhaustively reviewed
- Trivy results not triaged in detail; 2 non-seed OSV moderate/low omitted
- Non-security stack currency not assessed
