# Rapid Security Assessment: bcgov/nr-fom

Commit: a20cfc4350cd94a90bbe017090641ea176bb01fe

## Executive summary

11 open findings (0 Critical, 3 High, 2 Medium, 6 Low); AUTH-001 and CRYPTO-001 seeds confirmed fixed. Score is written by score.py.

## Scope table

| Chapter | Status | Findings |
|---|---|---|
| architecture | analyzed | 0 |
| cicd | analyzed | 3 |
| zero-trust | analyzed | 3 |
| authn | analyzed | 1 |
| authz | not_assessed | 0 |
| injection | analyzed | 2 |
| configuration | analyzed | 1 |
| cryptography | analyzed | 2 |
| secrets | analyzed | 1 |
| logging-data | analyzed | 1 |
| code-scanning | not_assessed | 0 |
| secret-scanning | not_assessed | 0 |
| dependabot | not_assessed | 0 |
| dependencies | analyzed | 4 |
| containers-iac | analyzed | 1 |
| testing | analyzed | 0 |
| stack | analyzed | 1 |

## Severity totals

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 3 |
| Medium | 2 |
| Low | 6 |

| Domain | Findings |
|---|---|
| CICD | 3 |
| INFRA | 1 |
| CONFIG | 1 |
| DATA | 1 |
| INJ | 1 |
| DEPS | 4 |

## OWASP Top 10 (2021)

| Category | Findings |
|---|---|
| A01 Broken Access Control | CICD-003, INFRA-001 |
| A04 Insecure Design | none |
| A05 Security Misconfiguration | CONFIG-001 |
| A06 Vulnerable Components | DEPS-001..004 |
| A08 Software and Data Integrity | CICD-002, INJ-001 |
| A09 Logging Failures | DATA-001 |
| A03 Injection | CICD-001 |
| A02/A07 | AUTH-001, CRYPTO-001 confirmed fixed |

## Component risk ranking

1. CI/CD workflows (.github/workflows)
2. Dependencies (root package-lock.json)
3. api (api/src)
4. OpenShift deployment manifests

## architecture

Status: analyzed

Monorepo with api, admin, public, db and libs components deployed through OpenShift manifests.

- README.md:5
- package.json:7

## cicd

Status: analyzed

Workflows use mutable action tags, inherit all secrets and interpolate inputs into shell scripts.

- CICD-001
- CICD-002
- CICD-003

## zero-trust

Status: analyzed

Mapped findings: secrets inherit and privilege escalation breach least privilege; dependency highs relate to assume breach.

- CICD-003
- INFRA-001
- DEPS-001

## authn

Status: analyzed

JWT verification pins RS256 and SECURITY_ENABLED defaults to true, so no algorithm confusion was found.

- AUTH-001
- api/src/core/security/auth.service.ts:115

## authz

Status: not_assessed

No manual review of route guards or RBAC was performed in this rapid pass.


## injection

Status: analyzed

Semgrep reported only a low-risk Object.assign pattern and workflow shell interpolation, no SQL injection hits.

- INJ-001
- CICD-001

## configuration

Status: analyzed

CORS wildcard exists only behind an env flag; helmet and ValidationPipe are configured in bootstrap.

- CONFIG-001
- api/src/main.ts:71

## cryptography

Status: analyzed

Encryption key fallback was removed and the service fails closed when the key is unset.

- CRYPTO-001
- AUTH-001

## secrets

Status: analyzed

Gitleaks output was empty and no hardcoded default encryption key was found in the service source.

- CRYPTO-001

## logging-data

Status: analyzed

Debug logging of decoded token claims and a console.log of the JWKS URI were identified.

- DATA-001

## code-scanning

Status: not_assessed

Code scanning alerts could not be read because the token lacked access (HTTP 403).


## secret-scanning

Status: not_assessed

Secret scanning alerts could not be read because the token lacked access (HTTP 403).


## dependabot

Status: not_assessed

Dependabot alerts could not be read because the token lacked access (HTTP 403).


## dependencies

Status: analyzed

OSV scanner and Trivy report high severity multer, joi and basic-ftp plus moderate vite advisories.

- DEPS-001
- DEPS-002
- DEPS-003
- DEPS-004

## containers-iac

Status: analyzed

OpenShift deployment manifests omit allowPrivilegeEscalation false though runAsNonRoot is set.

- INFRA-001

## testing

Status: analyzed

Playwright e2e specs and API unit tests exist, including auth service tests toggling SECURITY_ENABLED.

- e2e/admin-search.spec.ts:1
- api/src/core/security/auth.service.spec.ts:17

## stack

Status: analyzed

Node engine range is current and renovate is configured, though pinned dependencies carry advisories.

- DEPS-004
- package.json:7
- renovate.json:1

## Findings table

| ID | Severity | Title | Evidence |
|---|---|---|---|
| DEPS-001 | High | multer 2.4.0: DoS via aborted request (CVE-2026-113872) | package-lock.json:13972 |
| DEPS-002 | High | joi 18.3.0: DoS via inefficient regex (CVE-2026-118772) | package-lock.json:12912 |
| DEPS-003 | High | basic-ftp 5.3.1 high-severity advisory (likely transitive/dev) | package-lock.json:8668 |
| CICD-001 | Medium | Shell injection via ${{ inputs.* }} interpolation in deploy workflow | .github/workflows/.deploy.yml:84 |
| DEPS-004 | Medium | vite 8.3.0 with 6 moderate advisories (dev tooling) | package-lock.json:17583 |
| CICD-002 | Low | Third-party actions referenced by mutable tag instead of commit SHA | .github/workflows/analysis.yml:105 |
| CICD-003 | Low | Reusable workflows called with secrets: inherit | .github/workflows/pr-open.yml:67 |
| INFRA-001 | Low | OpenShift containers do not set allowPrivilegeEscalation: false | api/openshift.deploy.yml:164 |
| CONFIG-001 | Low | Wildcard CORS enabled via BYPASS_CORS env flag | api/src/main.ts:62 |
| DATA-001 | Low | Decoded JWT contents and JWKS URI written to logs | api/src/core/security/auth.service.ts:151 |
| INJ-001 | Low | Object.assign of parsed JSON into User object | libs/utility/src/security/user.ts:22 |

## Confirmed-fixed table

| ID | Evidence | Note |
|---|---|---|
| AUTH-001 | api/src/core/security/auth.service.ts:159 | ID token verify pinned to RS256 (access token verify also pinned at line 173). |
| CRYPTO-001 | api/src/app/modules/public-comment/public-comment.service.ts:42 | No default key; constructor fails closed when key unset. |

## Questions and coverage gaps

- Question (AUTHZ): Are all write endpoints protected by role guards? Not reviewed in this pass.
- Gap: Dependabot, code scanning and secret scanning alerts unavailable: HTTP 403 token cannot read cross-repo alerts.
- Gap: gitleaks.json empty: treated as a clean scan.
- Gap: osv-scanner exited non-zero; output kept.
- Gap: AUTHZ not manually reviewed.
