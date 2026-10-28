# Technical Review — bcgov/actions

**Project:** bcgov/actions (shared composite GitHub Actions: builder, diff-triggers, ghcr-cleanup, image-tracker, pr-validate, scan-url, test-and-analyse, workflow-notifier, workflow-results)
**Date:** 2026-10-26
**Prepared by:** FDS Code Quality Auditor (Automated)
**Audience:** Director and above

---

## Executive Summary

bcgov/actions is a library of reusable CI/CD building blocks, not an application. It has no Spring Boot backend and no React frontend, so the FDS backend and frontend standards do not apply; the audit scanner confirms no `pom.xml`, no Lombok, no JPA, no OAuth2 resource server, no React Query, no auth context and no error boundary, which is expected for this repository. The only TypeScript is the `test-and-analyse` workspace. The review therefore concentrates on CI/CD integrity, which is the repository's whole purpose and where every downstream bcgov project inherits its risk.

The most significant finding is supply chain exposure. All 29 third-party action references in workflows and 13 in composite `action.yml` files use mutable version tags (`actions/checkout@v7`, `docker/build-push-action@v7`, `github/codeql-action/upload-sarif@v4`) rather than commit SHAs. Because these actions are consumed by other repositories, a compromised tag propagates to every consumer. Second, `builder/action.yml` pipes a script from the `main` branch of a third-party repository into a shell (`curl ... anchore/syft/main/install.sh | sh`), and several composite actions interpolate inputs directly into shell and CLI arguments.

Positive controls exist: no `secrets: inherit`, no workflow-level secret exports, `permissions: {}` at the top of every workflow with per-job grants, no hardcoded credentials, and no disabled TLS verification. The remaining findings are shell-hygiene and test-coverage debt.

---

## Security

### Unverified installer piped to shell from a moving branch

`builder/action.yml` (SBOM step) runs `curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin` with `set +e -u`. The script is fetched from the `main` branch with no checksum or version pin, and runs on the runner that holds registry push credentials. A change to that branch, or a compromise of it, executes arbitrary code in every consumer's image build. The step is `continue-on-error: true`, which hides a failed or tampered install. Pin the installer to a release tag and verify its checksum, or use a SHA-pinned `anchore/sbom-action`.

### Inputs interpolated directly into shell and scanner arguments

`scan-url/action.yml` passes `args: -u ${{ inputs.url }} -jsonl-export ...` to the Nuclei step and `target: ${{ inputs.url }}` to ZAP, while the preceding reachability step correctly uses an `env:` variable. `builder/action.yml` builds `IMAGE="${{ steps.vars.outputs.registry }}/${{ steps.vars.outputs.image_path }}@${{ ... digest }}"` and `PACKAGE_SANITIZED=$(echo "${{ steps.vars.outputs.publish_package }}" ...)` inside `run:`. `.github/workflows/test.yml` lines 117 and 1208 interpolate `github.event_name`, `github.event.pull_request.head.repo.full_name` and `matrix.name` in `run:` blocks; `test.yml` line 114 also expands `toJSON(steps.build.outputs)` into an `echo`. The event-name and repository values are GitHub-controlled and low risk today, but the pattern bypasses the repository's own convention and the builder values derive from caller inputs. Assign each value to a step `env:` variable and reference it as `"$VAR"`.

---

## Frontend

The repository has no frontend application. The only TypeScript is the `test-and-analyse` Node workspace (ESLint 10, Vitest, ncc). No `localStorage`/`sessionStorage` use, no `CI=false`, and no file-level `eslint-disable` or `@ts-ignore` directives were found. The scanner flags `process.env.NODE_ENV` use; this is correct for a Node action and not a finding. No remediation required.

---

## Backend

The repository has no Java backend. FDS backend criteria (Spring Boot parent, JPA, Lombok, `@Transactional`, JWT resource server) are not applicable, and no finding is raised.

---

## CI/CD Pipelines

### Third-party actions pinned to mutable tags

The scanner found 25 mutable-tag references in the three workflows (20 `actions/checkout@v7`, 7 `actions/setup-node@v7` across `pr-validate.yml`, `release.yml` and `test.yml`, which is 1,403 lines). Verification of all `uses:` lines, including composite actions, also shows `github/codeql-action/upload-sarif@v4` (2), `docker/setup-buildx-action@v4`, `docker/metadata-action@v6`, `docker/login-action@v4`, `docker/build-push-action@v7`, `actions/upload-artifact@v7`, `actions/setup-python@v7`, `actions/setup-java@v6` and `actions/attest-build-provenance@v4`. The Docker and attestation actions run with registry write and `id-token` permissions inside `builder`, the highest-value target in the repository. Pin every reference to a full commit SHA with a version comment and let Renovate (already configured via `renovate.json`) maintain the pins.

### Shell scripts missing strict mode

`builder/context.sh` and `pr-validate/fork-notice.sh` have no `set -euo pipefail`. Both are sourced libraries (181 and 8 lines), so strict mode belongs in the sourcing script, but neither documents that, and the builder SBOM step runs with `set +e -u`, disabling error exit explicitly. The other 15 scripts (2,742 total shell lines in 17 files) were checked and set strict mode. Confirm that every sourcing caller sets it, and replace `set +e` in the SBOM step with explicit handling of the one command expected to fail.

### Release-tracing API calls rely on unvalidated responses

`test.yml` around lines 704 to 726 calls the GitHub registry API with `curl -sS` and extracts fields from the returned body (`resp`, `body`, `rev`, `bearer`) without `-f` and without checking HTTP status or JSON structure before use. A rate-limited or error response is parsed as data. Add `--fail-with-body` and a `jq -e` structure check before each extraction. Credentials here are passed as headers or `-u`, not as URL parameters, which is compliant.

---

## Testing and Observability

### Coverage is concentrated in shell tests; TypeScript coverage is thin

Seven test files exist outside `node_modules`. Most coverage is bash (`test-and-analyse/tests/unit.sh` at 518 lines, `workflow-notifier/tests/unit.sh` at 724 lines), executed through the 1,403-line `test.yml`. Several actions (`diff-triggers`, `ghcr-cleanup`, `workflow-results`) have no unit tests in the listing reviewed. No evidence of lowered coverage thresholds was found. Add tests for the untested actions and keep `test.yml` split by action to reduce its size and review burden.

---

## Summary

| Area | Finding | Severity |
|------|---------|----------|
| CI/CD | 38 third-party action references on mutable tags, including build, push and attestation actions | High |
| Security | Syft installer piped from `main` branch to shell, failure masked by `continue-on-error` | High |
| Security | Inputs and step outputs interpolated directly into `run:` and scanner arguments (`scan-url`, `builder`, `test.yml`) | Medium |
| CI/CD | `builder/context.sh` and `pr-validate/fork-notice.sh` lack strict mode; SBOM step uses `set +e` | Low |
| CI/CD | Registry API responses in `test.yml` not validated before parsing | Medium |
| Testing | Several actions without unit tests; `test.yml` at 1,403 lines | Low |
| Backend / Frontend | Not applicable to this repository | Low |

---

## Recommended Next Steps

1. Pin all `uses:` references in workflows and composite actions to commit SHAs, starting with the `docker/*` and `attest-build-provenance` actions in `builder`, to close the supply chain finding.
2. Replace the `curl | sh` Syft install with a tagged, checksum-verified install or a SHA-pinned action, and remove `continue-on-error` masking.
3. Move every `${{ }}` expression in `run:` blocks and in Nuclei/ZAP arguments into step `env:` variables, to remove the injection pattern.
4. Add `--fail-with-body` and `jq -e` validation to the registry API calls in `test.yml`.
5. Document or add strict mode in the sourcing scripts for `context.sh` and `fork-notice.sh`.
6. Add unit tests for untested actions and split `test.yml` to make changes reviewable.
