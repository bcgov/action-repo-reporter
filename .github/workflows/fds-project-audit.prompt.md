---
on:
  workflow_call:
    inputs:
      target_repository:
        required: true
        type: string
  workflow_dispatch:
    inputs:
      target_repository:
        required: true
        type: string

permissions:
  contents: read
  issues: read
  pull-requests: read
---
# FDS Full-Stack Project Audit

You are conducting a technical audit of the target repository: `{{ github.event.inputs.target_repository }}`. Your goal is to produce a director-level assessment report that covers security, reliability, maintainability, CI/CD pipeline integrity, and adherence to the established FDS stack standard. To navigate between files, make sure to load and use the `graphify` skill.

---

## Project to Audit

**Target Repository:** `{{ github.event.inputs.target_repository }}`
**Project Directory:** `./target_repo`

Use the tools available to you to explore this directory before writing anything. Read actual source files. Do not infer — verify.

---

## FDS Stack Standard

The established FDS standard, as demonstrated by `nr-waste-plus`, is:

**Backend:**
- Spring Boot 3.x or 4.x with `spring-boot-starter-parent` as the Maven parent — no plain Spring Framework WAR deployments
- Spring Data JPA (`spring-boot-starter-data-jpa`) for the repository layer — no hand-written `JdbcTemplate` or `AbstractRepository` base classes
- Lombok applied uniformly: `@Data` on mutable DTOs, `@Value` on immutable ones, `@RequiredArgsConstructor` with `final` fields for constructor injection in all service and controller classes
- Spring Security OAuth2 Resource Server (`spring-boot-starter-security-oauth2-resource-server`) for JWT validation — no custom `SecurityConfig` that silently falls back to a mock mode
- `application.yml` as the canonical configuration mechanism — no manual `PropertySourcesPlaceholderConfigurer`, no `@ComponentScan` with explicit package lists, no `WebApplicationInitializer` implementations
- `@Transactional` on all service methods that perform writes

**Frontend:**
- React with TypeScript in strict mode
- React Query as the data-fetching layer — no module-level mutable caches, no ad-hoc `fetch` outside hooks
- A single `AuthContext` / `useAuth()` as the sole source of truth for authentication state — `ProtectedRoute` and all components must consume this; no independent auth queries
- `ErrorBoundary` components wrapping route subtrees
- `import.meta.env.PROD` (not `NODE_ENV`) for environment guards in Vite projects
- No form data of any sensitivity written to `localStorage` or `sessionStorage`
- No `CI=false` in the build script
- No file-level `eslint-disable` directives on type-safety rules

**CI/CD:**
- Third-party GitHub Actions pinned to immutable commit SHAs (not mutable semver tags)
- Secrets passed as HTTP headers, never as URL parameters or curl form fields
- `secrets:` blocks in called workflows enumerate only what that workflow needs — no `secrets: inherit`
- Context values (`github.head_ref`, `github.ref_name`, `github.actor`, etc.) assigned to `env:` variables before shell use — never interpolated directly via `&#36;{{ }}` inside `run:` blocks
- Shell scripts use `set -euo pipefail` and validate API responses before acting on them
- No credential or token values exported at the workflow `env:` level — scoped to the individual step `env:` blocks that require them

---

## What to Investigate

Work through each area below. Use the actual source files to gather evidence before writing each finding.

### 1. Backend

- Does the backend use Spring Boot with `spring-boot-starter-parent` as the Maven parent? If not, document the configuration overhead introduced by the absence of Spring Boot.
- Are Lombok annotations applied consistently across all DTOs, models, and service classes? Count or estimate the number of manual getter/setter methods that could be replaced.
- Is Spring Data JPA (or Spring Data JDBC where appropriate) used for the repository layer? If not, document the hand-written JDBC surface area.
- Are write operations in service classes annotated with `@Transactional`? Identify any multi-step writes that are not.
- Is JWT validation handled by Spring Security's OAuth2 resource server auto-configuration? If a custom `isJwtEffectivelyEnabled()` or equivalent condition exists that can silently disable authentication, document it.
- Are there service classes that have grown to 400+ lines and handle more than one logical concern? Identify them by name and approximate line count.
- Does the exception handler expose internal framework details (e.g., `BindingResult#toString()`, stack traces) to API callers?
- Are there `@PreAuthorize` guards on all write endpoints, or are any deferred with TODO comments?
- Does the codebase have dead code: unreachable branches, duplicate identical branches in a conditional, methods that are never called?
- Does the global exception handler cover all common exception types, or are some bubbling up as 500s?

### 2. Frontend

- Is `ProtectedRoute` (or the equivalent guarded route wrapper) consuming the shared auth context, or does it have its own independent authentication query?
- Is there an `ErrorBoundary` wrapping the main route subtrees?
- Are environment guards using `import.meta.env.PROD` (for Vite projects) or `process.env.NODE_ENV === 'production'` (for CRA)?
- Is any sensitive form data (user input, licence numbers, identifiers, tokens) written to `localStorage` or `sessionStorage`?
- Does the application use module-level mutable state (`Map`, `Set`, arrays declared at module scope) in place of React Query cache or context state?
- Does the token refresh mechanism update the user object in the auth context, or only refresh the token silently?
- Is `CI=false` set in the frontend build script?
- Are there file-level `/* eslint-disable */` or `// @ts-ignore` directives in security-sensitive files (API client, auth utilities, request interceptors)?
- Does any file log JWT payloads, user identity attributes, or tokens to the browser console?

### 3. Security (cross-cutting)

- Are there hardcoded credentials, API keys, tokens, or infrastructure identifiers anywhere in committed source files?
- Does any SSL/TLS configuration accept all certificates unconditionally (empty `checkServerTrusted`, disabled hostname verification)?
- Are credentials assembled by string concatenation (creating log exposure and injection risk)?
- Is `JwtUtil` or any authentication-related class injected into the service layer (coupling business logic to auth)?
- Does the error response surface expose internal object graph, class names, or constraint violation paths?

### 4. CI/CD Pipelines

Review every file under `.github/workflows/` and any `.sh` scripts they reference.

- Are any `secrets.*` values passed as curl `--data-urlencode` form parameters or URL query parameters? They should be HTTP headers.
- Are any workflows using `secrets: inherit`? List which ones.
- Is any secret or token exported at the workflow-level `env:` block, making it available to every step?
- Are all external actions (`uses:`) pinned to full commit SHAs? List any that use mutable `@vN` tags.
- Are any GitHub context values — `github.head_ref`, `github.ref_name`, `github.actor`, `github.event.inputs.*` — interpolated directly via `&#36;{{ }}` inside a `run:` block? These are script injection vectors.
- Do shell scripts begin with `set -euo pipefail`?
- Are API responses validated for expected structure before fields are extracted from them?
- Are there any syntactically broken `curl` commands (e.g., `curl -s POST` instead of `curl -s -X POST`) that silently do the wrong thing?
- Are actions version-pinned in a way that allows supply chain attacks?

### 5. Testing and Observability

- Does the backend test suite include integration tests that exercise the database layer, or are all tests mocked at the service boundary?
- Is the repository or data access layer excluded from Sonar coverage enforcement?
- Does the frontend have unit tests for auth utilities, critical hooks, and error states?
- Is there any evidence that coverage flags or thresholds have been disabled or lowered to pass CI?

---

## Report Format

Write the report in the following format. Do not use numbered finding IDs, bullet lists per finding, or "Evidence:" / "Recommended action:" labels. Each finding is a standalone section with a heading and narrative prose. Evidence is quoted inline; the recommendation is the closing paragraph of the section.

```
# Technical Review — [Project Name]

**Project:** [Full project name]
**Date:** [Today's date]
**Prepared by:** Paulo Cruz
**Audience:** Director and above

---

## Executive Summary

[2-4 paragraph prose. Lead with the most significant structural finding. Name the two or three findings with immediate operational risk. Describe the rest as maintenance debt that compounds over time.]

---

## Security

### [Finding title]

[Prose description. Quote the relevant code inline. End with the remediation.]

---

## Frontend

[Same pattern — one section per finding, prose narrative.]

---

## Backend

[Same pattern.]

---

## CI/CD Pipelines

[Same pattern.]

---

## Summary

| Area | Finding | Severity |
|------|---------|----------|
[One row per finding. Severity: Critical / High / Medium / Low]

---

## Recommended Next Steps

[Numbered list, ordered by risk. Each item is 1-2 sentences: what to do and why it closes a specific finding.]
```

**Tone:** Professional, direct, written for a director-level reader who is not reviewing the code but needs to understand the risk exposure and the remediation effort. Do not use "AI language" (e.g., "it's worth noting", "it is important to", "it can be observed that", "notably", "in summary"). State findings plainly. Quantify where possible (line counts, file counts, method counts).

---

## Before You Start

1. Clone the target repository `{{ github.event.inputs.target_repository }}` into a local directory named `./target_repo` (e.g. run `git clone https://github.com/{{ github.event.inputs.target_repository }}.git ./target_repo`).
2. Run `find ./target_repo -maxdepth 1 -type f -o -maxdepth 2 -type d` to understand the top-level structure.
3. Read `./target_repo/pom.xml` (backend) and `./target_repo/package.json` (frontend) to confirm the stack.
4. Scan `./target_repo/.github/workflows/` for all workflow and shell script files.
5. Then proceed section by section. Do not write the report until you have read the source files for each area.

## After is Complete

When you have completed the report, review it for clarity and completeness. Ensure that each finding is supported by evidence from the codebase and that the recommended next steps are actionable and directly address the findings.
1. Save the report inside the `reports/` folder of the current workspace, named after the target repository name (e.g. `reports/pubcode-code-quality-assessment.md` or `reports/actions-code-quality-assessment.md` or `reports/quickstart-openshift-code-quality-assessment.md`).