# Technical Review — quickstart-openshift

**Project:** bcgov/quickstart-openshift
**Prepared by:** FDS Code Quality Auditor (Automated)
**Audience:** Director and above

---

## Executive Summary

quickstart-openshift is a template repository, not a Spring Boot application. The backend is NestJS 12 with Prisma 7 and PostgreSQL (about 1,150 lines of TypeScript in `backend/src`, including specs), and the frontend is React with Vite and TanStack Router (about 460 lines). The FDS Spring Boot, Spring Data JPA, Lombok and OAuth2 resource server standards do not apply to it. They are recorded here as a structural deviation: a project cloned from this template starts outside the FDS stack standard.

The most significant operational risk is that the backend has no authentication or authorisation and no input validation. `UsersController` exposes create, update, delete and search endpoints on `users` with no guard, `app.enableCors()` allows every origin, and no `ValidationPipe` is registered. Any caller can create, change or delete user records, and the search endpoint passes a caller-supplied JSON filter (arbitrary keys and operators) straight into a Prisma `where` clause. The second risk is supply-chain exposure in CI: 15 uses of GitHub-owned actions are pinned to mutable major-version tags (`@v7`, `@v6`, `@v4`, `@v11`) rather than commit SHAs, while the third-party actions are correctly SHA-pinned. The third is a disabled TLS check in the integration-test health probe (`curl -k`).

The remaining findings are maintenance debt: untyped `any` in the search service, error messages returned to callers from the delete path, response logging in the Axios interceptor, no frontend auth or React Query layer, and no database-backed integration test. The CI/CD pipeline is otherwise in good shape: no `secrets: inherit`, no workflow-level secrets, no direct interpolation of `head_ref`, `ref_name` or `actor` in `run:` blocks, and all shell scripts use `set -euo pipefail`.

---

## Security

### Backend endpoints have no authentication or authorisation

`backend/src/users/users.controller.ts` defines `@Post()`, `@Put(':id')`, `@Delete(':id')`, `@Get()` and `@Get('search')` with no guard, and the application has no guard, JWT or OAuth2 module anywhere under `backend/src`. `bootstrap()` in `app.ts` calls `app.enableCors()` with no options, which accepts requests from any origin. The routes are published at `https://<app>.apps.silver.devops.gov.bc.ca/api/v1/users`, so any internet client can read every user's name and email and modify or delete them. As a template this is a reasonable starting point, but derived projects inherit it with no warning in code. Add a JWT guard (Passport JWT or an OIDC library against the BC Gov SSO realm), apply it globally, restrict CORS to the application origin, and document that the sample endpoints are unprotected.

### Search filter accepts caller-controlled Prisma queries

`UsersService.searchUsers` parses the `sort` and `filter` query strings with `JSON.parse` and feeds them to Prisma: `orderBy: sortObj` is used unvalidated, and `convertFiltersToPrismaFormat` uses `item.key` as a column name with no allow-list (`prismaFilterObj[item.key] = { contains: item.value }`). Callers can filter or sort on any field in the model, including future sensitive columns, and can send values of unexpected types (`in` with a non-array). A malformed filter fails inside Prisma and is thrown as a plain `Error('Invalid query parameters')`, which Nest returns as a 500. Restrict keys and operations to an allow-list, validate with a DTO, and return 400 for invalid input.

### No request validation

`CreateUserDto` is `PickType(UserDto, ['email', 'name'])`, `main.ts` and `app.ts` register no `ValidationPipe`, and `class-validator` is not a dependency. The `id` path parameter is converted with `+id`, so `/users/abc` yields `NaN` passed to `new Prisma.Decimal(NaN)`. Register a global `ValidationPipe` with `whitelist: true`, add `class-validator` decorators to the DTOs, and use `ParseIntPipe` for ids.

### TLS verification disabled in integration-test health check

`.github/workflows/reusable-tests.yml` line 45 runs `curl -k --connect-timeout 5 --max-time 10 -s -o /dev/null -w "%{http_code}" "${BASE_URL}/api/health"`. The `-k` flag skips certificate validation. The target is a platform-issued route and the request carries no secret, so the exposure is low, but it hides certificate faults that the repository's own `cert-expiry.yml` workflow is meant to catch. Remove `-k`.

### Raw error messages returned to callers

`UsersService.remove` catches any error and returns `{ deleted: false, message: err.message }` with HTTP 200. Prisma error messages include model names, query arguments and constraint details. No global exception filter exists, so other errors surface as default Nest responses. Return a generic message, log the detail server-side, and map Prisma error codes (`P2025`, `P2002`) to 404 and 409 in an exception filter.

---

## Frontend

### Axios interceptor logs response data and discards errors

`frontend/src/service/api-service.ts` logs `console.info(`received response status: ${config.status} , data: ${config.data}`)` for every response, which writes API payloads (here, user names and emails) to the browser console and prints `[object Object]` because `config.data` is interpolated in a template string. The error handler calls `console.error(error)` and returns nothing, so rejected requests resolve as `undefined` and callers such as `Dashboard.tsx` receive no error. Remove the success log, and return `Promise.reject(error)` from the error handler.

### Data fetching and authentication are not on the FDS pattern

The frontend has no React Query, no `AuthContext` / `useAuth()` and no `ProtectedRoute`. `Dashboard.tsx` fetches `/v1/users` in a `useEffect`, copies the result into local state and swallows failures with `console.error(error)`, so users see an empty table on error. This matches the backend's lack of authentication. Adopt React Query for server state and add the auth context when the backend gains authentication.

### Error handling is limited to the root route

`routes/__root.tsx` sets `errorComponent: ({ error }) => <ErrorComponent error={error} />`, which covers route-level render errors. There is no `ErrorBoundary` component around subtrees such as the dashboard table or the modal, and no handling for failed fetches. Add boundaries around data-driven subtrees.

### Generated route tree disables lint and type checks

`frontend/src/routeTree.gen.ts` starts with `/* eslint-disable */` and `// @ts-nocheck`. This is a TanStack Router generated file, excluded from Sonar and from coverage, and is not security-sensitive. No file-level suppressions exist elsewhere. Keep the exclusion limited to generated output. Findings that pass: no `localStorage` or `sessionStorage` use, no `CI=false`, `strict: true` in `tsconfig.json`, and no `NODE_ENV` guards.

---

## Backend

### Not a Spring Boot application

There is no `pom.xml`. The backend is NestJS with Prisma (`backend/prisma/schema.prisma`) in place of Spring Boot, Spring Data JPA and Lombok. The equivalent concerns are met in different ways: Prisma provides the repository layer, TypeScript object literals replace getters and setters, and `@nestjs/config` and environment variables replace `application.yml`. This is a stack difference from the FDS standard and not a defect, but shared libraries, security configuration and developer skills do not transfer.

### Multi-step and write operations have no transaction handling

The service has three writes (`create`, `update`, `remove`), each a single Prisma call, so atomicity holds today. `searchUsers` runs `findMany` and `count` as two separate queries with the filter conversion repeated, so a concurrent write can return a total that does not match the page. Use `prisma.$transaction([...])` for the pair and as the pattern for derived projects.

### Untyped and duplicated search logic

`searchUsers` returns `Promise<any>`, declares `let sortObj: any`, and returns raw Prisma rows (`users`) rather than `UserDto` objects, so the search response has a different shape from the list endpoint. `convertFiltersToPrismaFormat` is a 10-branch if/else chain (about 30 lines) that is better as a lookup table. `UsersService` is 159 lines and has a single concern, so no oversized-service finding applies. `UsersController` uses `HttpException` for 400 and 404, but `update` and `remove` do not return 404 for an unknown id; `update` returns a 500 from Prisma.

### Pagination count passes unused `orderBy`

`prisma.users.count({ orderBy: sortObj, where })` passes sort options to a count query, which is unnecessary work and a second place where unvalidated sort input reaches the database. Remove `orderBy` from the count call.

---

## CI/CD Pipelines

### Actions pinned to mutable tags

15 `uses:` lines across 6 workflows reference mutable tags: `actions/checkout@v7` (8 uses in analysis, cert-expiry, reusable-tests, release, scheduled and merge), `actions/setup-node@v7` (2), `actions/cache@v6` (2), `actions/upload-artifact@v7` (1), `actions/stale@v11` (1) and `github/codeql-action/upload-sarif@v4` (2 in `analysis.yml`). Third-party actions (`bcgov/*`, `aquasecurity/trivy-action`, `shrink/actions-docker-registry-tag`) are SHA-pinned with a version comment, so only the GitHub-owned actions deviate. A moved tag would run new code with the repository's token. Pin these to SHAs; Renovate, which the repo already uses, can keep them current.

### Context values interpolated into shell

No `github.head_ref`, `ref_name` or `actor` is interpolated in `run:` blocks. Two lower-risk interpolations remain: `scheduled.yml` line 61 uses `REPO="${{ github.event.repository.name }}"` and `reusable-deploy.yml` uses `-p NAME="${{ github.event.repository.name }}"` inside `run:`. Repository names are constrained by GitHub and are not attacker-controlled in practice, and `release.yml` already passes the tag through `env: RELEASE`. Move these to `env:` for consistency.

### Items that meet the standard

No workflow uses `secrets: inherit`; called workflows receive `db_password` and `oc_token` explicitly. No secret is set at workflow-level `env:` (the only top-level `env:` in `reusable-tests.yml` holds `DOMAIN` and `PREFIX`). `reusable-tests.yml` declares `permissions: {}`. All four setup scripts in `scripts/` begin with `set -euo pipefail`. No broken `curl` invocations were found.

---

## Summary

| Area | Finding | Severity |
|------|---------|----------|
| Security | No authentication or authorisation on user endpoints; open CORS | High |
| Security | Search filter and sort accept unvalidated caller-controlled Prisma input | High |
| Security | No request validation (`ValidationPipe`, DTO validators, id parsing) | Medium |
| Security | `curl -k` disables TLS verification in health check | Low |
| Security | Raw Prisma error messages returned from delete | Medium |
| Frontend | Axios interceptor logs payloads and swallows errors | Medium |
| Frontend | No React Query, auth context or protected routes | Medium |
| Frontend | No `ErrorBoundary` below root route | Low |
| Frontend | `eslint-disable` / `@ts-nocheck` in generated route tree | Low |
| Backend | Not Spring Boot; outside FDS stack standard | Medium |
| Backend | Search count and query not in a transaction | Low |
| Backend | `any` types, inconsistent search response, missing 404 on update/delete | Low |
| CI/CD | 15 GitHub-owned action uses pinned to mutable tags | High |
| CI/CD | `github.event.repository.name` interpolated in `run:` blocks | Low |

---

## Recommended Next Steps

1. Add a global JWT guard to the backend and restrict CORS to the application origin, which closes the unauthenticated write access.
2. Register a global `ValidationPipe`, add DTO validators and `ParseIntPipe`, and replace the search `filter` and `sort` parsing with an allow-listed DTO, which closes the injection-style and bad-input findings.
3. Pin all `actions/*` and `github/codeql-action` references to commit SHAs, which closes the supply-chain finding.
4. Add a global exception filter that maps Prisma errors to 400, 404 and 409 and stops returning raw messages from `remove`.
5. Fix the Axios interceptor to stop logging response data and to reject on error, then move fetching to React Query with an `ErrorBoundary`.
6. Remove `-k` from the health-check `curl` and move `github.event.repository.name` into `env:` in the two workflows.
7. Wrap the search `findMany` and `count` in `$transaction`, type the return value as `UserDto`, and add a database-backed integration test (the current `backend/test` has one e2e spec, and unit tests mock Prisma).
8. Decide whether derived projects are expected to follow the FDS Spring Boot standard; if so, document the NestJS template as an approved alternative stack or provide a Spring Boot variant.
