# Technical Review — QuickStart OpenShift

**Project:** bcgov/quickstart-openshift
**Date:** 2026-10-28
**Prepared by:** FDS Code Quality Auditor (Automated)
**Audience:** Director and above

---

## Executive Summary

QuickStart OpenShift is a deliberately small reference template: a NestJS 12 / Prisma 7 backend (`backend/src`, 13 top-level source files plus a `users` module whose service is 159 lines), a React/Vite frontend (about 170 lines across routes and components), and eleven GitHub Actions workflows that deploy to OpenShift. The most significant structural finding is that it does not follow the FDS stack standard at all. There is no Spring Boot, JPA, Lombok or OAuth2 resource server (the scanner found no `pom.xml`), and the frontend has no React Query, no `AuthContext`, and no ErrorBoundary components. Teams that fork the template inherit a different stack with no authentication layer, which has to be built from scratch.

Three findings carry immediate operational risk. Every API endpoint, including create, update and delete on `/api/v1/users`, is reachable anonymously. The backend logs full SQL text and bound parameters for every query, so user names and emails land in application logs. Fifteen `uses:` references across six workflows are pinned to mutable tags (`actions/checkout@v7`, `actions/cache@v6`, `actions/stale@v11`, `github/codeql-action/upload-sarif@v4` and others), so a retargeted tag changes what runs in a pipeline that holds the OpenShift deploy token.

The remaining findings are maintenance debt: no request validation on DTOs, wildcard CORS, no global exception filter, a response interceptor that swallows errors, a `curl -k` health check, and a thin test base (one frontend test, no database-level tests). Strengths: no `secrets: inherit`, no workflow-level secret `env:`, no script-injection interpolations, `permissions: {}` at the top of every workflow, all four shell scripts use `set -euo pipefail`, and the third-party bcgov/aquasecurity/shrink actions are SHA-pinned.

---

## Security

### All API endpoints are unauthenticated

`backend/src/users/users.controller.ts` exposes `@Post()`, `@Put(':id')` and `@Delete(':id')` with no `@UseGuards`, no JWT validation and no role check. `app.module.ts` registers no global guard. Any caller with network access can create, modify or delete user records. The FDS standard requires JWT validation (Spring Security OAuth2 resource server on the Java stack) and `@PreAuthorize` on writes; the NestJS equivalent is absent. Add JWT validation as a global `APP_GUARD` with explicit `@Public()` exemptions for health and metrics, and require roles on write routes.

### SQL text and parameters are written to application logs

`backend/src/prisma.service.ts` line 56 logs `` `Query: ${e.query} - Params: ${e.params} - Duration: ${e.duration}ms` `` for every query not matching the health-check exclusion list. Names and emails supplied through `POST /users` and the `like`/`eq` search filters are therefore stored in plain text in the log stream. Remove `Params` from the message, or log queries only at debug level in non-production environments.

### Wildcard CORS

`backend/src/app.ts` calls `app.enableCors()` with no options, which allows every origin. Combined with the missing authentication, any web page can call the API from a visitor's browser. Restrict origins to the deployed frontend host through configuration.

### TLS verification disabled in the integration health check

`.github/workflows/reusable-tests.yml` line 45 runs `curl -k --connect-timeout 5 --max-time 10 -s -o /dev/null -w "%{http_code}" "${BASE_URL}/api/health" || true`. The check targets a deployed environment over HTTPS and accepts any certificate, so an invalid or expired certificate passes unnoticed. The `|| true` also converts curl failure into an empty status, which then fails the `[ "$status" -eq 200 ]` test with a shell error rather than a clear message. Remove `-k` and quote/default `status`.

### No hardcoded credentials found

The scanner found no hardcoded secrets or token writes to browser storage, and no empty trust managers. No action required.

---

## Frontend

### No shared authentication context, React Query layer or route guard

The scanner found no `AuthContext`/`useAuth`, no `@tanstack/react-query`, and no `ProtectedRoute`. `frontend/src/components/Dashboard.tsx` (96 lines) calls the API directly through the axios singleton in `service/api-service.ts`. This is consistent with an unauthenticated API but departs from the standard, so any team adding login has no sanctioned place to put it. Introduce React Query and a single `AuthContext` before the first authenticated feature is built.

### API client swallows errors and logs response bodies

`frontend/src/service/api-service.ts` registers a response interceptor whose error handler is `(error) => { console.error(error) }`. It returns nothing, so every failed request resolves as `undefined` and callers cannot distinguish failure from an empty result. The success handler logs `` `received response status: ${config.status} , data: ${config.data}` `` to the browser console, which will expose payloads (and user data) once real data or tokens flow through the client. Return `Promise.reject(error)` from the error handler and remove the payload logging.

### Error handling is route-level only

There are no `ErrorBoundary` components; `frontend/src/routes/__root.tsx` sets TanStack Router's `errorComponent`, which covers route render errors but not a failing component outside the router tree. This is partial coverage of the standard. Add an `ErrorBoundary` around the application root.

### Environment guards, CI flag and lint suppressions are clean

No `NODE_ENV` or `CI=false` usage was found (the build script is `vite build`). The only file-level suppressions are `/* eslint-disable */` and `// @ts-nocheck` in `frontend/src/routeTree.gen.ts`, a generated router file; this is acceptable but the file should be listed in the lint ignore config rather than carrying inline directives.

---

## Backend

### Stack differs from the FDS standard

The backend is NestJS with Prisma rather than Spring Boot with Spring Data JPA. Lombok, `@Transactional` and OAuth2 resource server checks do not apply; the equivalent controls (DI constructor injection, transactions, JWT guard) should be assessed against the NestJS stack. Constructor injection with `private readonly` is used consistently. Document the NestJS variant of the standard if this template is to remain in the portfolio.

### No input validation on DTOs

`backend/src/users/dto/user.dto.ts` declares `name!: string` and `email!: string` with only Swagger decorators, and `CreateUserDto` extends it. No `class-validator` decorators exist, `class-validator`/`class-transformer` are not in `package.json`, and `app.ts` never calls `useGlobalPipes(new ValidationPipe(...))`. Malformed email addresses and arbitrary field values reach the database unchecked. Add `class-validator` and a global `ValidationPipe` with `whitelist: true`.

### Search endpoint passes caller-controlled keys to Prisma

`UsersService.searchUsers` parses `sort` and `filter` from query-string JSON and `convertFiltersToPrismaFormat` uses `item.key` as a Prisma field name without an allow-list; `sort` goes straight to `orderBy`. Callers can probe any column of the `users` model with any operator. Restrict keys to a fixed set of permitted fields. In the controller, `page` and `limit` arrive as strings (`isNaN` works by coercion) with no upper bound on `limit`, so a single request can request the entire table.

### Inconsistent error handling

There is no global exception filter. `searchUsers` throws a plain `Error('Invalid query parameters')` for malformed JSON, which Nest returns as a 500 rather than a 400. `remove` catches all errors and returns `{ deleted: false, message }` with HTTP 200, and `update` on a missing id will surface a Prisma error as a 500. Add a global filter that maps Prisma `P2025` to 404 and validation failures to 400.

### Dead branches and ID parsing

`convertFiltersToPrismaFormat` is a ten-branch if/else chain that silently ignores unknown operations, and controllers convert ids with `+id` without validating, so `/users/abc` produces `NaN` queries. Use a lookup map and `ParseIntPipe`.

---

## CI/CD Pipelines

### Fifteen action references use mutable tags

The scanner lists 15 unpinned references across `analysis.yml` (4), `reusable-tests.yml` (6), `scheduled.yml` (2), `cert-expiry.yml`, `release.yml` and `merge.yml` (1 each): `actions/checkout@v7`, `actions/setup-node@v7`, `actions/cache@v6`, `actions/upload-artifact@v7`, `actions/stale@v11` and `github/codeql-action/upload-sarif@v4`. The bcgov, trivy and docker-tag actions are already pinned to full SHAs with version comments, so the gap is limited to GitHub-owned actions. Pin them to SHAs and let Renovate (already configured in `renovate.json`) maintain the digests.

### Deploy token reaches called workflows through explicit secrets only

Verified positives: no `secrets: inherit`, no secret at workflow-level `env:` (the only top-level `env:` holds `DOMAIN` and `PREFIX`), no `${{ github.head_ref }}`, `ref_name`, `actor` or `event.inputs` interpolation in `run:` blocks, and all workflows declare `permissions: {}` with per-job grants. No action required.

### Health check retry loop is fragile

Beyond `-k`, the loop in `reusable-tests.yml` ignores curl failure with `|| true` and compares a possibly empty string numerically. The step does not use `set -euo pipefail` (GitHub's default `bash -e` shell applies). Declare `shell: bash` with `set -euo pipefail`, default `status=000`, and fail with a clear message after 30 attempts.

---

## Testing and Observability

The backend has unit specs for the controller, service, logger, Prisma service and middleware, plus one e2e spec; none exercise a real database, so Prisma query behaviour (filters, `P2025` errors) is untested. Coverage excludes only configs and spec files, and the Sonar run excludes `**/*spec.ts` and coverage output, so the data-access layer is not excluded and no thresholds were found lowered. The frontend has one test (`__tests__/Dashboard.tsx`, 9 lines) that checks a title renders; there are no tests for the API client, error states or hooks. Add error-path tests for `api-service.ts` and a database-backed integration suite.

---

## Summary

| Area | Finding | Severity |
|------|---------|----------|
| Security | All API endpoints unauthenticated, including writes | Critical |
| Security | SQL text and parameters logged for every query | High |
| Security | Wildcard CORS | Medium |
| Security | `curl -k` TLS bypass in integration health check | Medium |
| Frontend | No AuthContext, React Query or route guard | Medium |
| Frontend | Axios error interceptor swallows errors; response data logged | Medium |
| Frontend | No ErrorBoundary component (router `errorComponent` only) | Low |
| Backend | Stack does not match FDS Spring Boot standard | Medium |
| Backend | No DTO validation, no global ValidationPipe | High |
| Backend | Search filter keys and sort not allow-listed; unbounded `limit` | Medium |
| Backend | No global exception filter; 500s and 200-on-failure delete | Medium |
| Backend | Unvalidated id parsing, long if/else operator chain | Low |
| CI/CD | 15 GitHub-owned actions pinned to mutable tags | High |
| CI/CD | Health check loop ignores failures with `|| true` | Low |
| Testing | No database-level tests; one 9-line frontend test | Medium |

---

## Recommended Next Steps

1. Add JWT validation as a global guard with role checks on POST, PUT and DELETE routes, closing the unauthenticated-API finding.
2. Remove `Params` from the Prisma query log line in `prisma.service.ts` to stop user data entering logs.
3. Pin the 15 mutable `uses:` references to commit SHAs and rely on Renovate for updates.
4. Add `class-validator` DTO decorators and a global `ValidationPipe`, and allow-list search filter and sort keys with a capped `limit`.
5. Add a global exception filter mapping Prisma and validation errors to 404/400 and make `remove` return proper status codes.
6. Restrict CORS origins and remove `curl -k` from `reusable-tests.yml`.
7. Fix the axios interceptor to reject errors and stop logging response bodies; add an `ErrorBoundary`.
8. Add React Query and a single `AuthContext` before any authenticated UI is built, and add database-backed backend tests and frontend error-path tests.