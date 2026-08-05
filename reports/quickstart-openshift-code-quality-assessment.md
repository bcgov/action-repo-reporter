# Technical Review — QuickStart OpenShift

**Project:** bcgov/quickstart-openshift
**Date:** 2026-08-05
**Prepared by:** Paulo Cruz
**Audience:** Director and above

---

## Executive Summary

The QuickStart OpenShift project is a NestJS/Prisma backend paired with a React (Vite/TypeScript) frontend, deployed on OpenShift via GitHub Actions. It is a deliberately minimal reference template, not a production application, and that context shapes both what is present and what is absent. Taken at face value as a starter kit, the code is structurally clean and the CI/CD scaffolding is above average. Taken as a foundation that teams extend toward production, several gaps require attention before it can be considered safe to ship as-is.

The two findings with immediate operational risk are: the complete absence of any authentication or authorisation layer on all API endpoints (every write and read is open to anonymous callers), and the logging of full SQL query parameters — including user-supplied values — to application logs in the Prisma query event handler. A third finding with operational risk is the use of mutable semver tags for several first-party GitHub Actions (`actions/checkout@v7`, `actions/setup-node@v7`, `actions/cache@v6`, `actions/upload-artifact@v7`, `actions/stale@v11`, `github/codeql-action/upload-sarif@v4`), which allows any tag retargeting to silently compromise the pipeline.

The remaining findings — no input validation on DTO fields, wildcard CORS, no global exception filter, no React Query or auth context in the frontend, and the `curl -k` TLS bypass in integration tests — are maintenance debt that teams extending this template will inherit and that compound once the project diverges from the reference baseline.

---

## Security

### All API Endpoints Are Unauthenticated

The NestJS application has no authentication or authorisation layer of any kind. `app.module.ts` imports `ConfigModule`, `TerminusModule`, and `UsersModule`; there is no `@nestjs/passport`, no JWT guard, and no `@UseGuards()` decorator anywhere in the controller tree. Every endpoint — `POST /api/v1/users`, `PUT /api/v1/users/:id`, `DELETE /api/v1/users/:id` — is reachable anonymously. Any network path to the deployed service is sufficient to create, modify, or delete records.

Adding `@nestjs/passport` and `passport-jwt` and applying an `AuthGuard('jwt')` via a global `APP_GUARD` provider in `app.module.ts` closes this for all routes by default, with explicit `@Public()` overrides for the health and metrics endpoints.

### SQL Query Parameters Written to Application Logs

`prisma.service.ts` subscribes to the Prisma `query` event and logs the full query text and parameter list:

```typescript
this.logger.log(`Query: ${e.query} - Params: ${e.params} - Duration: ${e.duration}ms`)
```

The `e.params` field contains the serialised runtime values passed to every query, including user names and email addresses. In a production deployment, these entries appear in the OpenShift log aggregator and any downstream log shipping targets. Remove or redact `e.params` from this log line; retain `e.query` and `e.duration` for performance observability.

### Database Connection String Assembled by String Concatenation

`prisma.service.ts` builds the PostgreSQL connection URL by concatenating environment variables:

```typescript
const dataSourceURL = PGBOUNCER_URL
  ? `${PGBOUNCER_URL}?schema=${DB_SCHEMA}&pgbouncer=true`
  : `(redacted)
```

`DB_PWD` is `encodeURIComponent`-encoded, which is correct for URL safety. However, the raw `process.env.POSTGRES_PASSWORD` value is read at module load time, and if it contains characters that survive encoding, it is embedded verbatim in the URL string that is passed to the `pg` pool. If that URL is ever logged (e.g., by a pool library on connection error), the password is exposed. Prefer configuring the `pg.Pool` directly with discrete host/user/password/database fields rather than assembling a connection string.

### CORS Accepts All Origins

`app.ts` calls `app.enableCors()` with no configuration object. NestJS defaults this to `{ origin: '*' }`, which means any web origin can make credentialed cross-origin requests to the API. For a deployed service, `origin` should be constrained to the known frontend hostname(s).

### No Input Validation on DTO Fields

The `CreateUserDto` and `UpdateUserDto` classes carry no `class-validator` decorators, and `ValidationPipe` is not registered globally. The `name` field has a 200-character `VARCHAR` constraint at the database level, but there is no server-side enforcement of that length, format, or required presence before the value reaches Prisma. A caller can submit an empty string for `name` or any content for `email` without receiving a validation error. Register `ValidationPipe` as a global pipe in `app.ts` and add `@IsString()`, `@MaxLength(200)`, and `@IsEmail()` decorators to the DTO classes.

### No Global Exception Filter

There is no `@Catch()` exception filter registered anywhere in the application. NestJS's built-in exception layer will surface Prisma client errors — including `PrismaClientKnownRequestError` with `meta` fields that can contain column names and constraint identifiers — as unhandled 500 responses. The `remove()` method in `users.service.ts` demonstrates this pattern: it catches Prisma errors and returns `{ deleted: false, message: err.message }`, directly forwarding Prisma's internal error text to the caller. A global `HttpExceptionFilter` that maps Prisma error codes to appropriate HTTP statuses and strips internal detail from the response body is required.

---

## Frontend

### No Authentication Layer

The frontend has no authentication mechanism. There is no `AuthContext`, no `useAuth()` hook, no `ProtectedRoute` wrapper, and no token acquisition or refresh logic. `main.tsx` renders the router directly from `routeTree`. The dashboard fetches user records without an `Authorization` header. For a reference template, this gap means every team that forks the repo must implement auth from scratch, with no structural guidance from the starter.

### Data Fetching Uses Ad-hoc State Rather Than React Query

`Dashboard.tsx` fetches data inside a `useEffect` using the raw Axios instance, storing results in local component state with `useState`:

```typescript
useEffect(() => {
  apiService.getAxiosInstance().get('/v1/users').then((response) => {
    setData(users)
  })
}, [])
```

The FDS standard mandates React Query as the data-fetching layer. The current pattern provides no caching, no automatic retry, no loading/error state management, and no stale-data handling. React Query is not listed in `package.json` at all; it is not a transitive dependency. This means every fork starts from an anti-pattern.

### No ErrorBoundary Wrapping Route Subtrees

The `__root.tsx` route uses TanStack Router's built-in `errorComponent` prop, which handles route-level loader errors. However, there is no React `ErrorBoundary` class component wrapping the render tree to catch runtime rendering errors within components (e.g., a `TypeError` thrown during render when `data` is in an unexpected shape). An `ErrorBoundary` at the root layout level is a production requirement.

### Response Body Logged to Browser Console

`api-service.ts` logs every API response body to the browser console:

```typescript
console.info(`received response status: ${config.status} , data: ${config.data}`)
```

`config.data` is the parsed JSON response from the API. If the API ever returns user identity attributes or other sensitive fields, those values appear in the browser console and are accessible to any script or browser extension running in the same page context. Remove this interceptor or replace it with structured logging that does not surface response bodies.

### Mutable `useState` in Place of Typed State

`Dashboard.tsx` declares data state as `useState<any>([])`. The `any` typing defeats TypeScript's structural checking for the entire data pipeline from API response to render. The state should be `useState<UserDto[]>([])` with the `UserDto` interface already defined in `src/interfaces/UserDto.ts`.

---

## Backend

### Stack Deviation from FDS Standard

The backend is NestJS with Prisma, not Spring Boot with Spring Data JPA. This is not a defect for a Node.js reference template, but it means the FDS stack standard criteria for Spring Boot, Lombok, Spring Data JPA, `@Transactional`, and Spring Security OAuth2 do not apply. The observations below are evaluated against NestJS best practices and the observable codebase.

### No Transaction Boundaries on Multi-Step Operations

`searchUsers()` in `users.service.ts` executes two sequential Prisma queries: `findMany` for the page of results and `count` for the total. These are not wrapped in a Prisma interactive transaction. If a concurrent write occurs between the two queries, the returned `total` and the returned `users` may be inconsistent, producing incorrect pagination metadata. Wrap both calls in `this.prisma.$transaction([...])` or use a single query with `_count`.

### Query Parameter Injection Risk in `searchUsers`

The `filter` and `sort` parameters in `GET /api/v1/users/search` are accepted as raw JSON strings from the query string, parsed client-side, and forwarded to Prisma's `orderBy` and `where` options:

```typescript
sortObj = JSON.parse(sort)
// ...
orderBy: sortObj,
where: this.convertFiltersToPrismaFormat(filterObj),
```

The `sortObj` is passed directly to Prisma's `orderBy` without any allowlist validation. A caller can supply an arbitrary `orderBy` structure that Prisma will forward to PostgreSQL. While Prisma's parameterisation prevents SQL injection, it does not prevent Prisma from accepting structural inputs that target unexpected fields. Add an explicit allowlist of permitted sort keys and filter field names before constructing the Prisma query.

### `remove()` Leaks Internal Error Messages

`users.service.ts` line 81–85:

```typescript
} catch (err) {
  const message = err instanceof Error ? err.message : String(err)
  return { deleted: false, message }
}
```

Prisma error messages include constraint names, table names, and field identifiers. These are returned directly to the API caller in the `message` field. Map Prisma error codes (e.g., `P2025` for record not found) to user-facing messages; do not forward `err.message` to the response.

### Singleton Pattern on `PrismaService` Is Fragile

`prisma.service.ts` implements a manual singleton via a static `instance` field:

```typescript
if (PrismaService.instance) {
  return PrismaService.instance
}
```

NestJS's dependency injection container already manages service lifetime as singletons by default. The manual singleton pattern adds complexity, makes testing harder (the static reference persists across test runs), and conflicts with NestJS's module system. Remove the static instance guard and rely on the DI container.

---

## CI/CD Pipelines

### First-Party GitHub Actions Not Pinned to Commit SHAs

Several workflows use mutable semver tags for `actions/*` and `github/codeql-action`:

| Workflow | Action | Tag |
|---|---|---|
| `reusable-tests.yml` | `actions/checkout` | `@v7` |
| `reusable-tests.yml` | `actions/setup-node` | `@v7` |
| `reusable-tests.yml` | `actions/cache` | `@v6` |
| `reusable-tests.yml` | `actions/upload-artifact` | `@v7` |
| `analysis.yml` | `actions/checkout` | `@v7` |
| `analysis.yml` | `actions/cache` | `@v6` |
| `analysis.yml` | `github/codeql-action/upload-sarif` | `@v4` |
| `merge.yml` | `actions/checkout` | `@v7` |
| `scheduled.yml` | `actions/stale` | `@v11` |

Third-party and first-party actions pinned to semver tags are a supply chain risk: if the tag is retargeted to a different commit, the pipeline silently executes the new code with the repository's secrets in scope. All `uses:` references must be pinned to a full 40-character commit SHA with the version tag as a comment. Renovate is already configured in `renovate.json` and can automate SHA updates.

### `curl -k` Disables TLS Certificate Verification in Integration Tests

`reusable-tests.yml` health-check step:

```bash
status=$(curl -k --connect-timeout 5 --max-time 10 -s -o /dev/null -w "%{http_code}" "${BASE_URL}/api/health" || true)
```

The `-k` flag instructs curl to accept any certificate, including self-signed or expired ones. In a CI environment where the target URL is a known OpenShift route with a valid certificate, `-k` is unnecessary and masks certificate configuration errors. Remove `-k` and ensure the runner's CA trust store includes the OpenShift cluster's CA.

### `set -euo pipefail` Absent from Most Shell Scripts

Only the `scheduled.yml` deployment cleanup script uses `set -euo pipefail`. The health-check loop in `reusable-tests.yml` and the integration test runner do not. In particular, the health-check uses `|| true` to suppress curl errors, which is correct within the retry loop, but the surrounding shell context has no `set -e` to catch other unexpected failures. Add `set -euo pipefail` as the first line of every multi-command `run:` block.

### `sonar_token` Forwarded via `env:` at Step Level, Then Re-referenced from `env`

In `analysis.yml`, the Sonar token is set in the step's `env:` block:

```yaml
env:
  sonar_token: ${{ secrets.sonar_token_backend }}
with:
  sonar_token: ${{ env.sonar_token }}
```

The token is placed into the step environment and then read back out of it via `${{ env.sonar_token }}`. This is functionally correct — the secret is scoped to the step — but the double-reference is unnecessary and potentially confusing. Pass `${{ secrets.sonar_token_backend }}` directly to the `sonar_token` input without the intermediate `env:` indirection.

---

## Summary

| Area | Finding | Severity |
|------|---------|----------|
| Security | All API endpoints are unauthenticated | Critical |
| Security | SQL query parameters (user data) written to logs | High |
| Security | No input validation on DTO fields | High |
| Security | No global exception filter; internal Prisma errors forwarded to callers | High |
| Security | Wildcard CORS (`*`) on all origins | Medium |
| Security | Database connection string assembled by concatenation | Medium |
| Backend | No transaction boundary on `searchUsers` count/findMany pair | Medium |
| Backend | `sortObj` forwarded to Prisma `orderBy` without allowlist validation | High |
| Backend | Manual singleton on `PrismaService` conflicts with NestJS DI | Low |
| Frontend | No authentication layer or auth context | Critical |
| Frontend | Data fetching via raw `useEffect`/Axios; React Query absent | High |
| Frontend | No `ErrorBoundary` wrapping route subtrees | Medium |
| Frontend | API response body logged to browser console | Medium |
| Frontend | `useState<any>` bypasses TypeScript checking on data pipeline | Low |
| CI/CD | Nine `actions/*` and `codeql-action` uses pinned to mutable semver tags | High |
| CI/CD | `curl -k` disables TLS verification in integration health check | Medium |
| CI/CD | `set -euo pipefail` absent from most shell `run:` blocks | Low |
| CI/CD | Sonar token double-referenced through unnecessary `env:` indirection | Low |

---

## Recommended Next Steps

1. **Add authentication to the NestJS API.** Register `@nestjs/passport` and `passport-jwt` as a global `APP_GUARD` in `app.module.ts`. This closes the critical unauthenticated endpoint finding and provides the structural hook for `@Public()` overrides on health and metrics routes.

2. **Remove `e.params` from the Prisma query log line.** Edit `prisma.service.ts` line 56 to log only `e.query` and `e.duration`. This immediately stops user data from flowing into log aggregators.

3. **Register `ValidationPipe` globally and add class-validator decorators to all DTOs.** This closes the input validation gap and prevents malformed or oversized values from reaching Prisma.

4. **Add a global exception filter.** Implement an `HttpExceptionFilter` that catches `PrismaClientKnownRequestError` and maps Prisma error codes to appropriate HTTP statuses without forwarding internal error text to callers.

5. **Pin all GitHub Actions to commit SHAs.** Replace every `@vN` tag reference in `.github/workflows/` with the corresponding 40-character SHA. Renovate's existing configuration can automate subsequent updates once the initial pins are in place.

6. **Introduce React Query and an `AuthContext` to the frontend.** Add `@tanstack/react-query` to `package.json`, wrap the router provider in a `QueryClientProvider`, and replace the `useEffect`/Axios fetch in `Dashboard.tsx` with a `useQuery` call. Add an `AuthContext` provider as the structural foundation for authentication state.

7. **Remove the `curl -k` flag from the integration test health check.** Ensure the runner trusts the OpenShift cluster CA so that certificate verification succeeds without bypassing it.

8. **Add an allowlist to `searchUsers` sort and filter parameters.** Before passing `sortObj` and `filterObj` to Prisma, validate that the field names they reference are members of the known `users` column set.

9. **Wrap the `findMany`/`count` pair in `searchUsers` inside a Prisma transaction.** This ensures the returned page and total are consistent under concurrent writes.

10. **Remove the manual singleton from `PrismaService`.** Delete the static `instance` field and the early-return guard in the constructor; NestJS's DI container provides singleton lifetime by default and the manual pattern causes test isolation failures.