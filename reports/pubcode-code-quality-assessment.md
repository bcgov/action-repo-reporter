# Technical Review — Public Code (pubcode)

**Project:** BC Gov Public Code Registry (`bcgov/pubcode`)
**Prepared by:** FDS Code Quality Auditor (Automated)
**Audience:** Director and above

---

## Executive Summary

pubcode is not built on the FDS stack. The backend is a 992-line Node.js/Express service on MongoDB (mongoose), not Spring Boot. The frontend is 664 lines of plain JavaScript React (`.jsx`) with Vite, not TypeScript. Most of the FDS backend and frontend standards (Spring Data JPA, Lombok, OAuth2 resource server, React Query, `AuthContext`, strict TypeScript) do not apply as written. The audit therefore assesses the equivalent controls. The service is small, so the platform divergence is a standardisation and skills-portability issue rather than a defect.

Three findings carry operational risk. First, the write endpoints (`POST /bulk-load`, `DELETE /:repo_name`) are protected only by a shared static `X-API-KEY`, with no identity, rotation or audit trail. Second, the deploy workflow interpolates workflow inputs and seven secrets directly into shell text, and the caller workflows use `secrets: inherit`. Third, 27 of the third-party action references use mutable version tags, including `actions/*` and `github/codeql-action`, which run in jobs that handle repository content and deployment credentials.

The remainder is maintenance debt: a module-level mutable cache, no automated test of the frontend beyond Cypress end-to-end specs, console logging of request objects, a 50 MB body limit, and unrestricted CORS. The scan found no hardcoded credentials, no disabled TLS validation, no `CI=false`, no web-storage use, and no workflow-level secret exports. Shell fragments use `set -euo pipefail`.

---

## Security

### Write endpoints rely on a single shared static API key

`api/src/routes/pubcode-router.js` guards `router.post("/bulk-load", ...)` and `router.delete("/:repo_name", ...)` with `isValidApiKey(req.header("X-API-KEY"))`. The comparison is constant-time and rejects an unset key, which is sound. The model is still one shared secret read from `process.env.API_KEY`. It is retrieved by the scheduled workflows with `oc get secrets/pubcode ... | base64 -d`. There is no caller identity, no per-client revocation and no audit record of who changed data. This is the equivalent of the FDS requirement for JWT validation, and it is not met. The guard is also copy-pasted inline across two routes rather than defined as middleware. Move the check into a named middleware now, and replace the shared key with OIDC/JWT validation (or at minimum per-caller keys with rotation) for the crawler and cleanup utility.

### Unrestricted CORS, 50 MB body limit and verbose request logging

`api/src/app.js` calls `app.use(cors())` with no origin allow-list, and sets `express.json({ limit: "50mb" })` and `express.urlencoded({ ..., limit: "50mb" })` globally, including on the unauthenticated paths. The body is parsed before the API key is checked on `/bulk-load`, so an unauthenticated client can force the server to buffer up to 50 MB per request, limited only by the 100 requests/minute per-IP rate limit. `softDeleteRepo` also calls `console.info(pubcodeEntityFromDB)`, writing full database documents to the console outside the structured logger. Restrict CORS to the frontend origin, apply the large limit only to the authenticated bulk-load route (default for the rest), and remove the `console.info` call.

### Unauthenticated diagnostic endpoint

`router.get("/ip/trace", (request, response) => response.send(request.ip))` is publicly reachable and returns the client IP as seen behind the proxy. It exists to debug `trust proxy`, and it should not ship in production routes. Remove it or place it behind the API key.

### No hardcoded credentials or disabled TLS validation

The deterministic scan reported zero hardcoded credentials and zero unvalidated TLS configurations. The CHES client credentials are read from `process.env` in `api/src/email/index.js` and validated for presence in `ches-service.js` and `connection.js`. No action required.

---

## Frontend

### Platform differs from the FDS frontend standard

`frontend/package.json` shows React 19 with Vite, MUI and `@rjsf`, written in plain JavaScript (`.jsx`). Only `vite-env.d.ts` and `@types/react` hint at TypeScript, and there is no `tsconfig`-enforced strict mode. There is no React Query, no `AuthContext` and no `ErrorBoundary`. Because the application has no authentication, the `ProtectedRoute`, token refresh and JWT console-logging checks do not apply. Type safety would be the first gain from migration, since the form schema flows through `FormComponent.jsx` (179 lines) and `EditForm.jsx` (111 lines) without static types.

### No error boundary around the route tree

`frontend/src/routes/index.jsx` (24 lines) defines the routes with a `NotFound` component but no `ErrorBoundary`. A render error in `FormComponent`, `Yaml` or `Dashboard` unmounts the whole application and shows a blank page. Wrap the route subtrees in an error boundary with a recoverable fallback.

### Ad-hoc `fetch` inside components

`FormComponent.jsx` fetches the JSON schema from `raw.githubusercontent.com/bcgov/pubcode/${jsonSchemaBranch}/schema/bcgovpubcode.json` inside `useEffect`, and `EditForm.jsx` calls `fetch(url)` against a user-supplied URL. Neither uses React Query, so there is no caching, retry or deduplication. `FormComponent` calls `response.json()` without checking `response.ok`, so an HTTP 404 from GitHub surfaces as a generic parse error. The schema is loaded from a branch name controlled by `VITE_SCHEMA_BRANCH`, so the runtime schema is not tied to the deployed release. Move both calls into query hooks and check `response.ok`.

### Debug logging left in components

`LeftDrawer.jsx` runs `console.log(event)`, and `FormComponent.jsx` runs `console.info(typeof yaml)`. Neither leaks identity data, but both are leftover debug output. No `localStorage`/`sessionStorage` use, file-level `eslint-disable` or `@ts-ignore` directive was found, and the build script is plain `vite build` with no `CI=false`. Remove the debug calls.

---

## Backend

### Node.js/Express with MongoDB instead of Spring Boot

The repository has no `pom.xml`. The API in `api/` is Express 5 with mongoose 9. Spring Boot, Spring Data JPA, Lombok and the OAuth2 resource server are absent, and the corresponding Java-specific checks (`@Transactional`, `@PreAuthorize`, `JwtUtil` coupling, `BindingResult` leakage) do not apply. The practical cost is that the team maintains one more language and runtime outside the standard, with its own dependency and patching cycle (17 runtime dependencies in `api/package.json`). Whether to migrate a 992-line service is a business decision. If the service stays, it should adopt the FDS cross-cutting controls (identity-based auth, structured errors, integration tests) in its own idiom.

### Bulk load is not transactional

The comment above `insertOrUpdate` in `pub-code-service.js` says it "will delete and add all these new in a single transaction into mongoDB". The code does not do that. It loops over the payload, runs `findOneAndReplace` one document at a time, collects the misses, then calls `insertMany` once. A failure midway leaves the collection partially updated, and invalid records are skipped with only an email notification. The `findOneAndReplace` call also passes the raw `pubcode` object rather than the validated entity, so mongoose schema casting and defaults are bypassed on the replace path. Use `bulkWrite` inside a mongoose session transaction and replace the raw object with the validated one.

### Module-level mutable cache and a dead-code branch

`api/src/services/cache-service.js` stores all records in a module-level `let PUB_CODES = []`, refreshed by a scheduler (`schedulers/refresh-cache.js`). Each replica holds its own copy, so replicas can briefly disagree after a bulk load. The `if (PUB_CODES && PUB_CODES.length > 0) { PUB_CODES = []; }` block is redundant because the next line reassigns the variable. `findById` is exported but not registered on any route, so it is dead code, and it would also return 500 on a malformed id. Remove the redundant block and the unused handler.

### Error handling is per-handler, with no central handler

Each handler in `pub-code-service.js` has its own `try/catch` that returns `{ message: "Internal server error" }`, which avoids leaking internals. The app has no Express error-handling middleware, so errors thrown outside these handlers (for example invalid JSON, or a payload over the size limit) use the framework default responses. `readAll` and `bulkLoad` e-mail `error.message` to recipients on failure. Add one error middleware and drop the duplicated try/catch blocks.

### Test coverage is limited to three API test files

`api/test/` holds 257 lines across three files (`bulk-load.test.js`, `pub-code-api.test.js`, `soft-delete-repo.test.js`) run with `node --test`. The repository layer is the mongoose entity; the soft-delete test is named for it, but no coverage threshold or Sonar gate is configured in the repository. The frontend has Cypress end-to-end specs (four files) and no unit tests. No evidence was found of thresholds being lowered.

---

## CI/CD Pipelines

### Third-party actions pinned to mutable tags

The scan found 27 mutable-tag references across `scheduled.yml`, `.deploy.yml`, `pr-open.yml`, `merge.yml`, `analysis.yml` and `.tests.yml`: `actions/checkout@v7` (14 uses), `actions/setup-node@v7` (7), `actions/cache@v6` (3), `actions/upload-artifact@v7` (1) and `github/codeql-action/upload-sarif@v4` (2). In contrast, `bcgov/actions-openshift`, `aquasecurity/trivy-action`, `cypress-io/github-action`, `TriPSs/conventional-changelog-action`, `softprops/action-gh-release` and `shrink/actions-docker-registry-tag` are pinned to commit SHAs with version comments, and the actionlint image is pinned by digest. Pin the remaining references to SHAs and let Renovate (already configured via `renovate.json`) manage updates.

### Workflow inputs and secrets interpolated into shell in the deploy workflow

`.github/workflows/.deploy.yml` interpolates `${{ inputs.release_name }}`, `${{ inputs.directory }}`, `${{ inputs.values }}`, `${{ inputs.tag }}`, `${{ inputs.timeout-minutes }}` and `${{ inputs.params }}` directly into the `commands:` shell script. `inputs.params` is appended to the helm argument string and later expanded unquoted. Seven secrets are likewise written into the script text: `--set-string global.secrets.chesClientSecret=${{ secrets.CHES_CLIENT_SECRET }}` and the same for `DB_PWD`, `CHES_TOKEN_URL`, `CHES_CLIENT_ID`, `CHES_API_URL`, `EMAIL_RECIPIENTS` and `POWERBI_URL`. The script also runs `echo "PARAMS: $PARAMS"`, which prints the assembled string, including the CHES client secret and database password, to the job log. GitHub masks registered secrets, but masking is not a control (a value with special characters, or a transformation of it, bypasses it). Callers are internal workflows, which limits the injection exposure. Pass inputs and secrets through `env:` and reference `"$VAR"` in the script, build the argument list as a bash array, and delete the `echo "PARAMS: ..."` line.

### `secrets: inherit` in three caller jobs

`pr-open.yml` (line 48) and `merge.yml` (lines 75 and 98) call `.deploy.yml` with `secrets: inherit`, which grants the called workflow every repository and environment secret rather than the seven it uses. List `oc_token`, `EMAIL_RECIPIENTS`, `CHES_*`, `DB_PWD` and `POWERBI_URL` explicitly under `secrets:`.

### Positive controls

Every workflow sets top-level `permissions: {}` and grants per-job permissions. No workflow-level `env:` exports credentials. No `github.head_ref`, `github.ref_name` or `github.actor` is interpolated into a `run:` block. The `gh pr list` step in `scheduled.yml` uses `set -euo pipefail` and an `env:` variable for the title. The curl calls in `pr-open.yml` use `-fsS` and do not pass secrets as URL parameters. The API key reaches the crawler through an environment variable, not a URL or form field.

---

## Summary

| Area | Finding | Severity |
|------|---------|----------|
| Security | Write endpoints protected by one shared static API key, no identity or audit | High |
| Security | Unrestricted CORS and 50 MB body limit parsed before authentication | Medium |
| Security | Unauthenticated `/ip/trace` endpoint | Low |
| Frontend | Not TypeScript, no React Query, no shared auth or error handling per FDS standard | Medium |
| Frontend | No ErrorBoundary around routes | Medium |
| Frontend | Ad-hoc `fetch` without `response.ok` check; schema loaded from a mutable branch | Medium |
| Frontend | Debug `console.log` calls in components | Low |
| Backend | Node/Express/MongoDB outside the FDS Spring Boot standard | Medium |
| Backend | Bulk load is not transactional despite its documentation | High |
| Backend | Module-level mutable cache per replica; redundant block; unused `findById` handler | Low |
| Backend | No central error middleware; error messages e-mailed | Low |
| Backend | Thin test suite (257 lines API, no frontend unit tests, no coverage gate) | Medium |
| CI/CD | 27 third-party action references on mutable tags | High |
| CI/CD | Inputs and secrets interpolated into shell; `PARAMS` echoed to logs | High |
| CI/CD | `secrets: inherit` in three jobs | Medium |

---

## Recommended Next Steps

1. Rewrite the `.deploy.yml` command block to pass inputs and secrets through `env:`, build helm arguments as an array, and remove `echo "PARAMS: $PARAMS"`. This closes the secret-exposure and injection finding.
2. Replace `secrets: inherit` in `pr-open.yml` and `merge.yml` with explicit `secrets:` mappings.
3. Pin the 27 mutable action references to commit SHAs and let Renovate maintain them.
4. Make bulk load atomic using `bulkWrite` within a mongoose transaction, and persist the validated entity rather than the raw payload.
5. Replace the shared `X-API-KEY` with identity-based authentication for the crawler and cleanup utility, and move the check into shared middleware.
6. Scope the 50 MB body limit to the authenticated bulk-load route, restrict CORS to the frontend origin, remove `/ip/trace` and the `console.info` of database documents.
7. Add an `ErrorBoundary` to the route tree, move fetches into React Query hooks with `response.ok` checks, and remove debug logging.
8. Add a central Express error handler and set a coverage gate for the API; add unit tests for the frontend form-conversion logic.
9. Decide whether to align the stack with the FDS standard (Spring Boot, TypeScript) or document pubcode as an accepted exception.
