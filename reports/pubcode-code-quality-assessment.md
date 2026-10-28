# Technical Review — pubcode

**Project:** BC Gov Public Code (pubcode) — registry of `bcgovpubcode.yml` metadata, with API, form frontend and OpenShift deployment
**Prepared by:** FDS Code Quality Auditor (Automated)
**Audience:** Director and above

---

## Executive Summary

pubcode is not built on the FDS stack. The API is Node.js 20+/Express 5 with Mongoose on MongoDB (about 990 lines across 15 source and test files), and the frontend is a 670-line plain JavaScript (JSX) Vite application with no TypeScript, no React Query and no auth context. There is no `pom.xml`, so the Spring Boot, JPA, Lombok and OAuth2 resource-server criteria cannot be met; they are reported as a structural divergence rather than as individual defects. The codebase is small and generally clean. Its risk is concentrated in the deployment pipeline.

Three findings carry immediate operational risk. First, the reusable deploy workflow interpolates workflow inputs, including a pull-request branch name, directly into a shell script that runs with cluster credentials, and the same script prints the assembled helm parameters, which embed six secrets. Second, all three deployment workflows use `secrets: inherit`, so called workflows receive every repository secret. Third, the write endpoints are protected by a single shared static API key with no per-caller identity, and an unauthenticated diagnostic route and a 50 MB body limit sit in front of it.

The remaining findings are maintenance debt: 27 third-party action references pinned to mutable tags, a module-level mutable cache, no frontend unit tests, no coverage gate, and dead code in the router and routes file.

---

## Security

### Write endpoints rely on one shared static API key

`POST /api/pub-code/bulk-load` and `DELETE /api/pub-code/:repo_name` are guarded by `isValidApiKey`, which compares the `X-API-KEY` header to `process.env.API_KEY` using `crypto.timingSafeEqual`. The comparison is implemented correctly and fails closed when the key is unset. The weakness is the model: one long-lived secret, no rotation mechanism, no per-caller identity and no audit trail of who deleted a record. The rate limiter is global (100 requests per minute per IP) rather than tighter on write routes, and `cors()` is applied with no origin restriction. Move to the organisation's OIDC/JWT service-account pattern, or at minimum support two concurrent keys for rotation and log the caller on writes.

### Unauthenticated diagnostic route and oversized request bodies

`router.get("/ip/trace", ...)` returns `request.ip` to anyone and has no operational purpose in production. `app.js` sets `express.json({ limit: "50mb" })` and the same limit for urlencoded bodies; these parsers run before the API key check, so unauthenticated callers can make the server buffer and parse 50 MB payloads per request. Remove `/ip/trace`, and lower the limit (or apply the large limit only after authentication on `/bulk-load`).

### Sensitive records and identifiers written to logs

`softDeleteRepo` calls `console.info(pubcodeEntityFromDB)`, dumping the full database document to stdout, bypassing the Winston logger. `ches-service.js` and `connection.js` also use `console.log` / `console.error(SERVICE, e)`, where an Axios error object can include request headers (the OAuth bearer token). `database.js` logs the connection URI, which is safe because credentials are passed in options (the file comments this). Replace the `console.*` calls with the logger and log only identifiers and error messages.

### Error content emailed as raw HTML

In `pub-code-service.js` the bulk-load error path emails `error.message` and `repoWithErrors.join(",")` inside `<p>` tags without escaping. Repository names originate from the submitted payload, so an authenticated caller can inject HTML into notification email. Escape values before building the HTML body.

### No hardcoded credentials or TLS bypasses found

The scanner found no committed credentials and no disabled certificate validation. `DB_USER` and `DB_PWD` default to the literal `"default"` in `database.js`; this works only against a local database but would silently run with weak credentials if the variables were missing in a deployed environment. Fail startup when these are unset outside local development.

---

## Frontend

### Platform divergence: plain JavaScript, no shared auth or data layer

`frontend/package.json` has React 19 and `react-router`, with no TypeScript (`vite-env.d.ts` is the only `.ts` file), no `@tanstack/react-query`, no `ErrorBoundary` and no auth context. The application is a public form with no login, so the absence of `ProtectedRoute` and `useAuth()` is by design and not a defect. Data fetching is ad hoc: `EditForm.jsx` and `FormComponent.jsx` call `fetch` directly inside event handlers and effects, with `console.error` for failures. Adopt TypeScript strict mode and React Query when the next feature work is scheduled.

### No error boundary around route subtrees

`routes/index.jsx` renders all six routes with no `ErrorBoundary`. A render exception in the form (`@rjsf`) or Power BI embed unmounts the whole application to a blank page. Wrap `<Routes>` in a boundary with a fallback.

### Form state passed through router state, not storage

No use of `localStorage` or `sessionStorage` was found, and no tokens or JWT payloads are logged. Form data moves between `/edit`, `/form` and `/yaml` through `navigate(..., { state })`. `LeftDrawer.jsx` logs the click event with `console.log(event)` and `FormComponent.jsx` logs `typeof yaml`; these are debug leftovers and should be removed.

### Outbound fetches to user-supplied URLs

`EditForm.jsx` rewrites a user-entered GitHub URL to `raw.githubusercontent.com` and fetches it, but only checks that the string contains `bcgovpubcode.yml`. A URL such as `https://example.com/?bcgovpubcode.yml` is fetched as given from the browser. Impact is limited to the user's own browser, but validate the host against `github.com` / `raw.githubusercontent.com` before fetching.

### Runtime config and environment guard

`env.js` merges `import.meta.env` with `window.config`, supplied by Caddy in production. No `process.env.NODE_ENV` guards exist, and there is no `CI=false` in the build. The Dockerfile `HEALTHCHECK` uses `curl -f http://localhost/:3001/health`; the URL is malformed (`/:3001`) and the final Caddy image is Alpine without `curl` installed, so the check cannot succeed. Correct to `http://localhost:3001/health` using `wget` or install `curl`.

---

## Backend

### Platform divergence from Spring Boot

There is no Maven build, Spring Boot parent, JPA, Lombok, `@Transactional` or OAuth2 resource server. The comparable concerns are handled as follows: Mongoose schema validation replaces entity constraints, and the API key middleware replaces JWT validation. The equivalent FDS-standard findings are therefore not applicable; migration would be a rewrite of roughly 500 lines of API logic rather than a refactor.

### Bulk load is not atomic

The doc comment on `insertOrUpdate` states it will "delete and add all these new in a single transaction", but the code runs `findOneAndReplace` once per record followed by `insertMany` for the remainder, with no Mongo session or transaction. A failure midway leaves the collection partially updated, and each record costs one round trip (sequential `await` in a loop). Use a MongoDB session transaction or `bulkWrite` with `upsert`, and correct the comment. Also `findOneAndReplace` is passed the raw `pubcode` object rather than the validated `entity`, so unknown fields bypass the schema's strict mode only if the replace path does not apply it; pass validated data.

### Duplicated error handling and unbounded in-memory cache

`bulkLoad` and `readAll` each repeat a try/catch that emails `error.message` to recipients. `readAll` serves `cache-service.js`, whose module-level `let PUB_CODES = []` is replaced on a scheduled refresh. This is a legitimate single-process cache, but each replica holds its own copy and a failed refresh is only logged, so replicas can serve stale data indefinitely with no staleness metric. Extract an error-notification helper and expose cache age on `/metrics`.

### Dead code and unrouted handlers

`findById` is exported but not mounted in `pubcode-router.js`, so it is unreachable. The `/health` handler returns a document count rather than a status, and runs a `countDocuments` against the database on every probe. `EMAIL_RECIPIENTS` is read once at module load, so changes need a restart. `cache-service.js` guards `PUB_CODES.length > 0` before clearing a value that is reassigned on the next line. Remove the unrouted handler and redundant branch.

### Global error handling is minimal

`app.js` has a 404 handler returning HTML but no Express error-handling middleware. Body-parser errors (malformed JSON, oversized payload) fall to Express's default handler, which returns an HTML page and, outside `NODE_ENV=production`, a stack trace. Add a JSON error middleware. Service functions already return generic "Internal server error" messages, so internals are not exposed through those paths.

---

## CI/CD Pipelines

### Script injection and secret echo in the deploy workflow

`.deploy.yml` builds its helm command inside the `commands:` input with direct `${{ }}` expansion: `${{ inputs.params }}`, `${{ inputs.release_name }}`, `${{ inputs.directory }}` and `${{ inputs.tag }}` are all substituted into shell text. In `pr-open.yml` the caller passes `--set-string global.env.VITE_SCHEMA_BRANCH=${{ github.event.pull_request.head.ref }}` unquoted through `params`. A branch name containing shell metacharacters (Git permits `;`, `$()` and backticks) executes in a step that holds the OpenShift token and the deployment secrets. The same step assembles `PARAMS` with `${{ secrets.CHES_CLIENT_SECRET }}`, `${{ secrets.DB_PWD }}` and four others, then runs `echo "PARAMS: $PARAMS"`, writing them to the job log (GitHub masks exact secret strings but not derived or encoded values). Pass inputs and secrets through `env:` and reference `"$VAR"`, remove the `echo "PARAMS"`, and supply secrets with `--set-file` or a values file instead of a command line.

### `secrets: inherit` on three deploy calls

`pr-open.yml` (line 48) and `merge.yml` (lines 75 and 98, TEST and PROD) call `.deploy.yml` with `secrets: inherit`. The called workflow uses `oc_token`, `EMAIL_RECIPIENTS`, `CHES_TOKEN_URL`, `CHES_CLIENT_ID`, `CHES_CLIENT_SECRET`, `CHES_API_URL`, `DB_PWD` and `POWERBI_URL`. List these explicitly under `secrets:`. The `pull_request` trigger also deploys on every PR, so a PR from a branch in the same repository has access to the deployment path; restrict by actor or require an approved environment for PR deploys.

### Actions pinned to mutable tags

The scanner found 27 `uses:` references on mutable tags: `actions/checkout@v7` (13), `actions/setup-node@v7` (6), `actions/cache@v6` (3), `actions/upload-artifact@v7` (1) and `github/codeql-action/upload-sarif@v4` (2), plus a Docker image that is digest-pinned and therefore compliant. All `bcgov/actions`, `bcgov/actions-openshift`, `shrink`, `softprops` and `TriPSs` references are already SHA-pinned with a version comment, so only first-party GitHub actions need conversion. Pin to SHAs and let Renovate (already configured) maintain them.

### Positive controls

Every workflow sets `permissions: {}` at the top level and grants per-job permissions. No secrets are set at workflow `env:` level, none are passed in URLs or curl form fields, and the one inline shell block (`Smoke test`) uses `set -euo pipefail`. No standalone `.sh` scripts exist. Container images are tracked by PR number and promoted to `prod` only after PROD deploy succeeds, and the release is created last so failed deploys leave no tag.

### Pipeline rollback behaviour

`helm status ... | jq .info.status || true` tolerates a missing release but also hides real `helm`/`jq` failures, and the `helm rollback` path is based on a regex match against the status. Validate the exit code of `helm status` separately from "release not found".

---

## Testing and Observability

### Test coverage is thin and not enforced

The API has three Node test files (about 257 lines) using `node --test`; they cover routes, bulk load and soft delete. They do not exercise `ches-service.js`, `cache-service.js`, the scheduler or the entity validation beyond what the routes touch. No coverage tool (`c8`, `nyc`, Sonar) is configured in any `package.json` or workflow, so no threshold exists to lower. The frontend has Cypress end-to-end specs for four pages but no unit tests, and no test covers error states such as a failed schema fetch. Add a coverage gate to the API test run and unit tests for the URL-rewrite logic in `EditForm.jsx`.

### Metrics endpoint is unauthenticated

`/metrics` exposes default Prometheus process metrics without authentication on the public route. Restrict it at the ingress or network policy (`knp.yaml` exists) so only the monitoring namespace can reach it.

---

## Summary

| Area | Finding | Severity |
|------|---------|----------|
| CI/CD | Deploy workflow interpolates inputs (incl. PR branch name) into shell with cluster credentials | High |
| CI/CD | Deploy script echoes helm parameters containing six secrets | High |
| CI/CD | `secrets: inherit` on three deploy calls | High |
| CI/CD | 27 first-party actions pinned to mutable tags | Medium |
| Security | Single shared static API key guards all writes | Medium |
| Security | Unauthenticated `/ip/trace`; 50 MB body parsing before auth | Medium |
| Security | `console.*` logging of DB documents and Axios errors | Medium |
| Security | Unescaped values in error emails | Low |
| Security | `"default"` DB credential fallbacks | Low |
| Backend | Bulk load not transactional despite documentation | Medium |
| Backend | No JSON error middleware; HTML/stack traces on parse errors | Low |
| Backend | Dead handler, duplicated error handling, per-replica cache without staleness metric | Low |
| Backend | Not on the FDS Spring Boot stack | Medium |
| Frontend | Plain JS, no TypeScript, no React Query | Medium |
| Frontend | No ErrorBoundary on routes | Medium |
| Frontend | User-supplied URL fetched without host validation | Low |
| Frontend | Malformed Dockerfile HEALTHCHECK with missing `curl` | Medium |
| Frontend | Debug `console.log` leftovers | Low |
| Testing | No coverage gate; no frontend unit tests | Medium |
| Observability | `/metrics` exposed without authentication | Low |

---

## Recommended Next Steps

1. Rewrite `.deploy.yml` so every `${{ }}` value goes through `env:` and is referenced as a quoted shell variable, remove `echo "PARAMS"`, and pass secrets by file; this closes the injection and secret-logging findings.
2. Replace `secrets: inherit` with explicit `secrets:` mappings in `pr-open.yml` and `merge.yml`, and put PR deploys behind a protected environment.
3. Remove `/ip/trace`, lower the body-size limits, add a JSON error middleware, and restrict `/metrics` at the network layer.
4. Pin the 27 first-party action references to commit SHAs; Renovate will keep them current.
5. Replace `console.*` calls with the logger, drop the full-document log in `softDeleteRepo`, and escape values in notification email.
6. Make bulk load transactional with `bulkWrite` or a Mongo session, and fix the misleading comment.
7. Add an `ErrorBoundary` to the route tree, validate the host in `EditForm.jsx`, and fix the frontend `HEALTHCHECK`.
8. Introduce API and frontend coverage thresholds and unit tests for the URL-rewrite, cache and email code.
9. Decide whether to migrate the API to Spring Boot and the frontend to TypeScript with React Query; this is a rewrite-scale effort, and the decision should be explicit rather than left as drift.
