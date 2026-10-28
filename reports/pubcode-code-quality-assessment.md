# Technical Review — pubcode

**Project:** bcgov/pubcode — BCGov Public Code Metadata Tool
**Date:** 2026-08-05
**Prepared by:** Paulo Cruz
**Audience:** Director and above

---

## Executive Summary

The pubcode project is a Node.js/Express API backed by MongoDB and a React/Vite frontend. It does not follow the FDS Spring Boot stack standard — the backend is entirely JavaScript with no JVM components — which places it outside the FDS reference baseline on the backend. That gap is acknowledged here, and findings are evaluated against its own stack's best practices and the FDS frontend and CI/CD standards where they apply.

Three findings carry immediate operational risk. First, the MongoDB connection URI is assembled by string concatenation and logged to the application log on every startup, exposing the database password in plaintext to any log aggregation system. Second, the `softDeleteRepo` handler does not send any HTTP response when an exception is raised, leaving the caller indefinitely waiting. Third, the deploy workflow interpolates secret values — including `CHES_CLIENT_SECRET`, `DB_PWD`, and six others — directly into the `helm upgrade` command string inside a `run:` block, where they appear in the workflow's process list and runner logs. Together these three issues represent a credential exposure path, a reliability gap in the delete path, and a CI secrets-leakage risk.

The remaining findings are maintenance debt: the absence of React Query or any caching layer in the frontend, no ErrorBoundary in the route tree, `secrets: inherit` propagation across two caller workflows, and several mutable action version pins. None of these are acute, but each raises the cost of future changes and the surface area for regressions.

---

## Security

### Database credentials logged on every startup

In `api/src/db/database.js` the connection URI is built by template literal and passed directly to `logger.info` before the connection is made:

```js
const connectionUri = `(redacted)
logger.info(`connecting to mongodb on url: ${connectionUri}`);
```

Any log aggregation system (Splunk, OpenShift logging, CloudWatch) will receive and store the database password in plaintext. The fix is to log only the host and port — or to use a parsed URL object and omit the credential component entirely.

### Secrets interpolated as shell strings in the deploy workflow

In `.github/workflows/.deploy.yml`, eight secrets are expanded as `${{ secrets.* }}` expressions directly inside the `helm upgrade` command string within a `run:` block:

```yaml
PARAMS="${{ inputs.release_name }} \
  --set-string global.secrets.chesClientSecret=${{ secrets.CHES_CLIENT_SECRET }} \
  --set-string global.secrets.databaseAdminPassword=${{ secrets.DB_PWD }} \
  ...
```

GitHub masks known secret values in logs, but the values are still present in the shell process arguments visible to other processes on the runner and in runner debug output. The correct pattern is to assign each secret to an `env:` variable at the step level and reference `$ENV_VAR` in the shell command. This keeps the values out of the argument list.

### API key validated by inline string comparison, no constant-time check

The `POST /bulk-load` and `DELETE /:repo_name` routes validate the `X-API-KEY` header with a plain `===` comparison:

```js
if (req.header("X-API-KEY") && req.header("X-API-KEY") === process.env.API_KEY) {
```

JavaScript string equality is not guaranteed to be constant-time in all V8 execution paths. For an internal bulk-load key this is a low-probability risk, but the comparison should use a constant-time utility (e.g., `crypto.timingSafeEqual`) to eliminate the theoretical timing side-channel.

---

## Frontend

### No ErrorBoundary anywhere in the route tree

The entire application renders inside `<App />` with no `ErrorBoundary` wrapping any route subtree. An unhandled render error in any component — `Dashboard`, `FormComponent`, `EditForm`, `YamlDisplay` — will unmount the entire application and show a blank page with no user-facing explanation. React's `ErrorBoundary` (class component or a library wrapper) should wrap the route group rendered by `<AppRoutes />`.

### No shared auth context; application has no authentication layer

The frontend has no `AuthContext`, no `useAuth` hook, no `ProtectedRoute`, and no token management of any kind. All routes are publicly accessible. Whether this is intentional (the tool is intended to be open) or an omission is not stated in the source. If any route is meant to be restricted, the mechanism does not exist and must be built from scratch.

### No React Query; data fetching is ad-hoc fetch inside useEffect

The frontend uses bare `fetch` calls inside `useEffect` hooks — visible in `FormComponent.jsx` — with no shared loading/error state, no deduplication, no stale-while-revalidate, and no cache invalidation. The module-level `PUB_CODES` array in `api/src/services/cache-service.js` mirrors this pattern on the server side. React Query (or equivalent) should be introduced to give the frontend consistent loading, error, and refetch semantics.

### `CI=false` absent; build configuration is clean

The `frontend/package.json` build script is `"build": "vite build"` with no `CI=false` override. No file-level `eslint-disable` directives were found in frontend source files. These aspects are compliant with the FDS standard.

---

## Backend

### `softDeleteRepo` does not respond on exception

The `softDeleteRepo` handler catches exceptions with `console.error` but does not send any response:

```js
} catch (e) {
  console.error(e);
}
```

Any error on the delete path leaves the HTTP connection open until timeout. The caller (the scheduled `remove-deleted-pubcode` utility) will hang on that request. The catch block must send a `500` response.

### `bulkLoad` fires and forgets the insert/update work

The `bulkLoad` handler dispatches `insertOrUpdate` without `await` and immediately returns `200 OK`:

```js
insertOrUpdate(payload, notInsertedArray).catch(async (error) => { ... });
res.status(200).json({});
```

The caller has no way to know whether the bulk load succeeded. Validation errors and database failures occur asynchronously after the `200` is already sent. The endpoint should either await the operation and return a meaningful status, or implement a job-queue pattern and expose a status endpoint.

### No authentication on read endpoint; write protection is ad-hoc middleware

`GET /pub-code` is publicly accessible with no authentication. Write operations (`POST /bulk-load`, `DELETE /:repo_name`) are guarded by an inline API key check duplicated across both route handlers rather than extracted as shared middleware. This duplication means any future endpoint that needs protection must remember to add the same check manually.

### Stack is JavaScript/Node.js, not FDS Spring Boot standard

The backend is Express 5 + Mongoose, not Spring Boot with `spring-boot-starter-parent`. There is no JPA, no Lombok, no `@Transactional`, no OAuth2 resource server. If this project is required to converge with the FDS standard, a full backend rewrite is needed. If it is intentionally a separate stack, that decision should be documented explicitly so the project is not evaluated against the JVM baseline in future audits.

---

## CI/CD Pipelines

### `secrets: inherit` propagated in two caller workflows

Both `merge.yml` and `pr-open.yml` call the deploy workflow with `secrets: inherit`:

```yaml
uses: ./.github/workflows/.deploy.yml
secrets: inherit
```

`secrets: inherit` passes every secret in the caller's context to the called workflow, including secrets the called workflow does not need. The deploy workflow explicitly names only eight secrets; all others should not be forwarded. Each `secrets:` block should enumerate only the secrets the called workflow actually consumes.

### Several actions pinned to mutable semver tags

The following `uses:` references use mutable version tags rather than immutable commit SHAs:

- `actions/checkout@v7` (five occurrences across workflows)
- `actions/setup-node@v7` (three occurrences, `scheduled.yml`)
- `actions/cache@v6` (three occurrences, `scheduled.yml`)
- `actions/upload-artifact@v7` (`.tests.yml`)
- `github/codeql-action/upload-sarif@v4` (`analysis.yml`)

Actions pinned by semver tag can be silently updated by the action publisher. All external actions should be pinned to a full commit SHA with the version noted in a comment, as is already done for `aquasecurity/trivy-action`, `shrink/actions-docker-registry-tag`, `bcgov/actions/pr-description-add`, and `bcgov/actions/builder-ghcr`.

### `github.actor` interpolated directly into a shell `run:` block

In `scheduled.yml`, the `validate-ministry-list` job writes `github.actor` directly into the shell:

```yaml
env:
  ACTOR: ${{ github.actor }}
run: |
  git config --local user.name "$ACTOR"
```

This particular instance is safe because the value is assigned to an `env:` variable before shell use. However, `.deploy.yml` interpolates `${{ inputs.release_name }}`, `${{ inputs.directory }}`, `${{ inputs.tag }}`, `${{ inputs.params }}`, and `${{ github.repository }}` directly into the shell command string. Workflow inputs are caller-controlled and can contain shell metacharacters. These should be assigned to step-level `env:` variables before use.

### Scheduled crawler uses `oc login` with token in command argument

In `scheduled.yml`:

```yaml
run: |
  oc login --token=${{ secrets.OC_TOKEN }} --server=${{ vars.OC_SERVER }}
```

The token is expanded as a `${{ }}` expression directly in the shell command, placing it in the process argument list. It should be exported as a step-level environment variable and referenced via `$OC_TOKEN`, or the `action-oc-runner` action should be used for the login step instead of the inline command, consistent with the deploy workflow.

---

## Summary

| Area | Finding | Severity |
|------|---------|----------|
| Security | Database password logged in plaintext on startup | Critical |
| CI/CD | Eight secrets expanded directly in `helm upgrade` shell string | High |
| Backend | `softDeleteRepo` sends no response on exception | High |
| Backend | `bulkLoad` fires and forgets; `200 OK` returned before work completes | High |
| CI/CD | `secrets: inherit` in `merge.yml` and `pr-open.yml` | High |
| CI/CD | Five action families pinned to mutable semver tags | High |
| CI/CD | Workflow inputs interpolated into shell strings without env assignment | High |
| Security | API key compared with plain `===`, not constant-time | Medium |
| Frontend | No `ErrorBoundary` wrapping route subtrees | Medium |
| Frontend | No React Query; bare `fetch` in `useEffect` with no shared cache | Medium |
| Backend | No authentication on public `GET /pub-code` read endpoint | Medium |
| Backend | API key guard duplicated across two route handlers | Low |
| Backend | Stack is Node.js/Express, not FDS Spring Boot standard | Low (informational) |

---

## Recommended Next Steps

1. **Remove the `logger.info` call that logs the MongoDB connection URI** in `api/src/db/database.js`. Log only the host and port. This closes the credential exposure on startup immediately without any architectural change.

2. **Assign all `secrets.*` values to step-level `env:` variables in `.deploy.yml`** and replace the `${{ secrets.* }}` interpolations in the `helm upgrade` command with `$ENV_VAR` references. This prevents secret values from appearing in the shell process argument list and in any runner debug output.

3. **Add a `500` response in the `softDeleteRepo` catch block** to close the hanging connection issue. The fix is a single `res.status(500).json({ message: "Internal server error" })` line.

4. **Await `insertOrUpdate` in `bulkLoad`** and return a meaningful HTTP status reflecting the result, or explicitly document the fire-and-forget contract and expose a status mechanism. The current `200 OK` before any work is done prevents callers from detecting failures.

5. **Replace `secrets: inherit` in `merge.yml` and `pr-open.yml`** with explicit `secrets:` blocks that name only the eight secrets consumed by `.deploy.yml`. This bounds the blast radius of any workflow compromise.

6. **Pin all mutable action tags to full commit SHAs.** Run `gh api /repos/{owner}/{repo}/git/refs` or use the GitHub UI to obtain the SHA for each of: `actions/checkout@v7`, `actions/setup-node@v7`, `actions/cache@v6`, `actions/upload-artifact@v7`, `github/codeql-action/upload-sarif@v4`. Add the version as a comment beside each SHA.

7. **Assign workflow inputs to step-level `env:` variables in `.deploy.yml`** before use in the shell body. Specifically: `inputs.release_name`, `inputs.directory`, `inputs.tag`, `inputs.params`, and `github.repository`. This eliminates the shell injection vector from caller-controlled values.

8. **Wrap `<AppRoutes />` in an `ErrorBoundary`** in `App.jsx`. This is a one-component addition that prevents any render failure from blanking the entire page.