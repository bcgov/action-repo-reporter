Audit of bcgov/pubcode completed. Full report: `reports/pubcode-code-quality-assessment.md`.

**High:** shared static API key on write endpoints; default credentials in docker-compose and Helm values; `secrets: inherit` on 3 workflow calls (incl. prod); 29 action refs not SHA-pinned.
**Medium:** Node/Express/Mongoose and JS rather than FDS stack; no ErrorBoundary/React Query; non-atomic bulk load; per-replica cache; secrets interpolated in `run:`; no frontend unit tests.
**Low:** debug logging, no global error handler, dead code.