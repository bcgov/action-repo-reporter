Audit of bcgov/pubcode completed. Full report: `reports/pubcode-code-quality-assessment.md` (workflow run 39221544949).

Headline findings:
- **High:** shared static API key guards write endpoints; hardcoded/default credentials in `docker-compose.yml` and Helm values; `secrets: inherit` on 3 workflow calls (including prod deploy); 27 GitHub-owned action refs on mutable tags.
- **Medium:** stack differs from FDS (Node/Express/Mongoose, JS not TS); no frontend error boundary or React Query; non-atomic bulk load; `OC_TOKEN` interpolated into `run:`; no frontend unit tests.
- **Low:** debug logging, dead code, module-level cache, unvalidated user URL fetch.

Prioritised next steps: rotate and remove committed credentials, replace `secrets: inherit` with explicit secrets, SHA-pin actions, harden API key middleware.