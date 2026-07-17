# Multi-Repo Code Quality Audits (action-repo-reporter)

This repository serves as a centralized, automated dashboard for code quality audits across our public repositories, using [GitHub Agentic Workflows (gh-aw)](https://github.com/github/gh-aw).

It runs a parallelized GitHub Actions workflow to audit repositories against the **Forest Digital Services (FDS) Stack Standard** (backend rules, React strict-mode frontend structures, and CI/CD security parameters).

## Active Reports

Browse the generated assessment reports directly in this repository:
*   📊 **actions:** [actions-code-quality-assessment.md](file:///home/derek/Repos/action-repo-reporter/reports/actions-code-quality-assessment.md) (source: `bcgov/actions`)
*   📊 **pubcode:** [pubcode-code-quality-assessment.md](file:///home/derek/Repos/action-repo-reporter/reports/pubcode-code-quality-assessment.md) (source: `bcgov/pubcode`)
*   📊 **quickstart-openshift:** [quickstart-openshift-code-quality-assessment.md](file:///home/derek/Repos/action-repo-reporter/reports/quickstart-openshift-code-quality-assessment.md) (source: `bcgov/quickstart-openshift`)

*Note: Reports are updated automatically every weekday morning via GitHub Actions.*

---

## Technical Architecture

The reporting engine uses a **Checkout-and-Audit** pipeline running in parallel using a GitHub Actions Matrix:

1.  **Orchestrator:** The [generate-reports.yml](file:///home/derek/Repos/action-repo-reporter/.github/workflows/generate-reports.yml) workflow runs at 8:00 AM Mon-Fri or when manually triggered.
2.  **Target Checkout:** For each target repository in the matrix, the runner clones the code into a subfolder (`./target_repo`).
3.  **Audit Execution:** The `gh-aw` agent executes the custom [fds-project-audit.prompt.md](file:///home/derek/Repos/action-repo-reporter/.github/workflows/fds-project-audit.prompt.md) prompt, using local file read tools to check files inside `./target_repo`.
4.  **Save:** The resulting assessment markdown report is moved to the `reports/` folder and pushed back to this dashboard branch.

---

## How to Add New Repositories

To expand the scope of audits to cover additional repositories:
1.  Open [.github/workflows/generate-reports.yml](file:///home/derek/Repos/action-repo-reporter/.github/workflows/generate-reports.yml).
2.  Append the target repository name to the `matrix.target_repository` list:
    ```yaml
    matrix:
      target_repository:
        - "bcgov/quickstart-openshift"
        - "bcgov/pubcode"
        - "bcgov/actions"
        - "org/your-new-repository" # Add your new repository here
    ```
3.  Commit and push the changes.
