# Engine Room portfolio registration and monitoring

The `.exechub/project.yml` file follows Engine Room's controlled manifest schema. It declares a **historical, 40-PR development baseline**, not a claim that the entire Suite is complete, secure, or deployed.

- The 40 completed PRs form roadmap **version 1**. The explicit mapping is recorded in `.exechub/approved-pr-mapping.json`; GitHub merger timestamps, not PR numbering alone, are the completion evidence.
- The post-baseline development work (PR #41 onwards) is an **extension workstream**, not a reason to silently enlarge or reset the historical denominator. Any new *approved* plan should be versioned explicitly rather than editing the historical plan in place.
- Discovering this manifest requires Engine Room's connected GitHub App to have repository access, successful repository reconciliation and a functioning database. The manifest alone does not configure webhooks, Render, telemetry, scheduled sync or the live dashboard.
- The Suite is **pre-alpha**: currently implemented functionality includes the local Rust core and CLI, but not the desktop/mobile UX, forward-secret messenger, remote relay, OS keystore adapters or independently audited production readiness.
- The Suite is primarily a client-side encryption product. Never equate a public informational site being live with encrypted client services being deployed or operating correctly.

## Expected Engine Room signals

| Signal | Ground truth | Expected meaning |
| --- | --- | --- |
| Historical PR completion | GitHub merges #1–#40 | Engineering baseline only |
| Extension development | GitHub PRs after #40 | Separate outstanding roadmap |
| CI | GitHub Actions on default branch | Code checks, not a security audit |
| Product release | Signed release artifacts and audit record | Pending |
| Marketing/docs site | Site health response | Publication only |
| End-user services | Explicit production endpoints and synthetic tests | Pending |

## Reconciliation/runbook

1. Ensure the Engine Room GitHub App can see `neophilism/End-To-End-Everywhere-Suite`.
2. Reconcile GitHub repositories, PRs and approved manifests using Engine Room's production dashboard.
3. Confirm the Suite is in the portfolio with roadmap version 1 and **40 baseline units**. If progress shows unmapped units, attach the reviewed mapping; do not infer ordinal N means PR N.
4. Track additional PRs separately from baseline completion, including failures and unmerged work.
5. Show the Suite as **pre-alpha / not deployed** until platform services and release acceptance evidence independently justify another label.
