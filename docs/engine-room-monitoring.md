# Engine Room portfolio registration and monitoring

The active PR plan is [registry/prs.json](../registry/prs.json), governed by [the shared registry contract](../registry/PR_FORMAT.md). It contains **61 approved units**. The `.exechub/project.yml` file and its mapping preserve a **historical 40-PR development baseline**; that baseline does not establish full product completion, security or deployment.

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
| Product release | Applicable implementation/tests, signed artifacts, source-review and operational evidence | Pending; independent human review separately deferred |
| Marketing/docs site | Site health response | Publication only |
| End-user services | Explicit production endpoints and synthetic tests | Pending |

## Reconciliation/runbook

1. Ensure the Engine Room GitHub App can see `neophilism/End-To-End-Everywhere-Suite`.
2. Reconcile GitHub repositories, PRs and approved manifests using Engine Room's production dashboard.
3. Confirm the portfolio reads the **61 approved canonical units** from `registry/prs.json` through `registry/pr-contract.mjs`. Preserve the 40 baseline units as historical evidence. Do not read the retired `registry/roadmap.json` or infer ordinal N means PR N.
4. Resolve current PR state from live GitHub. `contributingPrs` and `priorEvidencePrs` remain partial/historical evidence and cannot mark a complete unit by themselves. Keep failures, unmerged work and operational acceptance visible.
5. Show the Suite as **pre-alpha / not deployed** until platform services and release acceptance evidence independently justify another label.
