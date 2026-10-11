# Source-backed Engine Room roadmap

The [structured roadmap](roadmap.json) lists 40 historical original work units, explicitly mapped to GitHub PRs #1–40 by inspected PR metadata. It also lists the extension work currently in flight and separately flagged later work, with empty PR evidence until implemented.

Engine Room's latest `reconcilePortfolio` importer recognizes the `docs/roadmap.json` source and `github_prs` evidence. It uses GitHub's observed merge state and default-branch ancestry to calculate measured progress; proposed work is never marked delivered by enumeration alone.

The `origin` field keeps the 40-PR historical foundation distinct from extensions. The initial 40/40 represents **only the original pre-alpha core**, never application completeness, production readiness, verified service uptime, or security certification. Future extensions must be reviewed and mapped by PR evidence, not by assumption that PR number equals roadmap ordinal. Reconcile against live GitHub before displaying completion.

Website publication, on-premise desktop app operation, hosted relay availability, audited security and true online service deployments are separate operational statuses. Deploy and ingest status separately; do not infer them from any completed roadmap percentage.
