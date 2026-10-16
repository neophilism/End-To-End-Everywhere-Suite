# Static informational site deployment

The `site/public` directory is a **static documentation/status page only**, with no cryptographic keys, authentication, user data, accounts, encrypted message processing or server-side E2EE.

`render.yaml` contains a Render Blueprint for a static web service `e2ee-suite-information`, with conservative response headers, source-based pre-alpha messaging and CI-gated deploys. A passing `scripts/check-public-site.py` gate does not establish cryptographic readiness.

## Activation

After confirming the intended Render workspace, create the Blueprint/static site from this repository on `main` and verify the resulting provider-assigned URL. The live site should be observed separately in Engine Room as a **documentation site**. Do not register static site uptime as messenger or encryption-service availability.

This commit does **not** create the Render service, authorize any workspace, configure monitoring secrets, or prove a live URL. A public docs site can be released earlier than the actual encrypted apps; production applications require their applicable architecture, source/security review, testing and operational release checks. Independent human audits remain deferred under [the owner policy](../AGENTS.md).


## Deployment observation — 2026-10-16

The authorized workspace is Phillip's workspace (`tea-db23jkks728c73av263g`). Creating `e2ee-suite-information` from the public repository's `main` branch with the existing static claim-check build was refused by Render: **Hobby Tier is limited to 25 services**. No Suite service or live URL was created. Existing services were left intact; no paid upgrade was selected.

The source remains ready for static deployment when workspace capacity permits. Keep the Blueprint response headers when configuring the service. The HTML also carries a restrictive script-free meta CSP, but that does not supply the Blueprint's HTTP frame-ancestor header. Site publication remains a separate observation from encrypted application availability.
