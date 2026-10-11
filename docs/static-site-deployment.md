# Static informational site deployment

The `site/public` directory is a **static documentation/status page only**, with no cryptographic keys, authentication, user data, accounts, encrypted message processing or server-side E2EE.

`render.yaml` contains a Render Blueprint for a static web service `e2ee-suite-information`, with conservative response headers, source-based pre-alpha messaging and CI-gated deploys. A passing `scripts/check-public-site.py` gate does not establish cryptographic readiness.

## Activation

After confirming the intended Render workspace, create the Blueprint/static site from this repository on `main` and verify the resulting provider-assigned URL. The live site should be observed separately in Engine Room as a **documentation site**. Do not register static site uptime as messenger or encryption-service availability.

This commit does **not** create the Render service, authorize any workspace, configure monitoring secrets, or prove a live URL. A public docs site can be released earlier than the actual encrypted apps; production applications require separate architecture, audits and release gates.
