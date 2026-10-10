# Production-release acceptance gates

No public site, passing CI run, or merged roadmap can automatically change this Suite's maturity from **pre-alpha**.

Release candidates require documented, owner-approved evidence for:

1. **Protocol correctness:** selected exact-version E2EESA scopes, independent implementation review, threat-model review, interoperability, parser fuzzing and adversarial/session replay tests
2. **Cryptographic session properties:** reviewed forward-secret ratchet selection rather than bespoke primitives, explicit replay rejection and safe state recovery/rollback behavior
3. **Platform secret isolation:** working, tested OS/hardware key adapters or clearly scoped software-only release; device pairing and revocation with secure backup/recovery acceptance
4. **Secure delivery:** authenticated users/devices, ciphertext-only service design, no plaintext server logging, TLS and metadata disclosures, abuse controls and failure recovery
5. **Build and update assurance:** complete dependency/SBOM evidence, CI provenance, independent reproducible verification, signed artifacts and rollback-resistant software updates
6. **Client release usability:** UX threat review, permissions, accessibility, secure file handling, recovery and destructive-action confirmation, realistic support and incident response
7. **Operations:** independently probed service availability, release and deployment traceability, observed Engine Room freshness, key/privacy-safe telemetry and incident handling

For each gate, attach a reproducible evidence link, result revision, reviewer, and date. Anything unknown remains **pending**. Never display a green lock, "secure", "certified", or "production ready" based only on automated formatting/unit tests or a deployed informational page.

**Current position:** these acceptance gates are not completed. Users should experiment only with disposable test data.
