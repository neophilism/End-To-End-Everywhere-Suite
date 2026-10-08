# Core runtime contract

Application surfaces do not choose algorithms directly. They request operations from the core runtime under a version-pinned E2EESA profile set.

The runtime must:

- reject floating profile versions;
- reject conflicting versions of one profile;
- fail closed when an operation requires application E2EE but only transport protection is present;
- preserve the authorized-endpoint plaintext boundary;
- expose security decisions in a form higher-level clients can translate into user-visible errors;
- keep profile selection independent from UI and transport code.

PR 2 establishes these contracts. Concrete cryptographic providers and platform bindings are subsequent work.
