# Security policy

## Current support status

**Pre-alpha engineering project. No production security support promise.**
The source currently provides a local Rust encryption core and a stateful CLI. It has no independently verified production conformance or external cryptographic audit. Do not use it to protect sensitive personal, medical, legal, or business communications.

All published build artifacts before an explicit audited release are engineering test artifacts, not signed or certified security products. Passing automated CI does not imply security certification.

## Private vulnerability reporting

If GitHub's **Report a vulnerability** feature is available on this repository's Security tab, prefer that confidential channel. Do not publish exploit details, credentials, private keys, plaintext, or exploit data in public Issues, Pull Requests or discussion threads.

If private reporting is unavailable, contact the repository maintainers privately using a mutually authenticated channel, or open a nonsensitive public coordination issue without technical exploit details. No response SLA or bounty program is promised.

## Known security boundaries

- The current signed Capsule workflow has **no forward-secret sessions, post-compromise recovery, or replay protection**.
- Encrypted archives using password-only restore **lack an independent rollback floor**. Anchors must be retained in a separate trusted system to establish rollback detection.
- A healthy CI or live documentation website does **not** attest that secure messaging infrastructure is deployed.
- Device pairing interfaces, OS hardware-backed keys, secure synchronization, standalone desktop/mobile clients and independent production assurance remain incomplete.
- Local plaintext inputs, decrypted output files, swap, indexing and filesystem backups remain in the local host's trust boundary.

See [threat model](docs/threat-model.md), [release gates](docs/release-gates.md), and the separately maintained [E2EESA Standard](https://github.com/neophilism/End-To-End-Everywhere-Security-Architecture-Standard).
