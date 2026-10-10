# End-To-End Everywhere Suite: pre-alpha threat model

## Scope and security objective

This document describes **implemented local CLI use**, not future apps, hosted relays, browsers, calls, or mobile clients. The objective is confidentiality and integrity of locally prepared Capsule content between explicitly authenticated cryptographic endpoints while reducing plaintext access by transports. Cryptographic profiles follow exact E2EESA references but require further scoped conformance evidence.

## Assets and boundaries

- **Endpoint secrets:** local recipient private keys, signing keys, wrapping roots, credential inputs and unlocked ephemeral key material
- **User plaintext:** input files, edited notes, decrypted outputs, screen and clipboard state when future client surfaces exist
- **Trust decisions:** pinned contact fingerprints, key-change and revocation state, separately retained archive anchors
- **Transport data:** signed encrypted binary/armored Capsules and small local handoff encodings; public recipient hints, lengths, signer identity/context and routing metadata can remain visible
- **Operations:** local process, OS storage and backup, OS credential entry, compiler/build pipeline and distribution

## Adversaries

Untrusted message carrier, replacement or reordered ciphertext, malicious contact-card distributor, unauthorized local file observer, malicious recipient, compromised relay or server, stale/restored archive, lost endpoint, compromised host, package supply-chain attacker. The last three are **not fully mitigated** by the current pre-alpha implementation.

## Invariants the current code attempts to enforce

- Decrypt only at the authorized endpoint, never in the relay
- Importing a card does not mark it verified; compare fingerprints independently
- Reject revoked, unverified or changed recipient keys when encrypting or authenticated-opening
- Enforce signed context and separately pinned sender on required-signature workflows
- Treat ciphertext outputs and private local state as exclusive/private Unix files; do not overwrite a path
- Zeroize unlocked sensitive buffers where implemented; lock after an inactivity deadline
- Reject malformed Capsules, oversized inputs, unknown versions and unsupported suites before plaintext output

Those are **implementation goals and tested behaviors**, not exhaustive formal guarantees. Deployment-specific threats must be reassessed for every new client and platform.

## Explicit non-goals and unresolved threats

The current envelopes are not ratcheted sessions. They do not provide session forward secrecy, post-compromise security or replay prevention. Metadata is not globally anonymous. Password-only backups may be replayed, and local backups may retain plaintext. Hardware-isolated storage interfaces are not functioning OS adapters. A self-signed public card cannot establish identity without independent verification.

## Validation and release plan

Threat-model each surface separately, test malicious ciphertext and stale state across host platforms, fuzz all untrusted parsers, conduct dependency and memory-safety review, run independent protocol/security review, obtain scoped conformance evidence, add signed reproducible release provenance, and test incident response/backup recovery before any production claim. Hosted services require separately validated auth, TLS, storage/retention policy, abuse controls and outage monitoring.
