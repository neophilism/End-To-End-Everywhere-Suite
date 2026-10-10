# Unauthenticated local CLI capability inventory

Use `e2ee --capabilities-json` to read a small **non-secret** machine-readable document without creating or unlocking a local identity. It never accesses private archives, accesses the network, or prompts for credentials. The output states implemented features and explicitly false capabilities (no network delivery, native GUI, forward-secret sessions, post-compromise security, native platform keystore or replay protection).

The inventory can be consumed by a future desktop GUI or local diagnostics system. It is deliberately a static **implementation-capability claim** and not a device health probe, independent audit, conformance certificate, or indication of a running online service. Neither security-critical code nor external monitoring should infer the presence of encryption-session security properties from a successful CLI invocation.

Current schema version is `1`. Consumers should reject unrecognized schema versions and unknown fields as appropriate to their trust model. Sensitive configuration, passphrases, encrypted data, or private keys must never be added to the capability document.
