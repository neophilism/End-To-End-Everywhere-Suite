# Text and message Capsules

PR 9 turns the Capsule framing into a working single-recipient text/message encryption profile.

## Cryptographic construction

The recipient content-key wrap uses the exact E2EESA-recommended RFC 9180 suite:

`SUITE-HPKE-X25519-HKDF-SHA256-CHACHA20POLY1305`

The implementation pins `hpke 0.14.1` and enables only the RFC 9180 X25519/HKDF-SHA256/ChaCha20-Poly1305 feature set required by this profile. Post-quantum draft features are deliberately not enabled by default.

For each Capsule, the sender generates:

- a fresh random 256-bit content-encryption key;
- a fresh random 128-bit message identifier;
- an independent random 96-bit protected-header nonce; and
- an independent random 96-bit payload nonce.

The protected header and UTF-8 text payload use RFC 8439 ChaCha20-Poly1305. The recipient's HPKE stanza wraps only the fresh content key.

## Authenticated context

Domain-separated associated data binds:

- Capsule/message profile version;
- the exact E2EESA suite identifier;
- the opaque recipient hint;
- key-wrap vs protected-header vs payload purpose; and
- the protected message identifier into payload authentication.

Consequently, changing the recipient hint, protected header, payload, or cryptographic suite fails authentication rather than silently changing message meaning.

## Protected header

The protected header contains the random message identifier and content type. It is encrypted; those fields are not exposed in the Capsule's public framing.

No timestamp is inserted by default. Applications that need timestamps can carry them inside a later protected application-metadata structure instead of leaking them to the transport.

## Security boundary

This profile uses HPKE **Base mode**. It provides recipient confidentiality and ciphertext integrity but does **not** authenticate the real-world sender. PR 12 adds signatures/provenance, while stateful pairwise messaging can later bind to E2EESA's Double Ratchet profiles when forward secrecy and post-compromise security are required.

The random message identifier enables higher layers to implement replay caches, but PR 9 itself does not claim cross-application replay prevention because arbitrary carriers such as email, clipboard, and web forms do not share a universal replay database.

The visible recipient hint remains metadata. Later metadata-privacy integrations can replace or partition routing while keeping the Capsule payload unchanged.

## Secret-key handling

The endpoint HPKE private key is endpoint protocol state, not a hardware root key. Production clients should persist it only inside the encrypted local vault protected by the selected `e2ee-keystore` profile. Its temporary in-memory representation redacts Debug output and overwrites serialized bytes on drop.

## Dependency assurance

The Rust HPKE implementation is pinned to an exact release and is covered by the suite's CI and interoperability work. Upstream documentation states the crate has not received a paid formal audit; this repository therefore does not treat dependency choice as cryptographic certification. External review and reproducible release evidence remain required by the later assurance roadmap.
