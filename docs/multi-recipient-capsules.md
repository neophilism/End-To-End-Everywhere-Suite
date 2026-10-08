# Multi-recipient Capsules

PR 11 adds `encrypt_text_for_recipients` and `encrypt_file_for_recipients`.
Each operation encrypts the payload once with a fresh 256-bit key, then uses
the existing RFC 9180 HPKE suite independently for each authorized endpoint.
The same recipient may authorize several devices with distinct endpoint keys.

The single-recipient APIs and authenticated context remain wire-compatible
with PRs 9–10. Multi-recipient operations use separate versioned message/file
domains. The complete ordered hint roster is bound into every key wrap; the
SHA-256 digest of all length-framed stanzas is additionally bound into content
AEAD. Removing, adding, reordering or replacing any recipient stanza fails
authentication. Unknown recipients and invalid/duplicate keys or hints fail
closed. Limits allow 1–4096 recipients. Callers must authorize and verify every
endpoint before supplying it; this low-level API does not infer trust from
an account login or an arbitrary directory response.

Content keys, unwrapped keys and serialized private keys use `Zeroizing`
guards, including on error paths. This protects those owned buffers; it does
not promise elimination of every transient compiler/provider copy in memory.

This is static envelope distribution using the recommended
`SUITE-HPKE-X25519-HKDF-SHA256-CHACHA20POLY1305`, and, for files,
`attachment-chunked-aead@0.1.0`. It is not an MLS or Double Ratchet session and
does not provide forward secrecy, post-compromise security, recipient anonymity
or sender identity authentication. Authorized recipients can forward plaintext
or content keys. Changing membership requires creating a fresh Capsule.
Signatures/provenance follow in PR 12. Existing recipients cannot be made to
forget already-decrypted content by deleting a stanza or storage object.

Tests cover all-endpoint round trips, file chunks, wrong keys, zero/duplicate
recipients, invalid/low-order keys, roster mutations and tampering with another
endpoint's wrap.
