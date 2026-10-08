# Capsule signatures and provenance

PR 12 adds optional detached signatures. `e2ee-provenance` uses the registered
E2EESA `ALG-ED25519` primitive (RFC 8032) and `ALG-SHA256`, with exact dependency
versions and strict verification. The suite composition has record version 1;
it is not a separate E2EESA conformance profile.

Signatures bind the version, algorithm, signer-key fingerprint, caller-supplied
application context and SHA-256 digest of the complete canonical Capsule bytes.
That digest covers the suite, complete ordered recipient stanzas, protected
header and payload. Context is required, bounded to 256 printable ASCII bytes
and must match the application's independently expected context at verification.
Ed25519 signs this domain-separated statement directly; this is not Ed25519ph.

The record contains no public key or certificate. Verification requires a
`TrustedSigner` created from a key the caller separately pinned or authenticated
through an authorized account/device chain. A key returned alongside a signature
must not become trusted simply because that signature is internally consistent.
Weak/low-order signer keys fail closed. Keys for signing and HPKE are distinct.
The signing seed and provider signing key are zeroized on drop.

`DetachedSignature::encode/decode` use strict, bounded `E2CS` version-1 binary
records. Unknown versions/algorithms, malformed lengths, truncation, invalid
contexts and trailing data are rejected. Decryption applications that require
authenticated senders must verify the signature before displaying plaintext;
absence of a signature must never silently satisfy that policy.

Detached signatures expose a stable signer fingerprint and purpose context to
the carrier. Applications requiring sender privacy can carry the signature in a
separately encrypted application layer instead. Signatures provide transferable
evidence, so deniable communication should not opt into this feature. They do not
prove a civil identity, a timestamp, freshness, delivery or truth of the content.
Replay caches, key revocation and stateful ratchet sessions remain separate.

Validation includes RFC 8032 section 7.1 test vector 1, independent-key substitution,
every-field tampering, cross-context reuse, weak keys and adversarial parsing.
