# File and attachment Capsules

PR 10 implements the E2EESA `attachment-chunked-aead@0.1.0` architecture over E2E Capsules.

## Construction

Each file receives a fresh random 256-bit attachment key. The Capsule recipient stanza wraps that key using the same exact E2EESA-recommended RFC 9180 HPKE suite established by the text/message layer.

The implementation selects E2EESA's recommended `ALG-CHACHA20-POLY1305` content AEAD and `ALG-SHA256` whole-file hash.

Configured chunk sizes are restricted to 64 KiB through 8 MiB. Empty files are represented by one authenticated zero-length plaintext chunk.

Every chunk nonce is exactly:

`4-byte random nonce prefix || uint64_be(chunk_index)`

and every chunk authenticates:

- attachment identifier;
- private manifest-context digest;
- chunk index;
- total chunk count; and
- exact plaintext chunk length.

This causes reordering, cross-position substitution, false lengths, truncation, and ordinary chunk replay into another position to fail.

## Private manifest

Filename, media type, exact plaintext size, nonce prefix, whole-file plaintext hash, logical storage-object identifier, and attachment identifiers live in the encrypted Capsule protected header.

The manifest-context digest is SHA-256 over compact UTF-8 JSON whose object keys are deterministically sorted by `serde_json`, including the `E2EESA-ATTACHMENT-MANIFEST-v1` domain and all bound manifest fields except the attachment key value and the digest itself.

The actual attachment key is not duplicated in the manifest plaintext: the Capsule's authenticated recipient stanza is the E2EE key-distribution mechanism. This is the Capsule mapping of E2EESA's requirement that the attachment key and private manifest travel only inside authenticated E2EE material.

## Verification before release

Each chunk is authenticated before it is appended to the reconstructed file. Once all chunks authenticate, the completed plaintext is checked against the private manifest's SHA-256 hash before `decrypt_file` returns it.

## Inline vs streaming use

The convenience `encrypt_file` / `decrypt_file` API currently supports inline Capsules up to 512 MiB. This is an implementation memory bound, not an E2EESA format limit.

The chunk format is independently authenticated and range-addressable, so later object-relay and virtual-drive components can stream the same chunk construction without holding an entire large object in memory.

## Metadata and recall boundary

The carrier/storage layer can still infer ciphertext size, timing, object count, and access patterns. Filename, media type, exact plaintext size, and plaintext hash remain encrypted.

Storage deletion is not global cryptographic recall. A recipient that already obtained the attachment key or plaintext cannot be forced to forget it, and later product UI must not claim otherwise.
