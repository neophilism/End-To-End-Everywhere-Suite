# Client files and portable records

The shared client controller now encrypts and opens files with the same contact
pins, sender-signature policy and lock checks used for text. The existing
chunked AEAD profile authenticates private filename/media metadata and all file
chunks; no file plaintext is returned until validation succeeds. The bounded
client inline path accepts at most 32 MiB. Larger streaming file adapters are
separate work.

Opened files retain plaintext bytes and private filename/media metadata in
zeroizing containers and redact them from debug output. Hosts must provide a
user-selected save destination, avoid overwriting files unexpectedly and never
auto-execute decrypted files or render active content. Opening the file does
not save it to disk.

Public endpoint cards have a strict binary format and an `e2ec:v1:` Base64url
local handoff URI suitable for QR encoders. They contain public keys and an
endpoint ID only. Parsing a contact URI grants no trust: a complete fingerprint
must still be independently compared before constructing `VerifiedContact`.
URLs, queries, fragments, padding, percent escapes, alternate versions and
noncanonical encodings are rejected.

Encrypted recipient/signing key pairs have a separate bounded `E2CK` binary
record. Parsing only reconstructs ciphertext. Restore still requires a trusted
endpoint card, provider/root and sequence floor; the encoded record cannot
replace those trust decisions.
