# E2E Capsule format v1

The E2E Capsule is the universal encrypted-envelope layer for End-To-End Everywhere Suite.

An application carrying a Capsule does not need to understand the plaintext. The same envelope can be transported through email, chat, a browser form, a database field, object storage, a QR-assisted transfer, or a native application.

## Wire framing

All integers are unsigned big-endian.

```text
magic                     4 bytes = "E2EC"
format_version             u16 = 1
mandatory_flags            u16 = 0
suite_id_length            u16
suite_id                   bytes
recipient_count            u32
repeat recipient_count:
  recipient_hint_length    u16
  recipient_hint           opaque bytes
  encapsulated_key_length  u32
  encapsulated_key         opaque bytes
  wrapped_key_length       u32
  wrapped_content_key      opaque bytes
protected_header_length    u32
protected_header_ciphertext
payload_length             u64
payload_ciphertext
```

Unknown nonzero mandatory flags fail closed. Version 1 parsers reject unknown versions rather than guessing compatibility.

## Public vs protected information

The framing exposes only what is needed to parse/decrypt the capsule:

- format version;
- selected cryptographic suite identifier;
- opaque recipient hints and recipient key-wrapping material; and
- ciphertext lengths.

Application metadata such as filenames, MIME types, human recipient names, timestamps, message IDs, form fields, and application context belongs inside the encrypted protected header or payload.

Opaque recipient hints can still be metadata and may be linkable. Later metadata-privacy profiles may replace direct recipient hints with sender-hidden or privacy-partitioned delivery mechanisms. The base Capsule format does not claim recipient anonymity.

## Cryptographic binding requirements

PR 8 defines framing, not a new cryptographic construction. Higher-level encryption profiles must ensure:

- a fresh content-encryption key per Capsule;
- authenticated encryption of the protected header and payload;
- cryptographic binding between the public framing, protected header, payload, and recipient wrapping context;
- exact suite/profile negotiation with no silent downgrade; and
- content-key release only to an authorized recipient endpoint.

Recipient stanzas contain protocol-specific encapsulated and wrapped-key bytes. The selected E2EESA profile determines how those bytes are created and verified.

## Parser safety

Decoding untrusted Capsules is bounded by configurable limits for recipient count, stanza sizes, protected-header size, payload size, and total encoded size. The decoder rejects:

- invalid magic;
- unsupported versions or mandatory flags;
- zero recipients;
- duplicate recipient hints;
- empty key material;
- oversized fields;
- integer overflow;
- truncation; and
- trailing bytes.

The parser does not release plaintext. Decryption and authentication happen in later profile-specific layers.
