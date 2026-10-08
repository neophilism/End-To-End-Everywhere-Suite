# Portable Capsule deliveries

PR 13 carries one encrypted Capsule and an optional PR 12 detached signature
as a single delivery. Moving between encodings preserves both objects exactly.

| Carrier | Representation | Intended use |
| --- | --- | --- |
| Binary | `E2ED` version 1, `.e2ed` extension | Files, storage objects, attachments |
| ASCII armor | `BEGIN/END E2E DELIVERY`, padded Base64, 76-character lines | Clipboard, email body, text fields |
| Local URI | `e2ed:v1:` plus unpadded Base64url | Small app handoff, default 8 KiB policy |

The binary delivery wrapper contains a version, mandatory flags, length-framed
canonical Capsule bytes and a length-framed signature record. Unknown versions
or flags, signature presence/length contradictions, truncation, trailing data
and configured resource-limit violations fail closed. ASCII decoding accepts LF
or CRLF, rejects junk and multiple records, and checks encoded size before
Base64 allocation. URI decoding rejects padding and non-Base64url characters.

`application/vnd.e2ee.delivery;version=1` is an experimental vendor media type,
not a claim of IANA registration. MIME parsing is deliberately exact; email
adapters must normalize only their explicitly supported content-type syntax.
These APIs encode local data and do not send mail or make network requests.

Parsing does not authenticate the signature or decrypt the payload.
`Delivery::verify_required_signature` requires an independently trusted signer
and expected context, and rejects missing signatures. Applications that require
sender authentication must call it before decrypting or displaying plaintext.
Removing the whole signature can produce an unsigned wrapper, but it cannot
satisfy this required-signature policy.

Encodings add no confidentiality beyond the Capsule. Public recipient hints,
signer fingerprints, signature context and lengths remain visible. Handlers
must not upload these URIs to web search, log them or translate them into HTTP
query parameters. Larger objects use binary or armored transport instead of a
URI. The custom URI scheme is not registered with an OS by this library.
