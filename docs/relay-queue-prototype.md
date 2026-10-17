# Volatile ciphertext relay queue prototype

`e2ee_transport::relay` is the first bounded, **in-memory-only** mailbox
state machine for E2ES-054, intended to inform a later ciphertext-only offline
delivery service. It is **not** a usable public relay or network endpoint.
No database, user authentication, network TLS, durable retry ledger, abuse
monitoring, queue replication, rate limiting or operational service exists.

The transport wrapper validates exact canonical E2ED delivery framing and
requires a syntactically present detached signature before accepting bytes.
**It does not verify the signature, determine whether bytes are actually
encrypted, or verify the recipient.** Endpoint clients must authenticate
sender, context, recipient and cryptographic material independently. The
untrusted relay never decrypts or inspects protected payloads.

## State model

- Applications supply an opaque 32-byte mailbox identifier that must not
  reveal email addresses or other directly identifying information. It is
  **not** a secret, authorization token or account identity.
- An uploader uses a fresh unpredictable 16-byte upload token per delivery.
  Exact retries return the same sequence without extending expiry. Reusing a
  token with changed bytes is rejected while its delivery remains queued.
- Each enqueue chooses a positive bounded retention interval. The relay
  rejects backwards clock movement, timestamp overflow, malformed or unsigned
  delivery framing, and exhaustion of configured resource budgets.
- `page(mailbox, after, limit, now_ms)` provides insertion-ordered,
  bounded ciphertext pages. Fetching does **not** acknowledge or delete.
- `acknowledge` explicitly deletes a queued item. Missing/expired items are
  idempotent false outcomes; only an authorized recipient or responsible host
  should be able to invoke it.

The default prototype limits are 1 MiB per delivery, 64 messages and 8 MiB per
mailbox, 64 MiB total, 2,048 simultaneous mailboxes, 7 days maximum retention,
and 32 items per page. Those limits are **single-process resource bounds**,
not a shared production quota.

### Ordering and recovery

An endpoint must commit authentication and receive-once replay state into its
local encrypted archive and independently retained anchor **before** issuing
an acknowledgement. If that commit fails or becomes uncertain, retain the
remote delivery and require an anchored reload, rather than acknowledging
optimistically. Acknowledgement itself can fail after the relay removes an
item, so downstream client operations must also be idempotent. Reading does
not imply deletion.

The in-memory queue loses unacknowledged messages on process restart and
can be bypassed if the host omits authentication checks. Production work must
define and verify durable atomic queue writes, authenticated mailbox grants,
recipient endpoint lifecycle and revocation, sender abuse limits, server-side
quotas, metadata minimization, expiration scheduling, clock sources,
application/service interfaces, deployment and incident response.

A global sequence counter and access patterns expose some ordering/traffic
metadata to the relay. Duplicate uploads and ciphertext itself may be
correlated. No metadata anonymity, traffic padding, forward secrecy or
availability guarantees are provided here. Host logs must never include
plaintext, shared secrets, upload tokens or full delivery bodies.

## Developer example

```rust
use e2ee_transport::relay::{
    InMemoryRelay, MailboxId, RelayLimits, UploadToken,
};
use e2ee_capsule::CapsuleLimits;

let mut queue = InMemoryRelay::new(
    RelayLimits::default(),
    CapsuleLimits::default(),
)?;
let mailbox = MailboxId::new([1; 32])?;
let upload = UploadToken::new([2; 16])?;
// Only pass already encoded, signed E2ED bytes. Examples above are placeholders.
# let signed_e2ed_bytes: &[u8] = &[];
# let now_ms = 0;
# let _sequence = queue.enqueue(mailbox, upload, signed_e2ed_bytes, 60_000, now_ms)?;
```

The example's placeholder bytes are not a valid delivery; caller code must
supply a real encoded E2ED object. No independent E2EESA conformance or
production claim follows from the queue tests.
