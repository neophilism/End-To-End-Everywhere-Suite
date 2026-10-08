# Device enrollment and verification

A new device is not trusted merely because it authenticated to an account.

PR 5 introduces an explicit pairing ceremony between an already authorized endpoint and a new endpoint. The new endpoint becomes authorized only after both sides confirm the same cryptographic verification transcript and the session is finalized.

## Supported verification ceremonies

The shared model supports:

- QR scanning;
- short authentication strings; and
- another authenticated out-of-band channel.

The cryptographic transcript digest is supplied by the protocol implementation. The enrollment state machine compares the two endpoint views and aborts on mismatch.

## Fail-closed behavior

- Pairing offers expire.
- The existing and new endpoint IDs must differ.
- Each verification side may submit only once.
- Mismatched transcripts abort the session.
- Verification alone is not authorization; explicit finalization is required.
- Finalized or aborted sessions cannot be reused.

The QR representation added by client surfaces must contain only the public pairing material required to establish the session. Private root keys remain behind the secure key-store boundary.
