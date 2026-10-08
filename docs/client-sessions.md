# Shared client sessions

`e2ee-client` composes the real Capsule core into consumer-client workflows.
It is a reusable controller for desktop, mobile and other hosts; a native
graphical interface is separate work.

Each local endpoint has separate recipient and signing keys. Its public contact
card fingerprint covers the endpoint identity and both keys. Encryption accepts
only `VerifiedContact` values created by confirming the full fingerprint from an
independent channel. A card received from an untrusted service does not verify
itself. Contact verification is a human/higher-layer responsibility.

Text delivery can include a context-bound signature or be explicitly unsigned.
Opening signed content requires a pinned sender and expected application
context; verification occurs before any plaintext is returned. Unsigned content
cannot meet a required-signature policy, and a present signature cannot be
silently ignored under the unsigned policy. These envelopes do not implement
session forward secrecy, post-compromise security, or replay prevention.

Endpoint keys remain only in an unlocked session. Every key operation checks a
monotonic clock and inactivity deadline. Manual lock, deadline expiry or clock
regression drops the key objects. Hosts must call the timer even while idle,
drop their unlocked root provider, clear displayed/copied plaintext, and lock
on operating-system suspend/logout. The library cannot enforce OS events itself.
Failed cryptographic operations do not reset the inactivity deadline.

Encrypted persistence uses the local-state provider. Restore requires a
separately trusted contact card, wrapping root and sequence floor, and loads
both keys before publishing an unlocked state. A failed signing-key restore
cannot leave the recipient key usable. Creating a local endpoint does not
authorize a new device on an existing account.
