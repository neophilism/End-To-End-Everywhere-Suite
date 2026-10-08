# Contact verification and key changes

`ContactBook` provides the address-book lifecycle used by client hosts. Imported
or discovered cards start unverified. Verification compares the complete card
fingerprint obtained through an independent channel; a card or directory cannot
approve itself. Newly observed keys never silently replace a verified pin.

When a verified card changes, the contact enters `KeyChanged` and cannot be
selected for a new send or required sender check. Replaying the old card does
not clear that state. A human must compare the currently displayed fingerprint
again. Revocation blocks new operations and persists across imports; reactivation
is a separate explicit action requiring the matching fingerprint.

The contact-based client helpers resolve current lifecycle state for every
operation. Hosts should use them instead of caching `VerifiedContact` copies:
an already returned immutable pin cannot receive a later revocation event.
Revocation cannot prevent a recipient reading ciphertext already delivered to
its key, nor erase plaintext it has saved.

Address-book contents, pins and revocation/change flags can be sealed under a
protocol-state wrapping root. The authenticated context includes the local
owner endpoint. Restore requires an independently trusted state-sequence floor.
The plaintext serializer is bounded, ordered and rejects duplicate contacts,
unknown flags, malformed cards, truncation and trailing bytes. Encryption of the
address book does not provide an independent rollback anchor by itself.
