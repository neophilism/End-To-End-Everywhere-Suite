# Persistent local client archives

`e2ee_client::archive::LocalClient` keeps the software vault, recipient/signer
session and encrypted contact book together. Lock and timeout drop their shared
unlocked owner, including roots and endpoint keys. Hosts still call the timer,
handle OS suspend/logout, and clear displayed or copied plaintext.

Creation requires the exact software-vault profile. The E2CA v1 outer record
contains a password-encrypted vault snapshot and a separately authenticated
complete client payload, both written in one durable file commit. Endpoint IDs,
public-key pins, contact cards and trust decisions are encrypted in that payload.
Both endpoint keys, the contact book and the outer payload carry the same
authenticated state sequence. Strict bounded parsers reject mixed sequences,
unknown versions, lengths, truncation and trailing data before restoring a client.

`RestorePolicy::Anchored` checks a separately trusted `ArchiveAnchor`: vault ID,
minimum vault revision, minimum archive sequence and complete endpoint fingerprint.
The 70-byte E2AT v1 anchor is public, but its integrity and monotonicity matter.
Save the archive first; only then advance the independently trusted anchor.
Reading an anchor from the same replayable storage as the archive supplies no
independent rollback protection.

`RestorePolicy::PasswordOnly` is an explicit basic software option. It authenticates
the archive using the supplied password and the roots inside its vault, but has
no independent identity pin or rollback floor. Valid old backups remain accepted,
including backups predating contact revocation or a password change. Hosts must
make this limitation clear rather than label this mode rollback-protected.

`save` advances the in-memory sequence only after the private file adapter has
synced the complete record and its directory. Stale saves leave the durable state
and sequence unchanged. If a directory sync fails after rename, discard/reload
the transaction and resolve the uncertain state before retrying or updating a
trusted anchor. Password changes are reported successful only after saving.
Backups are never implicitly erased. Public `session_and_contacts` borrows are
for the current unlocked transaction; use the current contact book for every
send/open operation so changed or revoked keys block new operations.
