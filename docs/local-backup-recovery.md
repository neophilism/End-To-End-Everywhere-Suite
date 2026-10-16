# Anchored local backup and recovery

The CLI and Rust SDK can export a complete encrypted client checkpoint and restore it into a new local state directory. It includes the software vault, endpoint keys, verified/revoked contacts and receive-once receipt history. This restores the same endpoint identity. It does not enroll or authorize another device, synchronize active installations, or revoke retained copies of the keys.

## CLI

```sh
e2ee --state local-state --software-vault --anchor "$LATEST_ANCHOR" \
  backup private-backup.e2ca
```

Both `backup` and `restore` require an independently retained `--anchor`; there is no password-only fallback for these commands. Backup authenticates the current state, commits a new archive checkpoint, emits its new public `ANCHOR` on stderr, and writes the exact encrypted bytes to a new 0600 file. It syncs the file and containing directory before reporting success. It never overwrites a destination or includes the anchor as an authoritative part of the backup file.

Retain the emitted anchor in independently trusted storage. It is public but must not be replaceable or rolled back with the archive. A copy beside the backup is informational, not an independent floor. Protect the backup too: possession permits offline guessing of its passphrase, and a decryptable old backup retains that copy of the endpoint keys even after a later passphrase change.

To recover a lost installation, supply the current trusted floor and a backup at or above it:

```sh
e2ee --state recovered-state --software-vault --anchor "$LATEST_ANCHOR" \
  restore private-backup.e2ca
```

`recovered-state` must not exist. The command requires a regular input file, rejects symlinks, opens without blocking on pipes/devices, and bounds and authenticates the complete input against the independent identity/revision/sequence floor before creating that directory. Tampered, stale, wrong-identity or wrong-password inputs create no destination. It then durably saves the recovered state with a higher sequence and emits a new anchor. Keys, contact trust and committed receipt history survive; prior receive-once deliveries remain rejected. The original encrypted input is never modified.

Keep the new anchor after restore. A successful restore advances the floor beyond its input checkpoint, so that older input cannot subsequently be used under the new floor. Export a fresh checkpoint after recovery and after important contact, receipt or credential changes. A backup below the current floor is intentionally rejected; ignoring or lowering the floor would lose the replay/revocation protections it supplies. Do not treat backup files as automatically current recovery material.

Existing installations are not overwritten or remotely invalidated. If another copy is still active, it is the same endpoint with a separate local history; these commands do not make concurrent copies safe for synchronized messaging. Use distinct endpoint enrollment/authorization for another device when that capability is available.

## Failure and interruption

An existing export destination is rejected before advancing the checkpoint. A later export error can occur after the live archive has committed: stderr explicitly identifies that boundary and emits the new anchor first. Retain that anchor, keep the live archive, inspect the output, and obtain a current verified backup before discarding the source. Do not assume a failed export left the source state unchanged.

An abrupt interruption may leave an incomplete newly created export. Directory-sync failure reports uncertain durability and preserves the file for inspection. Recovery authenticates the entire archive; an incomplete or changed export cannot silently become a valid checkpoint. These commands do not claim atomic publication to external backup media or secure deletion of prior copies.

## Rust SDK

`SoftwareClient::checkpoint_backup(now_ms)` commits the live archive and host's independent `AnchorRepository`, then returns `EncryptedBackup`. `bytes()` exposes only the encrypted snapshot. `checkpoint_anchor()` is informational for display/comparison; it must never replace the repository as the recovery trust source. Hosts handle durable publication to their chosen backup destination and preserve existing files.

`SoftwareClient::restore_backup(empty_store, anchors, ciphertext, passphrase, options, now_ms)` obtains the floor from the independent repository, verifies the input, commits a fresh local archive and advances the repository before returning an unlocked controller. It refuses a nonempty destination record. If the final anchor update fails or is uncertain, the method returns no controller; a new archive may already exist. Keep both stores and reconcile through a fresh anchored open rather than automatically recreating, overwriting or lowering the anchor.

The host creates the empty `PrivateStateStore` before calling the SDK, so a failed SDK validation can leave that caller-created empty directory; no archive record is written. CLI validation additionally occurs before creating its destination directory. Production protected-anchor adapters remain unfinished and are not supplied by the test double.

Integration tests exercise actual encrypted archives, private output permissions, preserved endpoint identity/keys/contact trust/receipts, restart recovery, modified and stale backup rejection, no destination overwrite, a failed export after checkpoint commit, and restore failure before an anchor write followed by explicit fresh-open recovery. This is local software-vault backup functionality, not account recovery, native hardware assurance, network backup, forward secrecy or certification.
