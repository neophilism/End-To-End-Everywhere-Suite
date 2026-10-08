# Vault credential changes and root retirement

An unlocked software vault can change its unlock passphrase and Argon2id policy.
The new password-derived wrapping key and fresh salt are prepared before any
vault mutation. On success the revision advances and existing protocol roots
remain intact, so endpoint identity, contact pins and prior encrypted local
state do not have to change. Invalid credentials, policy failures and revision
exhaustion leave the original state usable.

Persist the new snapshot before advancing the independently trusted revision
floor or telling the user a durable password change succeeded. An old snapshot
still contains roots encrypted under the old credential; a password change
cannot erase copied backups or undo prior key extraction. The trusted floor
prevents that older snapshot from being accepted as current state.

`retire_root` removes and zeroizes a root's key and advances the vault revision.
Its encrypted tombstone remains, preventing that handle from being provisioned
again even after restart. Use a new handle for a replacement root. Active plus
retired handles share the bounded 1024-entry capacity.

New snapshots use version 2, which authenticates active/retired root status.
Version 1 snapshots remain readable and migrate to version 2 when saved. Local
state records retain version 1 and their existing authenticated context.

Root retirement blocks future local wrapping operations. It does not revoke
previously unlocked protocol keys, erase plaintext already opened, or revoke
access to network ciphertext already addressed to a recipient. Hosts must also
drop unlocked key objects and use their separate device/contact lifecycle when
revoking endpoint access.
