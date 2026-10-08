# Backup and recovery workflows

PR 7 binds suite recovery behavior to the exact E2EESA backup profiles:

- `backup-none@0.1.0`
- `backup-user-secret@0.1.0`
- `backup-hardware-assisted@0.1.0`

## Trust boundary

Restore does not authorize a device. Device enrollment and verification must complete first.

The storage provider receives an encrypted payload and wrapped backup data-encryption key, never plaintext, the user's recovery secret, or an unwrapped backup data-encryption key.

## User-secret recovery

Recovery-secret derivation is local. Generated secrets require at least 128 random bits. User-chosen passphrases remain supported but retain their offline-guessing limitations.

Argon2id parameters must meet one of the RFC 9106 recommended configurations represented by the suite policy floor.

## Hardware-assisted recovery

The hardware-assisted profile adds a non-exportable hardware wrapping layer around the already encrypted recovery material. The suite requires:

- hardware attestation evidence;
- a non-exportable wrapping key;
- authenticated release; and
- failed-attempt rate limiting.

## Rollback protection

Every backup has a positive monotonically tracked generation. Restore rejects generations older than the locally pinned minimum accepted generation.

The `backup-none` profile permits direct authorized device-to-device migration but forbids a persistent server-restorable backup envelope.
