# Anchored application SDK preview

`e2ee-sdk` is the first Rust application controller for the existing local client, under API preview version 1. It contributes to E2ES-051; stable language bindings, consumer applications, interoperability guarantees, and a supported SDK release remain unfinished. Version 0.1 interfaces can change. Existing Capsule and archive formats retain their own strict version handling; the API preview number is not a new cryptographic profile, protocol, certification, or stable ABI.

The controller owns the private archive writer guard, unlocked software vault, current contact book, receipt history, optimistic state digest and trusted anchor floor. Applications cannot obtain mutable key handles or forget a separate save after changing contact trust through this boundary. The software fallback is selected explicitly by `SoftwareClient`; it makes no native keystore or hardware isolation claim.

## Host responsibilities

Implement `AnchorRepository` for one installation's archive slot using independently protected storage. `current` must retrieve the trusted floor. `advance` must atomically compare the exact previous anchor, enforce the same vault/endpoint and nondecreasing revision plus increasing archive sequence, durably persist the next floor, and return success only after that is complete. Conflicts and uncertain writes return an error. Do not delete or reset the slot as a retry policy. `current` must return the authoritative value or an error, rather than silently serving a stale cached floor.

Process memory, a file next to the replayable archive, or an account-controlled server value alone does not supply the required independent protection. The in-memory implementation in the integration tests is a failure-injection test double, not a production adapter. Actual protected platform anchor adapters remain part of the platform integration work.

The host also selects a private archive directory, supplies a zeroizing local passphrase, enforces the configured KDF resource budget, provides monotonically increasing elapsed time within each unlocked session, and calls `tick`/`lock` on inactivity, screen lock, suspend and logout. It clears its own displayed/copied plaintext. The SDK never opens a network connection or collects credentials for a service.

## Basic application use

The host provisions an empty private store for `SoftwareClient::create`, or opens the existing private store for `SoftwareClient::open`. Opening requires the anchor from the repository; there is no password-only fallback in this controller.

```rust
use e2ee_sdk::{
    AnchorRepository, PrivateStateStore, SdkError, SoftwareClient,
    SoftwareOptions, Zeroizing,
};

fn unlock<A: AnchorRepository>(
    store: PrivateStateStore,
    anchors: A,
    passphrase: Zeroizing<Vec<u8>>,
    elapsed_ms: u64,
) -> Result<SoftwareClient<A>, SdkError> {
    SoftwareClient::open(store, anchors, passphrase, SoftwareOptions::default(), elapsed_ms)
}
```

Use `observe_contact` to import an untrusted card, then compare the complete card fingerprint over an independent channel before calling `verify_contact`. Observation alone never grants trust. `revoke_contact` and explicit fingerprint-checked `reactivate_contact` are durable operations. `seal_text` and `seal_file` resolve the current verified contacts and always sign with the exact application context.

`receive_text` and `receive_file` require the current verified sender and expected context. They authenticate/decrypt through the existing shared client, commit encrypted receipt history, and then advance the trusted anchor before returning a zeroizing plaintext owner. Attachments return bytes and authenticated metadata. The application chooses any export path and must not automatically render or execute active content or use a sender-supplied filename as a path.

## Transaction and failure contract

The controller rechecks the independent floor after archive unlock and before each operation that uses unlocked state. Signed text and file outputs get a second floor check before release. A missing, changed or unavailable floor locks the controller and requires a fresh open; restoring the old repository value does not reactivate that controller. Public cached identity cards and the last accepted anchor remain inspectable for diagnosis.

The SDK also re-reads the authoritative floor after an archive/floor commit (including initialization and recovery) before reporting success or releasing decrypted plaintext. A post-commit conflict or read error locks the controller; the archive or floor may already have advanced, so hosts must inspect and reload rather than retry or replay automatically.

These observations and write-time compare-and-swap detect a superseded controller; they are not a distributed revocation lease. The host must serialize recovery, anchor-slot updates and application use when strict ordering across concurrent controllers is required. A separate actor can still change the floor after the final read. The SDK does not promise instantaneous revocation across machines or release already-returned data.

1. Authenticate and validate the requested operation under current trust and lock policy.
2. Commit the complete encrypted archive through the private atomic storage adapter.
3. Advance the independently protected floor with compare-and-swap.
4. Return success and, for a receive, plaintext.

There is no distributed atomic commit across the archive and external anchor store. A failure after step 2 can leave the archive ahead of the floor, or an uncertain anchor write can already have advanced it. The controller locks, marks `needs_reload`, drops any pending plaintext and refuses subsequent operations. Keep both stores, drop the controller to release its writer guard, inspect the outcome and open against the anchor repository again. Never automatically resend, erase the archive, lower a floor, or declare a failed operation uncommitted.

If the archive is ahead of an older trusted floor, a fresh open accepts the authenticated newer state and preserves its receipts. Rollback protection still extends only to the independently retained floor. If the anchor is ahead of an old archive, opening fails. A fresh archive whose initial anchor was never persisted requires explicit host recovery/identity verification; the SDK does not adopt it without a trusted floor.

An invalid context, unverified/revoked contact or duplicate receipt does not create a new committed receipt. Authentication failures leave a still-unlocked controller usable. Save failures, lock and timeout require a fresh open. Creation can leave an archive behind if the anchor update fails; this is reported as failure, not automatically undone.

This boundary supplies local anchored replay rejection for explicitly received signed Capsules, with the shared maximum of 4,096 receipts and no silent eviction. It does not make output/export exactly once, synchronize devices, implement a ratchet, provide forward secrecy or post-compromise security, issue account/device authorizations, or supply network delivery. Low-level archival opening remains a separate repeatable operation.

## Backup and recovery

The SDK also provides [anchored local checkpoint export and recovery](local-backup-recovery.md) through `checkpoint_backup` and `restore_backup`. Recovery always obtains trust from the independent repository and restores the same endpoint, rather than enrolling a device or trusting a floor embedded in a backup.

## Evidence

External-consumer integration tests use real encryption and real private archive files. They cover unverified contacts, signed text and binary attachments, wrong contexts without state changes, receipt persistence across fresh controllers, rollback under a newer floor, durable revocation, timeout, redacted debug output, missing-anchor rejection, anchor failures both before and after a simulated write, same-endpoint recovery that supersedes a still-unlocked controller, floor deletion/change/read failures, and read failure after signing but before delivery release. The fake anchor adapter checks that a new encrypted archive is visible before every attempted floor update. Passing these tests does not establish a production platform anchor implementation or independent security certification.
