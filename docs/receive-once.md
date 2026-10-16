# Durable receive-once receipts

`LocalClient::receive_text_once` supplies an explicit inbox receive boundary for signed text Capsules. It verifies the current contact, expected signature context, sender provenance and recipient decryption, then records a receipt and commits the complete encrypted archive before returning plaintext and a new archive anchor.

Receipt identity is a domain-separated SHA-256 commitment to the recipient's full endpoint fingerprint, the verified sender's full fingerprint, the exact application context and canonical Capsule bytes. Changing binary, ASCII-armored or local-URI transport spelling leaves the receipt unchanged. New encryption of identical text creates a new delivery and remains a separate message.

The history holds at most 4,096 receipts. It never silently expires or evicts old entries. Capacity exhaustion blocks new receive-once operations, rather than pretending prior deliveries have never arrived. A later inbox/archive retention design must explicitly define any loss of replay history before adding deletion or rollover.

Keys, contacts and receipt history commit atomically through the existing private file adapter. A stale digest, write error or uncertain directory-sync result returns no plaintext from this API and locks the mutated client. Reload and inspect durable state before continuing. If a commit became visible but the caller lost its result, the delivery may already count as received; this API does not claim exactly-once delivery to an external file, GUI, notification or application action.

The E2CA outer container remains version 1. Its authenticated internal payload is version 2 and includes strictly bounded, sorted receipt records. Version-1 payloads can be read and are upgraded when saved; their initial receipt history is empty. Protection begins with committed receive-once calls and supplies no history of earlier archival opens.

Whole-archive rollback remains a separate threat. Advance an independently trusted `ArchiveAnchor` only after successful commit and require it on restoration. Password-only restoration accepts valid old backups, including backups before receipt creation, and therefore cannot promise rollback-resistant replay rejection. Cloning an endpoint archive creates another copy of that history; device-wide synchronization and concurrent cross-device inbox delivery are separate unfinished capabilities.

Existing `EndpointSession::open_text` and the CLI's archival open commands retain their repeatable decryption behavior. They are useful for reopening saved encrypted material and make no replay-rejection claim. CLI inbox integration is a separate follow-up to this client API.

This feature uses the existing Capsule/signature/HPKE implementation and adds no new encryption protocol or ratchet. It does not provide forward secrecy, post-compromise security, network delivery, account/device synchronization, or E2EESA certification.

Tests cover real signed/decrypted messages, restart persistence, duplicate delivery through alternate transport encoding, changed context, missing signature, revoked sender, archive rollback under fresh anchors, legacy payload upgrade and failed saves that release no plaintext. The ledger parser rejects duplicate/unsorted entries, changed lengths, truncation, trailing bytes and excessive capacity.
