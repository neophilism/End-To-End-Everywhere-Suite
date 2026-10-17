//! Bounded, volatile ciphertext mailbox model for an eventual offline relay.
//!
//! This is NOT an HTTP server, authentication layer or durable delivery queue.
//! Host integrations must authenticate every mailbox operation, persist queues
//! transactionally, enforce distributed quotas and allow acknowledgement only
//! after a recipient commits its independent replay-protection anchor.
//! Delivery framing is validated, not decrypted or cryptographically verified.

use crate::Delivery;
use e2ee_capsule::CapsuleLimits;
use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
};

/// Opaque routing namespace. Never derive this value from a user name, email,
/// fingerprint or other directly identifying string. It is NOT a secret or an
/// authentication credential; server policy must authorize operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MailboxId([u8; 32]);

impl MailboxId {
    pub fn new(bytes: [u8; 32]) -> Result<Self, RelayError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(RelayError::InvalidMailbox);
        }
        Ok(Self(bytes))
    }
}

/// Client-chosen, independently random upload retry token; hosts must not
/// reuse it for different deliveries. This is not a sender credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UploadToken([u8; 16]);

impl UploadToken {
    pub fn new(bytes: [u8; 16]) -> Result<Self, RelayError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(RelayError::InvalidUploadToken);
        }
        Ok(Self(bytes))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayLimits {
    pub max_delivery_bytes: usize,
    pub max_items_per_mailbox: usize,
    pub max_bytes_per_mailbox: usize,
    pub max_total_bytes: usize,
    pub max_mailboxes: usize,
    pub max_retention_ms: u64,
    pub max_page_items: usize,
}

impl Default for RelayLimits {
    fn default() -> Self {
        Self {
            max_delivery_bytes: 1024 * 1024,
            max_items_per_mailbox: 64,
            max_bytes_per_mailbox: 8 * 1024 * 1024,
            max_total_bytes: 64 * 1024 * 1024,
            max_mailboxes: 2048,
            max_retention_ms: 7 * 24 * 60 * 60 * 1000,
            max_page_items: 32,
        }
    }
}

impl RelayLimits {
    pub fn validate(self) -> Result<Self, RelayError> {
        if self.max_delivery_bytes == 0
            || self.max_items_per_mailbox == 0
            || self.max_bytes_per_mailbox < self.max_delivery_bytes
            || self.max_total_bytes < self.max_bytes_per_mailbox
            || self.max_mailboxes == 0
            || self.max_retention_ms == 0
            || self.max_page_items == 0
            || self.max_page_items > self.max_items_per_mailbox
        {
            return Err(RelayError::InvalidLimits);
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayError {
    InvalidMailbox,
    InvalidUploadToken,
    InvalidLimits,
    InvalidLifetime,
    InvalidPageSize,
    InvalidDelivery,
    UnsignedDelivery,
    DuplicateUploadConflict,
    QuotaExceeded,
    ClockRollback,
    SequenceExhausted,
}

impl fmt::Display for RelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidMailbox => "relay mailbox identifier is invalid",
            Self::InvalidUploadToken => "relay upload token is invalid",
            Self::InvalidLimits => "relay resource policy is invalid",
            Self::InvalidLifetime => "relay message lifetime is invalid",
            Self::InvalidPageSize => "relay page size is invalid",
            Self::InvalidDelivery => "delivery framing or canonical encoding is invalid",
            Self::UnsignedDelivery => "relay prototype requires a signed delivery",
            Self::DuplicateUploadConflict => "upload token already identifies different bytes",
            Self::QuotaExceeded => "relay quota exceeded",
            Self::ClockRollback => "relay clock moved backwards",
            Self::SequenceExhausted => "relay sequence exhausted",
        })
    }
}

impl std::error::Error for RelayError {}

/// Copied ciphertext for an authorized recipient's device-side processing.
/// Acknowledgement is separate; listing never marks messages received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedDelivery {
    pub sequence: u64,
    pub expires_at_ms: u64,
    pub bytes: Vec<u8>,
}

#[derive(Debug)]
struct Item {
    upload_token: UploadToken,
    delivery: QueuedDelivery,
}

/// In-memory state machine only. Restart loses unacknowledged messages;
/// production implementations need a durable, authenticated transactional store.
#[derive(Debug)]
pub struct InMemoryRelay {
    limits: RelayLimits,
    delivery_limits: CapsuleLimits,
    mailboxes: BTreeMap<MailboxId, VecDeque<Item>>,
    queued_bytes: usize,
    next_sequence: u64,
    last_time_ms: Option<u64>,
}

impl InMemoryRelay {
    pub fn new(limits: RelayLimits, delivery_limits: CapsuleLimits) -> Result<Self, RelayError> {
        Ok(Self {
            limits: limits.validate()?,
            delivery_limits,
            mailboxes: BTreeMap::new(),
            queued_bytes: 0,
            next_sequence: 0,
            last_time_ms: None,
        })
    }

    /// Queue an authenticated-envelope *candidate* without ever opening it.
    /// The relay checks framing and signature presence only. The endpoint
    /// must independently authenticate the signer, context and recipient.
    /// A retry with identical bytes and token returns the original sequence
    /// without extending TTL. A different delivery with the token is rejected.
    pub fn enqueue(
        &mut self,
        mailbox: MailboxId,
        upload_token: UploadToken,
        raw_delivery: &[u8],
        retention_ms: u64,
        now_ms: u64,
    ) -> Result<u64, RelayError> {
        self.observe(now_ms)?;
        if retention_ms == 0 || retention_ms > self.limits.max_retention_ms {
            return Err(RelayError::InvalidLifetime);
        }
        let expires_at_ms = now_ms
            .checked_add(retention_ms)
            .ok_or(RelayError::InvalidLifetime)?;
        if raw_delivery.is_empty() || raw_delivery.len() > self.limits.max_delivery_bytes {
            return Err(RelayError::QuotaExceeded);
        }
        let candidate = Delivery::decode(raw_delivery, self.delivery_limits)
            .map_err(|_| RelayError::InvalidDelivery)?;
        if candidate.signature.is_none() {
            return Err(RelayError::UnsignedDelivery);
        }
        if candidate
            .encode(self.delivery_limits)
            .map_err(|_| RelayError::InvalidDelivery)?
            != raw_delivery
        {
            return Err(RelayError::InvalidDelivery);
        }
        if let Some(queue) = self.mailboxes.get(&mailbox) {
            if let Some(item) = queue.iter().find(|item| item.upload_token == upload_token) {
                return if item.delivery.bytes == raw_delivery {
                    Ok(item.delivery.sequence)
                } else {
                    Err(RelayError::DuplicateUploadConflict)
                };
            }
        }

        let count = self.mailboxes.get(&mailbox).map_or(0, VecDeque::len);
        let mailbox_bytes: usize = self.mailboxes.get(&mailbox).map_or(0, |queue| {
            queue.iter().map(|item| item.delivery.bytes.len()).sum()
        });
        if count >= self.limits.max_items_per_mailbox
            || mailbox_bytes
                .checked_add(raw_delivery.len())
                .filter(|total| *total <= self.limits.max_bytes_per_mailbox)
                .is_none()
            || self
                .queued_bytes
                .checked_add(raw_delivery.len())
                .filter(|total| *total <= self.limits.max_total_bytes)
                .is_none()
            || (!self.mailboxes.contains_key(&mailbox)
                && self.mailboxes.len() >= self.limits.max_mailboxes)
        {
            return Err(RelayError::QuotaExceeded);
        }
        let sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(RelayError::SequenceExhausted)?;
        self.mailboxes.entry(mailbox).or_default().push_back(Item {
            upload_token,
            delivery: QueuedDelivery {
                sequence,
                expires_at_ms,
                bytes: raw_delivery.to_vec(),
            },
        });
        self.next_sequence = sequence;
        self.queued_bytes += raw_delivery.len();
        Ok(sequence)
    }

    /// Return a bounded page of unexpired ciphertext in insertion order.
    /// `after` is a pagination cursor, not an acknowledgement.
    pub fn page(
        &mut self,
        mailbox: MailboxId,
        after: Option<u64>,
        limit: usize,
        now_ms: u64,
    ) -> Result<Vec<QueuedDelivery>, RelayError> {
        self.observe(now_ms)?;
        if limit == 0 || limit > self.limits.max_page_items {
            return Err(RelayError::InvalidPageSize);
        }
        Ok(self.mailboxes.get(&mailbox).map_or_else(Vec::new, |queue| {
            queue
                .iter()
                .filter(|item| after.is_none_or(|cursor| item.delivery.sequence > cursor))
                .take(limit)
                .map(|item| item.delivery.clone())
                .collect()
        }))
    }

    /// Destructive acknowledgement. The host MUST call this only after the
    /// recipient has durably committed authenticated replay-rejection state.
    /// Return false when the item was already deleted or expired.
    pub fn acknowledge(
        &mut self,
        mailbox: MailboxId,
        sequence: u64,
        now_ms: u64,
    ) -> Result<bool, RelayError> {
        self.observe(now_ms)?;
        let mut removed_size = None;
        let mut is_empty = false;
        if let Some(queue) = self.mailboxes.get_mut(&mailbox) {
            if let Some(position) = queue
                .iter()
                .position(|item| item.delivery.sequence == sequence)
            {
                removed_size = queue.remove(position).map(|item| item.delivery.bytes.len());
            }
            is_empty = queue.is_empty();
        }
        if is_empty {
            self.mailboxes.remove(&mailbox);
        }
        if let Some(size) = removed_size {
            self.queued_bytes -= size;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Pure queue accounting; these are resource stats, not user metrics.
    pub fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }

    fn observe(&mut self, now_ms: u64) -> Result<(), RelayError> {
        if self.last_time_ms.is_some_and(|previous| now_ms < previous) {
            return Err(RelayError::ClockRollback);
        }
        self.last_time_ms = Some(now_ms);
        let mut removed = 0;
        self.mailboxes.retain(|_, queue| {
            queue.retain(|item| {
                if item.delivery.expires_at_ms <= now_ms {
                    removed += item.delivery.bytes.len();
                    false
                } else {
                    true
                }
            });
            !queue.is_empty()
        });
        self.queued_bytes -= removed;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Delivery;
    use e2ee_message::{encrypt_text, generate_recipient_keypair, RecipientPublicKey};
    use e2ee_provenance::{sign_capsule, CapsuleSigningKey};

    fn mailbox(byte: u8) -> MailboxId {
        MailboxId::new([byte; 32]).unwrap()
    }
    fn token(byte: u8) -> UploadToken {
        UploadToken::new([byte; 16]).unwrap()
    }
    fn signed_delivery(text: &str) -> Vec<u8> {
        let receiver = generate_recipient_keypair();
        let capsule = encrypt_text(
            &RecipientPublicKey {
                recipient_hint: vec![1; 16],
                encoded_public_key: receiver.public_key,
            },
            text,
            None,
        )
        .unwrap();
        let signer = CapsuleSigningKey::generate().unwrap();
        Delivery {
            signature: Some(
                sign_capsule(&signer, &capsule, "relay-fixture", CapsuleLimits::default()).unwrap(),
            ),
            capsule,
        }
        .encode(CapsuleLimits::default())
        .unwrap()
    }
    fn queue() -> InMemoryRelay {
        InMemoryRelay::new(RelayLimits::default(), CapsuleLimits::default()).unwrap()
    }

    #[test]
    fn rejects_plaintext_bad_framing_and_unsigned_deliveries() {
        let mut relay = queue();
        assert_eq!(
            relay.enqueue(mailbox(1), token(1), b"plaintext", 50, 0),
            Err(RelayError::InvalidDelivery)
        );
        let signed = signed_delivery("a");
        let mut malformed = signed.clone();
        malformed.push(0);
        assert_eq!(
            relay.enqueue(mailbox(1), token(1), &malformed, 50, 0),
            Err(RelayError::InvalidDelivery)
        );
        let mut unsigned = Delivery::decode(&signed, CapsuleLimits::default()).unwrap();
        unsigned.signature = None;
        assert_eq!(
            relay.enqueue(
                mailbox(1),
                token(1),
                &unsigned.encode(CapsuleLimits::default()).unwrap(),
                50,
                0,
            ),
            Err(RelayError::UnsignedDelivery)
        );
        assert_eq!(relay.queued_bytes(), 0);
    }

    #[test]
    fn exact_retry_is_idempotent_conflicting_token_fails_and_ttl_is_not_extended() {
        let mut relay = queue();
        let bytes = signed_delivery("alpha");
        assert_eq!(relay.enqueue(mailbox(1), token(1), &bytes, 5, 10), Ok(1));
        assert_eq!(relay.enqueue(mailbox(1), token(1), &bytes, 10, 11), Ok(1));
        assert_eq!(
            relay.enqueue(mailbox(1), token(1), &signed_delivery("beta"), 5, 11),
            Err(RelayError::DuplicateUploadConflict)
        );
        assert_eq!(
            relay.page(mailbox(1), None, 8, 14).unwrap()[0].expires_at_ms,
            15
        );
        assert!(relay.page(mailbox(1), None, 8, 15).unwrap().is_empty());
        assert_eq!(relay.queued_bytes(), 0);
        assert_eq!(relay.enqueue(mailbox(1), token(1), &bytes, 5, 16), Ok(2));
    }

    #[test]
    fn paginates_across_mailboxes_without_implicit_acknowledgement() {
        let mut relay = queue();
        let bytes = signed_delivery("ciphertext");
        assert_eq!(relay.enqueue(mailbox(1), token(1), &bytes, 200, 1), Ok(1));
        assert_eq!(relay.enqueue(mailbox(2), token(1), &bytes, 200, 2), Ok(2));
        assert_eq!(relay.enqueue(mailbox(1), token(2), &bytes, 200, 3), Ok(3));
        assert_eq!(relay.page(mailbox(1), None, 1, 4).unwrap()[0].sequence, 1);
        assert_eq!(
            relay.page(mailbox(1), Some(1), 1, 5).unwrap()[0].sequence,
            3
        );
        assert_eq!(relay.page(mailbox(2), None, 4, 6).unwrap().len(), 1);
        assert!(relay.acknowledge(mailbox(1), 1, 7).unwrap());
        assert!(!relay.acknowledge(mailbox(1), 1, 8).unwrap());
        assert_eq!(relay.page(mailbox(1), None, 4, 9).unwrap().len(), 1);
        assert_eq!(relay.page(mailbox(2), None, 4, 10).unwrap().len(), 1);
    }

    #[test]
    fn quotas_expiration_and_clock_rollback_fail_closed() {
        let data = signed_delivery("bounded");
        let mut limits = RelayLimits::default();
        limits.max_delivery_bytes = data.len();
        limits.max_bytes_per_mailbox = data.len();
        limits.max_total_bytes = data.len();
        limits.max_items_per_mailbox = 1;
        limits.max_mailboxes = 1;
        limits.max_page_items = 1;
        let mut relay = InMemoryRelay::new(limits, CapsuleLimits::default()).unwrap();
        assert_eq!(relay.enqueue(mailbox(1), token(1), &data, 10, 100), Ok(1));
        assert_eq!(
            relay.enqueue(mailbox(2), token(1), &data, 10, 100),
            Err(RelayError::QuotaExceeded)
        );
        assert_eq!(
            relay.enqueue(mailbox(1), token(2), &data, 10, 100),
            Err(RelayError::QuotaExceeded)
        );
        assert_eq!(
            relay.page(mailbox(1), None, 2, 100),
            Err(RelayError::InvalidPageSize)
        );
        assert_eq!(
            relay.page(mailbox(1), None, 1, 99),
            Err(RelayError::ClockRollback)
        );
        assert_eq!(relay.page(mailbox(1), None, 1, 110).unwrap().len(), 0);
        assert_eq!(relay.enqueue(mailbox(2), token(1), &data, 10, 111), Ok(2));
        assert_eq!(relay.queued_bytes(), data.len());
    }

    #[test]
    fn invalid_inputs_and_time_arithmetic_fail_closed() {
        assert_eq!(MailboxId::new([0; 32]), Err(RelayError::InvalidMailbox));
        assert_eq!(
            UploadToken::new([0; 16]),
            Err(RelayError::InvalidUploadToken)
        );
        assert!(InMemoryRelay::new(
            RelayLimits {
                max_delivery_bytes: 0,
                ..RelayLimits::default()
            },
            CapsuleLimits::default()
        )
        .is_err());
        let bytes = signed_delivery("overflow");
        let mut relay = queue();
        assert_eq!(
            relay.enqueue(mailbox(1), token(1), &bytes, 0, 0),
            Err(RelayError::InvalidLifetime)
        );
        assert_eq!(
            relay.enqueue(mailbox(1), token(1), &bytes, 2, u64::MAX),
            Err(RelayError::InvalidLifetime)
        );
    }
}
