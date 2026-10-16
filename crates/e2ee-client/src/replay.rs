//! Bounded receipt history for explicitly selected receive-once operations.
//! Entries are encrypted inside the complete client archive; this is not a ratchet.

use crate::{EndpointCard, VerifiedContact};
use e2ee_capsule::CapsuleLimits;
use e2ee_transport::Delivery;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fmt};

const PREFIX: &[u8; 6] = b"E2RP\0\x01";
pub const MAX_RECEIPTS: usize = 4096;
pub(crate) const MAX_LEDGER_BYTES: usize = 10 + 32 * MAX_RECEIPTS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayError {
    AlreadyReceived,
    CapacityExceeded,
    Malformed,
    InvalidDelivery,
}

impl fmt::Display for ReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AlreadyReceived => "this authenticated delivery was already received",
            Self::CapacityExceeded => "receipt history is full; no entries were silently evicted",
            Self::Malformed => "encrypted receipt history is malformed",
            Self::InvalidDelivery => "delivery cannot be committed to receipt history",
        })
    }
}
impl std::error::Error for ReplayError {}

#[derive(Default)]
pub(crate) struct ReplayLedger {
    received: BTreeSet<[u8; 32]>,
}

impl ReplayLedger {
    pub(crate) fn record(&mut self, id: [u8; 32]) -> Result<(), ReplayError> {
        if self.received.contains(&id) {
            return Err(ReplayError::AlreadyReceived);
        }
        if self.received.len() >= MAX_RECEIPTS {
            return Err(ReplayError::CapacityExceeded);
        }
        self.received.insert(id);
        Ok(())
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut bytes = PREFIX.to_vec();
        bytes.extend_from_slice(&(self.received.len() as u32).to_be_bytes());
        for id in &self.received {
            bytes.extend_from_slice(id);
        }
        bytes
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, ReplayError> {
        if bytes.len() < 10 || bytes.len() > MAX_LEDGER_BYTES || bytes[..6] != *PREFIX {
            return Err(ReplayError::Malformed);
        }
        let count = u32::from_be_bytes(
            bytes[6..10]
                .try_into()
                .map_err(|_| ReplayError::Malformed)?,
        ) as usize;
        if count > MAX_RECEIPTS
            || count.checked_mul(32).and_then(|n| n.checked_add(10)) != Some(bytes.len())
        {
            return Err(ReplayError::Malformed);
        }
        let mut received = BTreeSet::new();
        let mut previous = None;
        for part in bytes[10..].as_chunks::<32>().0 {
            let id = *part;
            if previous.is_some_and(|p| p >= id) {
                return Err(ReplayError::Malformed);
            }
            received.insert(id);
            previous = Some(id);
        }
        Ok(Self { received })
    }
}

/// Caller verifies current sender trust, signature and decryption before recording.
/// The canonical Capsule bytes make binary/armored/URI transport spellings equivalent.
pub(crate) fn receipt_id(
    recipient: &EndpointCard,
    sender: &VerifiedContact,
    context: &str,
    delivery: &Delivery,
) -> Result<[u8; 32], ReplayError> {
    if delivery.signature.is_none() || context.is_empty() || context.len() > 256 {
        return Err(ReplayError::InvalidDelivery);
    }
    let bytes = delivery
        .capsule
        .encode(CapsuleLimits::default())
        .map_err(|_| ReplayError::InvalidDelivery)?;
    let mut hash = Sha256::new();
    hash.update(b"End-To-End Everywhere receive-once Capsule receipt v1\0");
    hash.update(recipient.fingerprint());
    hash.update(sender.card().fingerprint());
    hash.update((context.len() as u64).to_be_bytes());
    hash.update(context.as_bytes());
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
    Ok(hash.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strict_roundtrip_rejects_duplicates_unsorted_truncated_and_extended_records() {
        let mut ledger = ReplayLedger::default();
        ledger.record([2; 32]).unwrap();
        ledger.record([1; 32]).unwrap();
        let encoded = ledger.encode();
        let mut restored = ReplayLedger::decode(&encoded).unwrap();
        assert_eq!(restored.record([1; 32]), Err(ReplayError::AlreadyReceived));
        assert_eq!(restored.encode(), encoded);
        for mut malformed in [
            encoded[..encoded.len() - 1].to_vec(),
            [encoded.as_slice(), &[0]].concat(),
            encoded.clone(),
        ] {
            if malformed.len() == encoded.len() {
                malformed[42..74].copy_from_slice(&encoded[10..42]);
            }
            assert!(ReplayLedger::decode(&malformed).is_err());
        }
        let mut reversed = encoded.clone();
        reversed[10..42].copy_from_slice(&[2; 32]);
        reversed[42..74].copy_from_slice(&[1; 32]);
        assert!(ReplayLedger::decode(&reversed).is_err());
    }
    #[test]
    fn capacity_never_forgets_old_receipts() {
        let mut ledger = ReplayLedger::default();
        for i in 0..MAX_RECEIPTS {
            let mut id = [0; 32];
            id[..8].copy_from_slice(&(i as u64).to_be_bytes());
            ledger.record(id).unwrap();
        }
        assert_eq!(
            ledger.record([0xff; 32]),
            Err(ReplayError::CapacityExceeded)
        );
        assert_eq!(ledger.record([0; 32]), Err(ReplayError::AlreadyReceived));
        assert_eq!(ledger.encode().len(), MAX_LEDGER_BYTES);
        assert!(ReplayLedger::decode(&ledger.encode()).is_ok());
    }
}
