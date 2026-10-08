#![forbid(unsafe_code)]

//! Recipient directory and transparency verification.
//!
//! Directory responses remain untrusted until an independent verifier accepts
//! the checkpoint, inclusion proof, and any required consistency proof.

use e2ee_core::{DeviceId, EndpointId, RecipientAddress, UserId};
use std::collections::BTreeSet;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyId(String);

impl KeyId {
    pub fn parse(value: &str) -> Result<Self, DirectoryError> {
        if value.is_empty()
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
        {
            return Err(DirectoryError::InvalidRecord);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientKey {
    pub key_id: KeyId,
    pub suite_id: String,
    pub encoded_public_key: Vec<u8>,
}

impl RecipientKey {
    fn validate(&self) -> Result<(), DirectoryError> {
        if self.suite_id.is_empty() || self.encoded_public_key.is_empty() {
            return Err(DirectoryError::InvalidRecord);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointBinding {
    pub device_id: DeviceId,
    pub endpoint_id: EndpointId,
    pub recipient_key: RecipientKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryRecord {
    pub address: RecipientAddress,
    pub user_id: UserId,
    pub generation: u64,
    pub endpoints: Vec<EndpointBinding>,
}

impl DirectoryRecord {
    pub fn validate(&self) -> Result<(), DirectoryError> {
        if self.endpoints.is_empty() {
            return Err(DirectoryError::InvalidRecord);
        }

        let mut endpoints = BTreeSet::new();
        let mut keys = BTreeSet::new();
        for binding in &self.endpoints {
            binding.recipient_key.validate()?;
            if !endpoints.insert(binding.endpoint_id.as_str().to_owned()) {
                return Err(DirectoryError::DuplicateEndpoint);
            }
            if !keys.insert(binding.recipient_key.key_id.clone()) {
                return Err(DirectoryError::DuplicateKey);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparencyCheckpoint {
    pub log_id: String,
    pub tree_size: u64,
    pub root_hash: [u8; 32],
    pub signed_checkpoint: Vec<u8>,
}

impl TransparencyCheckpoint {
    fn validate(&self) -> Result<(), DirectoryError> {
        if self.log_id.is_empty() || self.tree_size == 0 || self.signed_checkpoint.is_empty() {
            return Err(DirectoryError::InvalidCheckpoint);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    pub leaf_index: u64,
    pub audit_path: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsistencyProof {
    pub from_tree_size: u64,
    pub to_tree_size: u64,
    pub path: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryResponse {
    pub record: DirectoryRecord,
    pub checkpoint: TransparencyCheckpoint,
    pub inclusion_proof: InclusionProof,
    pub consistency_proof: Option<ConsistencyProof>,
}

pub trait TransparencyVerifier {
    fn verify_checkpoint(&self, checkpoint: &TransparencyCheckpoint) -> bool;

    fn verify_inclusion(
        &self,
        record: &DirectoryRecord,
        checkpoint: &TransparencyCheckpoint,
        proof: &InclusionProof,
    ) -> bool;

    fn verify_consistency(
        &self,
        previous: &TransparencyCheckpoint,
        current: &TransparencyCheckpoint,
        proof: &ConsistencyProof,
    ) -> bool;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDirectoryRecord {
    pub record: DirectoryRecord,
    pub checkpoint: TransparencyCheckpoint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectoryError {
    AddressMismatch,
    InvalidRecord,
    DuplicateEndpoint,
    DuplicateKey,
    InvalidCheckpoint,
    CheckpointSignatureInvalid,
    LogChanged,
    RollbackDetected,
    EquivocationDetected,
    MissingConsistencyProof,
    InvalidConsistencyProof,
    InclusionProofInvalid,
}

impl fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::AddressMismatch => "directory response address does not match request",
            Self::InvalidRecord => "directory record is invalid",
            Self::DuplicateEndpoint => "directory record repeats an endpoint",
            Self::DuplicateKey => "directory record repeats a recipient key",
            Self::InvalidCheckpoint => "transparency checkpoint is invalid",
            Self::CheckpointSignatureInvalid => "transparency checkpoint authentication failed",
            Self::LogChanged => "transparency log identity changed unexpectedly",
            Self::RollbackDetected => "transparency checkpoint rollback detected",
            Self::EquivocationDetected => "conflicting roots exist at the same tree size",
            Self::MissingConsistencyProof => "advancing checkpoint lacks a consistency proof",
            Self::InvalidConsistencyProof => "transparency consistency proof is invalid",
            Self::InclusionProofInvalid => "directory record inclusion proof is invalid",
        };
        f.write_str(message)
    }
}

impl std::error::Error for DirectoryError {}

pub struct DirectoryClient<V> {
    verifier: V,
    pinned_checkpoint: Option<TransparencyCheckpoint>,
}

impl<V: TransparencyVerifier> DirectoryClient<V> {
    pub fn new(verifier: V) -> Self {
        Self {
            verifier,
            pinned_checkpoint: None,
        }
    }

    pub fn pinned_checkpoint(&self) -> Option<&TransparencyCheckpoint> {
        self.pinned_checkpoint.as_ref()
    }

    pub fn verify_lookup(
        &mut self,
        requested: &RecipientAddress,
        response: DirectoryResponse,
    ) -> Result<VerifiedDirectoryRecord, DirectoryError> {
        response.record.validate()?;
        response.checkpoint.validate()?;

        if &response.record.address != requested {
            return Err(DirectoryError::AddressMismatch);
        }
        if !self.verifier.verify_checkpoint(&response.checkpoint) {
            return Err(DirectoryError::CheckpointSignatureInvalid);
        }

        if let Some(previous) = &self.pinned_checkpoint {
            if previous.log_id != response.checkpoint.log_id {
                return Err(DirectoryError::LogChanged);
            }
            if response.checkpoint.tree_size < previous.tree_size {
                return Err(DirectoryError::RollbackDetected);
            }
            if response.checkpoint.tree_size == previous.tree_size
                && response.checkpoint.root_hash != previous.root_hash
            {
                return Err(DirectoryError::EquivocationDetected);
            }
            if response.checkpoint.tree_size > previous.tree_size {
                let proof = response
                    .consistency_proof
                    .as_ref()
                    .ok_or(DirectoryError::MissingConsistencyProof)?;
                if proof.from_tree_size != previous.tree_size
                    || proof.to_tree_size != response.checkpoint.tree_size
                    || !self
                        .verifier
                        .verify_consistency(previous, &response.checkpoint, proof)
                {
                    return Err(DirectoryError::InvalidConsistencyProof);
                }
            }
        }

        if !self.verifier.verify_inclusion(
            &response.record,
            &response.checkpoint,
            &response.inclusion_proof,
        ) {
            return Err(DirectoryError::InclusionProofInvalid);
        }

        self.pinned_checkpoint = Some(response.checkpoint.clone());
        Ok(VerifiedDirectoryRecord {
            record: response.record,
            checkpoint: response.checkpoint,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy)]
    struct TestVerifier {
        checkpoint: bool,
        inclusion: bool,
        consistency: bool,
    }

    impl TransparencyVerifier for TestVerifier {
        fn verify_checkpoint(&self, _: &TransparencyCheckpoint) -> bool {
            self.checkpoint
        }

        fn verify_inclusion(
            &self,
            _: &DirectoryRecord,
            _: &TransparencyCheckpoint,
            _: &InclusionProof,
        ) -> bool {
            self.inclusion
        }

        fn verify_consistency(
            &self,
            _: &TransparencyCheckpoint,
            _: &TransparencyCheckpoint,
            _: &ConsistencyProof,
        ) -> bool {
            self.consistency
        }
    }

    fn address() -> RecipientAddress {
        RecipientAddress::parse("alice@example.org").unwrap()
    }

    fn record(generation: u64) -> DirectoryRecord {
        DirectoryRecord {
            address: address(),
            user_id: UserId::parse("alice").unwrap(),
            generation,
            endpoints: vec![EndpointBinding {
                device_id: DeviceId::parse("phone").unwrap(),
                endpoint_id: EndpointId::parse("alice-phone").unwrap(),
                recipient_key: RecipientKey {
                    key_id: KeyId::parse("key-1").unwrap(),
                    suite_id: "suite-1".into(),
                    encoded_public_key: vec![1, 2, 3],
                },
            }],
        }
    }

    fn checkpoint(size: u64, root: u8) -> TransparencyCheckpoint {
        TransparencyCheckpoint {
            log_id: "log-1".into(),
            tree_size: size,
            root_hash: [root; 32],
            signed_checkpoint: vec![9],
        }
    }

    fn response(size: u64, root: u8, with_consistency: bool) -> DirectoryResponse {
        DirectoryResponse {
            record: record(size),
            checkpoint: checkpoint(size, root),
            inclusion_proof: InclusionProof {
                leaf_index: 0,
                audit_path: vec![],
            },
            consistency_proof: with_consistency.then(|| ConsistencyProof {
                from_tree_size: size - 1,
                to_tree_size: size,
                path: vec![],
            }),
        }
    }

    fn verifier() -> TestVerifier {
        TestVerifier {
            checkpoint: true,
            inclusion: true,
            consistency: true,
        }
    }

    #[test]
    fn returns_record_only_after_transparency_verification() {
        let mut client = DirectoryClient::new(verifier());
        let verified = client
            .verify_lookup(&address(), response(1, 1, false))
            .unwrap();
        assert_eq!(verified.record.address, address());
        assert_eq!(client.pinned_checkpoint().unwrap().tree_size, 1);
    }

    #[test]
    fn rejects_invalid_inclusion_proof() {
        let mut client = DirectoryClient::new(TestVerifier {
            checkpoint: true,
            inclusion: false,
            consistency: true,
        });
        assert!(matches!(
            client.verify_lookup(&address(), response(1, 1, false)),
            Err(DirectoryError::InclusionProofInvalid)
        ));
    }

    #[test]
    fn detects_same_size_equivocation() {
        let mut client = DirectoryClient::new(verifier());
        client
            .verify_lookup(&address(), response(1, 1, false))
            .unwrap();
        assert!(matches!(
            client.verify_lookup(&address(), response(1, 2, false)),
            Err(DirectoryError::EquivocationDetected)
        ));
    }

    #[test]
    fn rejects_checkpoint_rollback() {
        let mut client = DirectoryClient::new(verifier());
        client
            .verify_lookup(&address(), response(2, 2, false))
            .unwrap();
        assert!(matches!(
            client.verify_lookup(&address(), response(1, 1, false)),
            Err(DirectoryError::RollbackDetected)
        ));
    }

    #[test]
    fn advancing_tree_requires_consistency_proof() {
        let mut client = DirectoryClient::new(verifier());
        client
            .verify_lookup(&address(), response(1, 1, false))
            .unwrap();
        assert!(matches!(
            client.verify_lookup(&address(), response(2, 2, false)),
            Err(DirectoryError::MissingConsistencyProof)
        ));
    }

    #[test]
    fn advancing_tree_accepts_verified_consistency() {
        let mut client = DirectoryClient::new(verifier());
        client
            .verify_lookup(&address(), response(1, 1, false))
            .unwrap();
        let verified = client
            .verify_lookup(&address(), response(2, 2, true))
            .unwrap();
        assert_eq!(verified.checkpoint.tree_size, 2);
    }
}
