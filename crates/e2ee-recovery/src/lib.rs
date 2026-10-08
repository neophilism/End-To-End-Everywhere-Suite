#![forbid(unsafe_code)]

//! Backup and recovery policy for End-To-End Everywhere Suite.
//!
//! Restore is intentionally separate from device authorization. A valid backup
//! never turns an unverified device into an authorized E2EE endpoint.

use e2ee_core::{EndpointId, ProfileId, UserId};
use e2ee_keystore::SecretHandle;
use std::fmt;

pub const BACKUP_NONE_PROFILE: &str = "backup-none@0.1.0";
pub const BACKUP_USER_SECRET_PROFILE: &str = "backup-user-secret@0.1.0";
pub const BACKUP_HARDWARE_ASSISTED_PROFILE: &str = "backup-hardware-assisted@0.1.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryMode {
    None,
    UserSecret,
    HardwareAssisted,
}

pub fn recovery_mode(profile: &ProfileId) -> Result<RecoveryMode, RecoveryError> {
    match (profile.name(), profile.version()) {
        ("backup-none", "0.1.0") => Ok(RecoveryMode::None),
        ("backup-user-secret", "0.1.0") => Ok(RecoveryMode::UserSecret),
        ("backup-hardware-assisted", "0.1.0") => Ok(RecoveryMode::HardwareAssisted),
        _ => Err(RecoveryError::UnsupportedProfile),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct BackupGeneration(u64);

impl BackupGeneration {
    pub fn new(value: u64) -> Result<Self, RecoveryError> {
        if value == 0 {
            return Err(RecoveryError::InvalidGeneration);
        }
        Ok(Self(value))
    }

    pub fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2idParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Argon2idParams {
    pub fn validate_rfc9106_recommended_floor(self) -> Result<(), RecoveryError> {
        let first_recommended =
            self.memory_kib >= 2 * 1024 * 1024 && self.iterations >= 1 && self.parallelism >= 4;
        let second_recommended =
            self.memory_kib >= 64 * 1024 && self.iterations >= 3 && self.parallelism >= 4;

        if first_recommended || second_recommended {
            Ok(())
        } else {
            Err(RecoveryError::WeakPasswordKdf)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoverySecretKind {
    Generated { entropy_bits: u16 },
    UserPassphrase,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoverySecretPolicy {
    pub kind: RecoverySecretKind,
    pub argon2id: Argon2idParams,
    pub derivation_is_local: bool,
}

impl RecoverySecretPolicy {
    pub fn validate(&self) -> Result<(), RecoveryError> {
        if !self.derivation_is_local {
            return Err(RecoveryError::ServerSideSecretDerivation);
        }
        self.argon2id.validate_rfc9106_recommended_floor()?;
        if let RecoverySecretKind::Generated { entropy_bits } = self.kind {
            if entropy_bits < 128 {
                return Err(RecoveryError::WeakGeneratedRecoverySecret);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupManifest {
    pub user_id: UserId,
    pub source_endpoint_id: EndpointId,
    pub generation: BackupGeneration,
    pub suite_id: String,
    pub content_set_digest: [u8; 32],
}

impl BackupManifest {
    pub fn validate(&self) -> Result<(), RecoveryError> {
        if self.suite_id.is_empty() {
            return Err(RecoveryError::InvalidManifest);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardwareRecoveryEvidence {
    pub wrapping_key: SecretHandle,
    pub attestation: Vec<u8>,
    pub wrapping_key_non_exportable: bool,
    pub release_authenticated: bool,
    pub failed_attempt_rate_limiting: bool,
}

impl HardwareRecoveryEvidence {
    pub fn validate(&self) -> Result<(), RecoveryError> {
        if self.attestation.is_empty()
            || !self.wrapping_key_non_exportable
            || !self.release_authenticated
            || !self.failed_attempt_rate_limiting
        {
            return Err(RecoveryError::HardwareAssuranceIncomplete);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupEnvelope {
    pub profile: ProfileId,
    pub manifest: BackupManifest,
    pub encrypted_payload: Vec<u8>,
    pub wrapped_backup_data_key: Vec<u8>,
    pub recovery_secret_policy: RecoverySecretPolicy,
    pub hardware: Option<HardwareRecoveryEvidence>,
}

impl BackupEnvelope {
    pub fn validate(&self) -> Result<(), RecoveryError> {
        self.manifest.validate()?;
        if self.encrypted_payload.is_empty() || self.wrapped_backup_data_key.is_empty() {
            return Err(RecoveryError::InvalidEnvelope);
        }
        self.recovery_secret_policy.validate()?;

        match recovery_mode(&self.profile)? {
            RecoveryMode::None => Err(RecoveryError::BackupForbidden),
            RecoveryMode::UserSecret => {
                if self.hardware.is_some() {
                    return Err(RecoveryError::UnexpectedHardwareLayer);
                }
                Ok(())
            }
            RecoveryMode::HardwareAssisted => self
                .hardware
                .as_ref()
                .ok_or(RecoveryError::HardwareAssuranceIncomplete)?
                .validate(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryError {
    UnsupportedProfile,
    InvalidGeneration,
    WeakPasswordKdf,
    WeakGeneratedRecoverySecret,
    ServerSideSecretDerivation,
    InvalidManifest,
    InvalidEnvelope,
    BackupForbidden,
    UnexpectedHardwareLayer,
    HardwareAssuranceIncomplete,
    DeviceNotAuthorized,
    RollbackDetected,
}

impl fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UnsupportedProfile => "backup/recovery profile is unsupported",
            Self::InvalidGeneration => "backup generation is invalid",
            Self::WeakPasswordKdf => "Argon2id parameters are below the accepted RFC 9106 floor",
            Self::WeakGeneratedRecoverySecret => {
                "generated recovery secret has less than 128 bits of entropy"
            }
            Self::ServerSideSecretDerivation => "recovery secret derivation must occur locally",
            Self::InvalidManifest => "backup manifest is invalid",
            Self::InvalidEnvelope => "backup envelope is invalid",
            Self::BackupForbidden => "selected profile forbids persistent recoverable backups",
            Self::UnexpectedHardwareLayer => "user-secret profile must not claim a hardware layer",
            Self::HardwareAssuranceIncomplete => "hardware recovery assurance is incomplete",
            Self::DeviceNotAuthorized => "restore requires an already authorized device",
            Self::RollbackDetected => "stale backup generation was rejected",
        };
        f.write_str(message)
    }
}

impl std::error::Error for RecoveryError {}

#[derive(Debug, Clone)]
pub struct RestoreGuard {
    device_authorized: bool,
    minimum_generation: BackupGeneration,
}

impl RestoreGuard {
    pub fn new(device_authorized: bool, minimum_generation: BackupGeneration) -> Self {
        Self {
            device_authorized,
            minimum_generation,
        }
    }

    pub fn set_device_authorized(&mut self, authorized: bool) {
        self.device_authorized = authorized;
    }

    pub fn validate_restore(&mut self, envelope: &BackupEnvelope) -> Result<(), RecoveryError> {
        if !self.device_authorized {
            return Err(RecoveryError::DeviceNotAuthorized);
        }
        envelope.validate()?;
        if envelope.manifest.generation < self.minimum_generation {
            return Err(RecoveryError::RollbackDetected);
        }
        self.minimum_generation = envelope.manifest.generation;
        Ok(())
    }

    pub fn minimum_generation(&self) -> BackupGeneration {
        self.minimum_generation
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret_policy() -> RecoverySecretPolicy {
        RecoverySecretPolicy {
            kind: RecoverySecretKind::Generated { entropy_bits: 128 },
            argon2id: Argon2idParams {
                memory_kib: 64 * 1024,
                iterations: 3,
                parallelism: 4,
            },
            derivation_is_local: true,
        }
    }

    fn envelope(profile: &str, generation: u64) -> BackupEnvelope {
        BackupEnvelope {
            profile: ProfileId::parse(profile).unwrap(),
            manifest: BackupManifest {
                user_id: UserId::parse("alice").unwrap(),
                source_endpoint_id: EndpointId::parse("alice-phone").unwrap(),
                generation: BackupGeneration::new(generation).unwrap(),
                suite_id: "backup-suite-1".into(),
                content_set_digest: [4; 32],
            },
            encrypted_payload: vec![1, 2, 3],
            wrapped_backup_data_key: vec![8, 9],
            recovery_secret_policy: secret_policy(),
            hardware: None,
        }
    }

    #[test]
    fn restore_never_authorizes_a_device() {
        let mut guard = RestoreGuard::new(false, BackupGeneration::new(1).unwrap());
        assert_eq!(
            guard.validate_restore(&envelope(BACKUP_USER_SECRET_PROFILE, 1)),
            Err(RecoveryError::DeviceNotAuthorized)
        );
    }

    #[test]
    fn stale_generation_is_rejected() {
        let mut guard = RestoreGuard::new(true, BackupGeneration::new(4).unwrap());
        assert_eq!(
            guard.validate_restore(&envelope(BACKUP_USER_SECRET_PROFILE, 3)),
            Err(RecoveryError::RollbackDetected)
        );
    }

    #[test]
    fn generated_recovery_secret_requires_128_bits() {
        let mut candidate = envelope(BACKUP_USER_SECRET_PROFILE, 1);
        candidate.recovery_secret_policy.kind = RecoverySecretKind::Generated { entropy_bits: 127 };
        assert_eq!(
            candidate.validate(),
            Err(RecoveryError::WeakGeneratedRecoverySecret)
        );
    }

    #[test]
    fn no_backup_profile_forbids_envelope() {
        assert_eq!(
            envelope(BACKUP_NONE_PROFILE, 1).validate(),
            Err(RecoveryError::BackupForbidden)
        );
    }

    #[test]
    fn hardware_assisted_requires_assurance_evidence() {
        assert_eq!(
            envelope(BACKUP_HARDWARE_ASSISTED_PROFILE, 1).validate(),
            Err(RecoveryError::HardwareAssuranceIncomplete)
        );
    }

    #[test]
    fn hardware_assisted_accepts_complete_evidence() {
        let mut candidate = envelope(BACKUP_HARDWARE_ASSISTED_PROFILE, 1);
        candidate.hardware = Some(HardwareRecoveryEvidence {
            wrapping_key: SecretHandle::parse("recovery/hardware/root").unwrap(),
            attestation: vec![1],
            wrapping_key_non_exportable: true,
            release_authenticated: true,
            failed_attempt_rate_limiting: true,
        });
        assert!(candidate.validate().is_ok());
    }

    #[test]
    fn accepted_restore_advances_rollback_floor() {
        let mut guard = RestoreGuard::new(true, BackupGeneration::new(1).unwrap());
        guard
            .validate_restore(&envelope(BACKUP_USER_SECRET_PROFILE, 3))
            .unwrap();
        assert_eq!(guard.minimum_generation().get(), 3);
    }
}
