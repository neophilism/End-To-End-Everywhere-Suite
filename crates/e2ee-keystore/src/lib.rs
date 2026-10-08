#![forbid(unsafe_code)]

//! Secure key-store policy and provider contracts.
//!
//! This crate deliberately exposes opaque root-key handles rather than root-key
//! bytes. Concrete platform adapters must satisfy the selected E2EESA profile;
//! callers never silently fall back to a weaker backend.

use e2ee_core::{ProfileId, ProfileParseError};
use std::fmt;

pub const PLATFORM_KEYSTORE_PROFILE: &str = "secret-platform-keystore@0.1.0";
pub const HARDWARE_ISOLATED_PROFILE: &str = "secret-hardware-isolated@0.1.0";
pub const EXTERNAL_TOKEN_PROFILE: &str = "secret-external-token@0.1.0";
pub const SOFTWARE_VAULT_PROFILE: &str = "secret-software-vault@0.1.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretClass {
    DeviceIdentityRoot,
    ProtocolStateWrappingRoot,
    RecoveryRoot,
    TransparencyCheckpoint,
    Credential,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    PlatformKeystore,
    HardwareIsolated,
    ExternalToken,
    SoftwareVault,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportPolicy {
    NonExportable,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecretHandle(String);

impl SecretHandle {
    pub fn parse(value: &str) -> Result<Self, KeyStoreError> {
        if value.is_empty() {
            return Err(KeyStoreError::InvalidHandle);
        }
        if !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':' | b'/'))
        {
            return Err(KeyStoreError::InvalidHandle);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretMetadata {
    pub handle: SecretHandle,
    pub class: SecretClass,
    pub backend: BackendKind,
    pub export_policy: ExportPolicy,
    pub generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionRequest {
    pub handle: SecretHandle,
    pub class: SecretClass,
    pub required_profile: ProfileId,
    pub minimum_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyStoreError {
    InvalidHandle,
    UnsupportedProfile,
    BackendUnavailable,
    PolicyViolation,
    RollbackDetected,
    NotFound,
}

impl fmt::Display for KeyStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidHandle => "secret handle is invalid",
            Self::UnsupportedProfile => "requested secret-storage profile is unsupported",
            Self::BackendUnavailable => "required secure key-store backend is unavailable",
            Self::PolicyViolation => "secure key-store policy was violated",
            Self::RollbackDetected => "secret generation rollback was detected",
            Self::NotFound => "secret handle was not found",
        };
        f.write_str(message)
    }
}

impl std::error::Error for KeyStoreError {}

impl From<ProfileParseError> for KeyStoreError {
    fn from(_: ProfileParseError) -> Self {
        Self::UnsupportedProfile
    }
}

pub trait SecureKeyStore {
    /// Exact E2EESA secret-storage profile implemented by this backend.
    fn profile(&self) -> &ProfileId;

    fn backend_kind(&self) -> BackendKind;

    /// Provision an opaque root secret. Implementations must not return raw key
    /// material through this API.
    fn provision(&mut self, request: ProvisionRequest) -> Result<SecretMetadata, KeyStoreError>;

    fn metadata(&self, handle: &SecretHandle) -> Result<SecretMetadata, KeyStoreError>;
}

pub fn expected_backend(profile: &ProfileId) -> Result<BackendKind, KeyStoreError> {
    match (profile.name(), profile.version()) {
        ("secret-platform-keystore", "0.1.0") => Ok(BackendKind::PlatformKeystore),
        ("secret-hardware-isolated", "0.1.0") => Ok(BackendKind::HardwareIsolated),
        ("secret-external-token", "0.1.0") => Ok(BackendKind::ExternalToken),
        ("secret-software-vault", "0.1.0") => Ok(BackendKind::SoftwareVault),
        _ => Err(KeyStoreError::UnsupportedProfile),
    }
}

pub fn validate_backend_for_profile(
    profile: &ProfileId,
    actual_backend: BackendKind,
) -> Result<(), KeyStoreError> {
    let expected = expected_backend(profile)?;
    if expected != actual_backend {
        return Err(KeyStoreError::PolicyViolation);
    }
    Ok(())
}

pub fn validate_generation(
    minimum_generation: u64,
    actual_generation: u64,
) -> Result<(), KeyStoreError> {
    if actual_generation < minimum_generation {
        return Err(KeyStoreError::RollbackDetected);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    struct MetadataOnlyBackend {
        profile: ProfileId,
        kind: BackendKind,
        records: BTreeMap<SecretHandle, SecretMetadata>,
    }

    impl MetadataOnlyBackend {
        fn new(profile: &str, kind: BackendKind) -> Self {
            Self {
                profile: ProfileId::parse(profile).unwrap(),
                kind,
                records: BTreeMap::new(),
            }
        }
    }

    impl SecureKeyStore for MetadataOnlyBackend {
        fn profile(&self) -> &ProfileId {
            &self.profile
        }

        fn backend_kind(&self) -> BackendKind {
            self.kind
        }

        fn provision(
            &mut self,
            request: ProvisionRequest,
        ) -> Result<SecretMetadata, KeyStoreError> {
            validate_backend_for_profile(&request.required_profile, self.kind)?;
            if request.required_profile != self.profile {
                return Err(KeyStoreError::UnsupportedProfile);
            }

            let next_generation = match self.records.get(&request.handle) {
                Some(existing) => existing.generation.saturating_add(1),
                None => request.minimum_generation,
            };
            validate_generation(request.minimum_generation, next_generation)?;

            let metadata = SecretMetadata {
                handle: request.handle.clone(),
                class: request.class,
                backend: self.kind,
                export_policy: ExportPolicy::NonExportable,
                generation: next_generation,
            };
            self.records.insert(request.handle, metadata.clone());
            Ok(metadata)
        }

        fn metadata(&self, handle: &SecretHandle) -> Result<SecretMetadata, KeyStoreError> {
            self.records
                .get(handle)
                .cloned()
                .ok_or(KeyStoreError::NotFound)
        }
    }

    #[test]
    fn hardware_profile_never_silently_falls_back_to_software() {
        let profile = ProfileId::parse(HARDWARE_ISOLATED_PROFILE).unwrap();
        assert_eq!(
            validate_backend_for_profile(&profile, BackendKind::SoftwareVault),
            Err(KeyStoreError::PolicyViolation)
        );
    }

    #[test]
    fn root_secret_is_represented_only_by_opaque_handle() {
        let handle = SecretHandle::parse("device/root/1").unwrap();
        assert_eq!(handle.as_str(), "device/root/1");
    }

    #[test]
    fn provisioning_binds_exact_profile_and_nonexportability() {
        let mut backend =
            MetadataOnlyBackend::new(PLATFORM_KEYSTORE_PROFILE, BackendKind::PlatformKeystore);
        let metadata = backend
            .provision(ProvisionRequest {
                handle: SecretHandle::parse("device/root/1").unwrap(),
                class: SecretClass::DeviceIdentityRoot,
                required_profile: ProfileId::parse(PLATFORM_KEYSTORE_PROFILE).unwrap(),
                minimum_generation: 7,
            })
            .unwrap();

        assert_eq!(metadata.generation, 7);
        assert_eq!(metadata.export_policy, ExportPolicy::NonExportable);
    }

    #[test]
    fn generation_rollback_is_rejected() {
        assert_eq!(
            validate_generation(8, 7),
            Err(KeyStoreError::RollbackDetected)
        );
    }
}
