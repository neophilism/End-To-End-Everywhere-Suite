//! Host-platform key-store contract with explicit attestation validation.
//!
//! This module does not implement an operating-system key store by itself. A
//! platform bridge must keep key bytes outside Rust and return an opaque handle
//! plus evidence about the key that was actually created. Portable callers then
//! validate that evidence before accepting the handle.

use crate::{
    expected_backend, validate_backend_for_profile, validate_generation, BackendKind, ExportPolicy,
    KeyStoreError, ProvisionRequest, SecretHandle, SecretMetadata, SecureKeyStore,
};
use e2ee_core::ProfileId;

const MAX_PROVIDER_NAME_BYTES: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationLevel {
    OperatingSystemProtected,
    HardwareBacked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformAttestation {
    pub provider: String,
    pub handle: SecretHandle,
    pub profile: ProfileId,
    pub backend: BackendKind,
    pub level: AttestationLevel,
    pub exportable: bool,
    pub rollback_resistant: bool,
    pub generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedSecret {
    pub metadata: SecretMetadata,
    pub attestation: PlatformAttestation,
}

/// Boundary implemented by a reviewed platform-specific component.
///
/// Implementations must not return key bytes. An error or missing attestation
/// fails provisioning; the adapter never changes the requested profile.
pub trait PlatformBridge {
    fn profile(&self) -> &ProfileId;
    fn backend_kind(&self) -> BackendKind;

    fn provision_attested(
        &mut self,
        request: &ProvisionRequest,
    ) -> Result<AttestedSecret, KeyStoreError>;

    fn metadata_attested(&self, handle: &SecretHandle) -> Result<AttestedSecret, KeyStoreError>;
}

pub struct PlatformKeyStore<B> {
    bridge: B,
}

impl<B: PlatformBridge> PlatformKeyStore<B> {
    pub fn new(bridge: B) -> Result<Self, KeyStoreError> {
        validate_platform_profile(bridge.profile(), bridge.backend_kind())?;
        Ok(Self { bridge })
    }

    pub fn into_bridge(self) -> B {
        self.bridge
    }

    fn validate(
        &self,
        secret: AttestedSecret,
        minimum_generation: u64,
    ) -> Result<SecretMetadata, KeyStoreError> {
        validate_attestation(
            self.profile(),
            self.backend_kind(),
            &secret.metadata,
            &secret.attestation,
            minimum_generation,
        )?;
        Ok(secret.metadata)
    }
}

impl<B: PlatformBridge> SecureKeyStore for PlatformKeyStore<B> {
    fn profile(&self) -> &ProfileId {
        self.bridge.profile()
    }

    fn backend_kind(&self) -> BackendKind {
        self.bridge.backend_kind()
    }

    fn provision(&mut self, request: ProvisionRequest) -> Result<SecretMetadata, KeyStoreError> {
        if &request.required_profile != self.profile() {
            return Err(KeyStoreError::UnsupportedProfile);
        }
        validate_platform_profile(&request.required_profile, self.backend_kind())?;
        let minimum_generation = request.minimum_generation;
        let secret = self.bridge.provision_attested(&request)?;
        self.validate(secret, minimum_generation)
    }

    fn metadata(&self, handle: &SecretHandle) -> Result<SecretMetadata, KeyStoreError> {
        let secret = self.bridge.metadata_attested(handle)?;
        if &secret.metadata.handle != handle {
            return Err(KeyStoreError::AttestationInvalid);
        }
        self.validate(secret, 1)
    }
}

pub fn select_backend(
    required_profile: &ProfileId,
    platform_available: bool,
) -> Result<BackendKind, KeyStoreError> {
    let backend = expected_backend(required_profile)?;
    match backend {
        BackendKind::PlatformKeystore | BackendKind::HardwareIsolated if !platform_available => {
            Err(KeyStoreError::BackendUnavailable)
        }
        _ => Ok(backend),
    }
}

pub fn validate_attestation(
    profile: &ProfileId,
    backend: BackendKind,
    metadata: &SecretMetadata,
    attestation: &PlatformAttestation,
    minimum_generation: u64,
) -> Result<(), KeyStoreError> {
    validate_platform_profile(profile, backend)?;
    validate_backend_for_profile(profile, metadata.backend)?;
    validate_generation(minimum_generation, metadata.generation)?;

    if &metadata.handle != &attestation.handle
        || metadata.backend != attestation.backend
        || metadata.generation != attestation.generation
        || &attestation.profile != profile
        || metadata.export_policy != ExportPolicy::NonExportable
        || attestation.exportable
        || attestation.provider.is_empty()
        || attestation.provider.len() > MAX_PROVIDER_NAME_BYTES
        || !attestation.provider.is_ascii()
    {
        return Err(KeyStoreError::AttestationInvalid);
    }

    match backend {
        BackendKind::PlatformKeystore => {}
        BackendKind::HardwareIsolated
            if attestation.level == AttestationLevel::HardwareBacked
                && attestation.rollback_resistant => {}
        BackendKind::HardwareIsolated => return Err(KeyStoreError::AttestationInvalid),
        _ => return Err(KeyStoreError::PolicyViolation),
    }

    Ok(())
}

fn validate_platform_profile(
    profile: &ProfileId,
    backend: BackendKind,
) -> Result<(), KeyStoreError> {
    validate_backend_for_profile(profile, backend)?;
    match backend {
        BackendKind::PlatformKeystore | BackendKind::HardwareIsolated => Ok(()),
        _ => Err(KeyStoreError::PolicyViolation),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        SecretClass, HARDWARE_ISOLATED_PROFILE, PLATFORM_KEYSTORE_PROFILE, SOFTWARE_VAULT_PROFILE,
    };

    struct Bridge {
        profile: ProfileId,
        backend: BackendKind,
        level: AttestationLevel,
        exportable: bool,
        rollback_resistant: bool,
        generation: u64,
    }

    impl Bridge {
        fn secret(&self, request: &ProvisionRequest) -> AttestedSecret {
            let metadata = SecretMetadata {
                handle: request.handle.clone(),
                class: request.class,
                backend: self.backend,
                export_policy: ExportPolicy::NonExportable,
                generation: self.generation,
            };
            AttestedSecret {
                metadata,
                attestation: PlatformAttestation {
                    provider: "test-platform".to_owned(),
                    handle: request.handle.clone(),
                    profile: self.profile.clone(),
                    backend: self.backend,
                    level: self.level,
                    exportable: self.exportable,
                    rollback_resistant: self.rollback_resistant,
                    generation: self.generation,
                },
            }
        }
    }

    impl PlatformBridge for Bridge {
        fn profile(&self) -> &ProfileId {
            &self.profile
        }

        fn backend_kind(&self) -> BackendKind {
            self.backend
        }

        fn provision_attested(
            &mut self,
            request: &ProvisionRequest,
        ) -> Result<AttestedSecret, KeyStoreError> {
            Ok(self.secret(request))
        }

        fn metadata_attested(
            &self,
            handle: &SecretHandle,
        ) -> Result<AttestedSecret, KeyStoreError> {
            self.provision_view(handle)
        }
    }

    impl Bridge {
        fn provision_view(&self, handle: &SecretHandle) -> Result<AttestedSecret, KeyStoreError> {
            Ok(self.secret(&ProvisionRequest {
                handle: handle.clone(),
                class: SecretClass::DeviceIdentityRoot,
                required_profile: self.profile.clone(),
                minimum_generation: 1,
            }))
        }
    }

    fn request(profile: &str, minimum_generation: u64) -> ProvisionRequest {
        ProvisionRequest {
            handle: SecretHandle::parse("device/root/1").unwrap(),
            class: SecretClass::DeviceIdentityRoot,
            required_profile: ProfileId::parse(profile).unwrap(),
            minimum_generation,
        }
    }

    #[test]
    fn platform_profile_accepts_nonexportable_os_attestation() {
        let mut store = PlatformKeyStore::new(Bridge {
            profile: ProfileId::parse(PLATFORM_KEYSTORE_PROFILE).unwrap(),
            backend: BackendKind::PlatformKeystore,
            level: AttestationLevel::OperatingSystemProtected,
            exportable: false,
            rollback_resistant: false,
            generation: 4,
        })
        .unwrap();

        assert_eq!(
            store
                .provision(request(PLATFORM_KEYSTORE_PROFILE, 4))
                .unwrap()
                .generation,
            4
        );
    }

    #[test]
    fn hardware_profile_requires_hardware_and_rollback_evidence() {
        let mut store = PlatformKeyStore::new(Bridge {
            profile: ProfileId::parse(HARDWARE_ISOLATED_PROFILE).unwrap(),
            backend: BackendKind::HardwareIsolated,
            level: AttestationLevel::OperatingSystemProtected,
            exportable: false,
            rollback_resistant: false,
            generation: 1,
        })
        .unwrap();

        assert_eq!(
            store.provision(request(HARDWARE_ISOLATED_PROFILE, 1)),
            Err(KeyStoreError::AttestationInvalid)
        );
    }

    #[test]
    fn exportable_platform_key_is_rejected() {
        let mut store = PlatformKeyStore::new(Bridge {
            profile: ProfileId::parse(PLATFORM_KEYSTORE_PROFILE).unwrap(),
            backend: BackendKind::PlatformKeystore,
            level: AttestationLevel::OperatingSystemProtected,
            exportable: true,
            rollback_resistant: false,
            generation: 1,
        })
        .unwrap();

        assert_eq!(
            store.provision(request(PLATFORM_KEYSTORE_PROFILE, 1)),
            Err(KeyStoreError::AttestationInvalid)
        );
    }

    #[test]
    fn attested_generation_cannot_roll_back() {
        let mut store = PlatformKeyStore::new(Bridge {
            profile: ProfileId::parse(PLATFORM_KEYSTORE_PROFILE).unwrap(),
            backend: BackendKind::PlatformKeystore,
            level: AttestationLevel::OperatingSystemProtected,
            exportable: false,
            rollback_resistant: false,
            generation: 3,
        })
        .unwrap();

        assert_eq!(
            store.provision(request(PLATFORM_KEYSTORE_PROFILE, 4)),
            Err(KeyStoreError::RollbackDetected)
        );
    }

    #[test]
    fn unavailable_platform_never_changes_to_software_profile() {
        let platform = ProfileId::parse(PLATFORM_KEYSTORE_PROFILE).unwrap();
        let software = ProfileId::parse(SOFTWARE_VAULT_PROFILE).unwrap();

        assert_eq!(
            select_backend(&platform, false),
            Err(KeyStoreError::BackendUnavailable)
        );
        assert_eq!(
            select_backend(&software, false),
            Ok(BackendKind::SoftwareVault)
        );
    }
}
