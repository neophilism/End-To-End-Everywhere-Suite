//! Explicit software-vault fallback. This module never claims hardware isolation.
//!
//! Snapshot rollback protection depends on an independently trusted vault ID and
//! revision floor. State rollback protection similarly needs a trusted sequence
//! floor; an old authenticated ciphertext is otherwise still authentic.

use crate::{
    BackendKind, ExportPolicy, KeyStoreError, ProvisionRequest, SecretClass, SecretHandle,
    SecretMetadata, SecureKeyStore, SOFTWARE_VAULT_PROFILE,
};
use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use e2ee_core::ProfileId;
use std::{collections::BTreeMap, fmt};
use zeroize::Zeroizing;

const SNAPSHOT_HEADER: usize = 74;
const STATE_HEADER: usize = 38;
const MAX_ROOTS: usize = 1024;
const MAX_HANDLE: usize = 512;
pub const MAX_SNAPSHOT_BYTES: usize = 1024 * 1024;
pub const MAX_STATE_BYTES: usize = 1024 * 1024;
pub const VAULT_SNAPSHOT_VERSION: u16 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultKdf {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for VaultKdf {
    fn default() -> Self {
        Self {
            memory_kib: 64 * 1024,
            iterations: 3,
            parallelism: 4,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfBudget {
    pub max_memory_kib: u32,
    pub max_iterations: u32,
    pub max_parallelism: u32,
}

impl Default for KdfBudget {
    fn default() -> Self {
        Self {
            max_memory_kib: 256 * 1024,
            max_iterations: 10,
            max_parallelism: 8,
        }
    }
}

impl VaultKdf {
    fn params(self, budget: KdfBudget) -> Result<Params, VaultError> {
        let rfc_first =
            self.memory_kib >= 2 * 1024 * 1024 && self.iterations >= 1 && self.parallelism >= 4;
        let rfc_second =
            self.memory_kib >= 64 * 1024 && self.iterations >= 3 && self.parallelism >= 4;
        if !(rfc_first || rfc_second) {
            return Err(VaultError::WeakKdf);
        }
        if self.memory_kib > budget.max_memory_kib
            || self.iterations > budget.max_iterations
            || self.parallelism > budget.max_parallelism
        {
            return Err(VaultError::KdfBudgetExceeded);
        }
        Params::new(self.memory_kib, self.iterations, self.parallelism, Some(32))
            .map_err(|_| VaultError::WeakKdf)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultError {
    KeyStore(KeyStoreError),
    InvalidPassphrase,
    WeakKdf,
    KdfBudgetExceeded,
    DerivationFailed,
    Malformed,
    UnsupportedVersion,
    AuthenticationFailed,
    WrongVault,
    RollbackDetected,
    LimitExceeded,
    InvalidContext,
    EncryptFailed,
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::KeyStore(_) => "software vault key-store operation failed",
            Self::InvalidPassphrase => "unlock passphrase must contain 12 to 1024 bytes",
            Self::WeakKdf => "Argon2id parameters are below the RFC 9106 floor or invalid",
            Self::KdfBudgetExceeded => "Argon2id parameters exceed the local resource budget",
            Self::DerivationFailed => "local password derivation failed",
            Self::Malformed => "encrypted vault or state framing is malformed",
            Self::UnsupportedVersion => "encrypted vault or state version is unsupported",
            Self::AuthenticationFailed => "vault or state authentication failed",
            Self::WrongVault => "snapshot does not belong to the expected vault",
            Self::RollbackDetected => "an older vault revision or state sequence was rejected",
            Self::LimitExceeded => "vault or state exceeds the resource limit",
            Self::InvalidContext => "state context or sequence is invalid",
            Self::EncryptFailed => "authenticated encryption failed",
        })
    }
}

impl std::error::Error for VaultError {}

impl From<KeyStoreError> for VaultError {
    fn from(value: KeyStoreError) -> Self {
        Self::KeyStore(value)
    }
}

struct Root {
    class: SecretClass,
    generation: u64,
    key: Option<Zeroizing<[u8; 32]>>,
}

/// Keep this object only while the application is unlocked. Drop it to lock;
/// root keys and the password-derived wrapping key are overwritten on drop.
pub struct SoftwareVault {
    profile: ProfileId,
    vault_id: [u8; 16],
    salt: [u8; 16],
    revision: u64,
    kdf: VaultKdf,
    wrapping_key: Zeroizing<[u8; 32]>,
    roots: BTreeMap<SecretHandle, Root>,
}

impl fmt::Debug for SoftwareVault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SoftwareVault")
            .field("profile", &self.profile)
            .field("revision", &self.revision)
            .field("root_count", &self.roots.len())
            .field("secrets", &"[REDACTED]")
            .finish()
    }
}

impl SoftwareVault {
    pub fn create(
        required_profile: &ProfileId,
        passphrase: Zeroizing<Vec<u8>>,
        kdf: VaultKdf,
        budget: KdfBudget,
    ) -> Result<Self, VaultError> {
        if (required_profile.name(), required_profile.version())
            != ("secret-software-vault", "0.1.0")
        {
            return Err(KeyStoreError::UnsupportedProfile.into());
        }
        let params = kdf.params(budget)?;
        let salt = random()?;
        let wrapping_key = derive(&passphrase, &salt, params)?;
        Ok(Self {
            profile: required_profile.clone(),
            vault_id: random()?,
            salt,
            revision: 1,
            kdf,
            wrapping_key,
            roots: BTreeMap::new(),
        })
    }

    pub fn vault_id(&self) -> [u8; 16] {
        self.vault_id
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// Replace the local unlock credential without replacing protocol roots.
    /// After success, persist a new snapshot before advancing the trusted floor.
    pub fn change_passphrase(
        &mut self,
        passphrase: Zeroizing<Vec<u8>>,
        kdf: VaultKdf,
        budget: KdfBudget,
    ) -> Result<(), VaultError> {
        let revision = self
            .revision
            .checked_add(1)
            .ok_or(KeyStoreError::GenerationExhausted)?;
        let params = kdf.params(budget)?;
        let salt = random()?;
        let wrapping_key = derive(&passphrase, &salt, params)?;
        // All fallible preparation precedes mutation; assigning the Zeroizing
        // wrapper also clears the previous password-derived key.
        self.wrapping_key = wrapping_key;
        self.salt = salt;
        self.kdf = kdf;
        self.revision = revision;
        Ok(())
    }

    /// Remove and zeroize one wrapping root. Its authenticated tombstone remains
    /// so provisioning the retired handle again cannot accidentally reuse it.
    pub fn retire_root(&mut self, handle: &SecretHandle) -> Result<(), VaultError> {
        if self
            .roots
            .get(handle)
            .ok_or(KeyStoreError::NotFound)?
            .key
            .is_none()
        {
            return Err(KeyStoreError::NotFound.into());
        }
        let revision = self
            .revision
            .checked_add(1)
            .ok_or(KeyStoreError::GenerationExhausted)?;
        self.roots
            .get_mut(handle)
            .ok_or(KeyStoreError::NotFound)?
            .key = None;
        self.revision = revision;
        Ok(())
    }

    /// Export ciphertext only. The caller persists the snapshot and updates its
    /// independent revision anchor after a successful durable write.
    pub fn snapshot(&self) -> Result<Vec<u8>, VaultError> {
        let mut plaintext = Zeroizing::new(Vec::new());
        plaintext.extend_from_slice(&(self.roots.len() as u16).to_be_bytes());
        for (handle, root) in &self.roots {
            let bytes = handle.as_str().as_bytes();
            plaintext.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
            plaintext.extend_from_slice(bytes);
            plaintext.push(class_tag(root.class));
            plaintext.extend_from_slice(&root.generation.to_be_bytes());
            match &root.key {
                Some(key) => {
                    plaintext.push(0);
                    plaintext.extend_from_slice(key.as_ref());
                }
                None => plaintext.push(1),
            }
        }
        let mut header = Vec::with_capacity(SNAPSHOT_HEADER);
        header.extend_from_slice(b"E2SV");
        header.extend_from_slice(&VAULT_SNAPSHOT_VERSION.to_be_bytes());
        header.extend_from_slice(&self.kdf.memory_kib.to_be_bytes());
        header.extend_from_slice(&self.kdf.iterations.to_be_bytes());
        header.extend_from_slice(&self.kdf.parallelism.to_be_bytes());
        header.extend_from_slice(&self.vault_id);
        header.extend_from_slice(&self.salt);
        header.extend_from_slice(&self.revision.to_be_bytes());
        header.extend_from_slice(&random::<12>()?);
        header.extend_from_slice(&((plaintext.len() + 16) as u32).to_be_bytes());
        let aad = snapshot_aad(&header);
        let ciphertext = encrypt(&self.wrapping_key, &header[58..70], &plaintext, &aad)?;
        header.extend_from_slice(&ciphertext);
        Ok(header)
    }

    /// The expected ID and revision floor must come from trusted local state or
    /// an independent witness, never from this untrusted snapshot's header.
    pub fn unlock(
        bytes: &[u8],
        passphrase: Zeroizing<Vec<u8>>,
        expected_vault_id: [u8; 16],
        minimum_revision: u64,
        budget: KdfBudget,
    ) -> Result<Self, VaultError> {
        framing(bytes, b"E2SV", SNAPSHOT_HEADER, MAX_SNAPSHOT_BYTES)?;
        let kdf = VaultKdf {
            memory_kib: number32(bytes, 6),
            iterations: number32(bytes, 10),
            parallelism: number32(bytes, 14),
        };
        let params = kdf.params(budget)?;
        let vault_id = bytes[18..34]
            .try_into()
            .map_err(|_| VaultError::Malformed)?;
        if vault_id != expected_vault_id {
            return Err(VaultError::WrongVault);
        }
        let salt = bytes[34..50]
            .try_into()
            .map_err(|_| VaultError::Malformed)?;
        let revision = number64(bytes, 50);
        let wrapping_key = derive(&passphrase, &salt, params)?;
        let plaintext = decrypt(
            &wrapping_key,
            &bytes[58..70],
            &bytes[SNAPSHOT_HEADER..],
            &snapshot_aad(&bytes[..SNAPSHOT_HEADER]),
        )?;
        if revision == 0 || minimum_revision == 0 || revision < minimum_revision {
            return Err(VaultError::RollbackDetected);
        }
        let version = u16::from_be_bytes([bytes[4], bytes[5]]);
        let roots = decode_roots(&plaintext, version)?;
        Ok(Self {
            profile: ProfileId::parse(SOFTWARE_VAULT_PROFILE)
                .map_err(|_| KeyStoreError::UnsupportedProfile)?,
            vault_id,
            salt,
            revision,
            kdf,
            wrapping_key,
            roots,
        })
    }

    pub fn seal_state(
        &self,
        handle: &SecretHandle,
        sequence: u64,
        context: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, VaultError> {
        check_context(sequence, context)?;
        if plaintext.len() > MAX_STATE_BYTES {
            return Err(VaultError::LimitExceeded);
        }
        let root = self.roots.get(handle).ok_or(KeyStoreError::NotFound)?;
        let key = root.key.as_ref().ok_or(KeyStoreError::NotFound)?;
        let mut header = Vec::with_capacity(STATE_HEADER);
        header.extend_from_slice(b"E2LS");
        header.extend_from_slice(&1_u16.to_be_bytes());
        header.extend_from_slice(&root.generation.to_be_bytes());
        header.extend_from_slice(&sequence.to_be_bytes());
        header.extend_from_slice(&random::<12>()?);
        header.extend_from_slice(&((plaintext.len() + 16) as u32).to_be_bytes());
        let ciphertext = encrypt(
            key,
            &header[22..34],
            plaintext,
            &self.state_aad(handle, root, context, &header),
        )?;
        header.extend_from_slice(&ciphertext);
        Ok(header)
    }

    pub fn open_state(
        &self,
        handle: &SecretHandle,
        minimum_sequence: u64,
        context: &[u8],
        bytes: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        check_context(minimum_sequence, context)?;
        framing(
            bytes,
            b"E2LS",
            STATE_HEADER,
            MAX_STATE_BYTES + STATE_HEADER + 16,
        )?;
        let root = self.roots.get(handle).ok_or(KeyStoreError::NotFound)?;
        let key = root.key.as_ref().ok_or(KeyStoreError::NotFound)?;
        let plaintext = decrypt(
            key,
            &bytes[22..34],
            &bytes[STATE_HEADER..],
            &self.state_aad(handle, root, context, &bytes[..STATE_HEADER]),
        )?;
        if number64(bytes, 6) != root.generation || number64(bytes, 14) < minimum_sequence {
            return Err(VaultError::RollbackDetected);
        }
        Ok(plaintext)
    }

    fn state_aad(
        &self,
        handle: &SecretHandle,
        root: &Root,
        context: &[u8],
        header: &[u8],
    ) -> Vec<u8> {
        let mut aad = b"End-To-End Everywhere local state v1\0".to_vec();
        aad.extend_from_slice(&self.vault_id);
        aad.extend_from_slice(&(handle.as_str().len() as u16).to_be_bytes());
        aad.extend_from_slice(handle.as_str().as_bytes());
        aad.push(class_tag(root.class));
        aad.extend_from_slice(&(context.len() as u16).to_be_bytes());
        aad.extend_from_slice(context);
        aad.extend_from_slice(header);
        aad
    }
}

impl SecureKeyStore for SoftwareVault {
    fn profile(&self) -> &ProfileId {
        &self.profile
    }

    fn backend_kind(&self) -> BackendKind {
        BackendKind::SoftwareVault
    }

    fn provision(&mut self, request: ProvisionRequest) -> Result<SecretMetadata, KeyStoreError> {
        if request.required_profile != self.profile {
            return Err(KeyStoreError::UnsupportedProfile);
        }
        if request.minimum_generation == 0 {
            return Err(KeyStoreError::InvalidGeneration);
        }
        if request.handle.as_str().len() > MAX_HANDLE || self.roots.len() >= MAX_ROOTS {
            return Err(KeyStoreError::CapacityExceeded);
        }
        if self.roots.contains_key(&request.handle) {
            return Err(KeyStoreError::AlreadyExists);
        }
        let revision = self
            .revision
            .checked_add(1)
            .ok_or(KeyStoreError::GenerationExhausted)?;
        let key = Zeroizing::new(random().map_err(|_| KeyStoreError::RandomnessFailure)?);
        self.roots.insert(
            request.handle.clone(),
            Root {
                class: request.class,
                generation: request.minimum_generation,
                key: Some(key),
            },
        );
        self.revision = revision;
        self.metadata(&request.handle)
    }

    fn metadata(&self, handle: &SecretHandle) -> Result<SecretMetadata, KeyStoreError> {
        let root = self.roots.get(handle).ok_or(KeyStoreError::NotFound)?;
        if root.key.is_none() {
            return Err(KeyStoreError::NotFound);
        }
        Ok(SecretMetadata {
            handle: handle.clone(),
            class: root.class,
            backend: BackendKind::SoftwareVault,
            export_policy: ExportPolicy::SoftwareProtected,
            generation: root.generation,
        })
    }
}

fn random<const N: usize>() -> Result<[u8; N], VaultError> {
    let mut bytes = [0_u8; N];
    getrandom::fill(&mut bytes).map_err(|_| KeyStoreError::RandomnessFailure)?;
    Ok(bytes)
}

fn derive(
    password: &[u8],
    salt: &[u8; 16],
    params: Params,
) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    if !(12..=1024).contains(&password.len()) {
        return Err(VaultError::InvalidPassphrase);
    }
    // The library's convenience allocator doesn't clear the memory matrix.
    // Own it here so all password-dependent blocks are zeroized on every path.
    let mut memory = Zeroizing::new(vec![Block::default(); params.block_count()]);
    let mut key = Zeroizing::new([0_u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into_with_memory(password, salt, key.as_mut(), memory.as_mut_slice())
        .map_err(|_| VaultError::DerivationFailed)?;
    Ok(key)
}

fn encrypt(
    key: &[u8; 32],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, VaultError> {
    ChaCha20Poly1305::new(key.into())
        .encrypt(
            &Nonce::try_from(nonce).map_err(|_| VaultError::Malformed)?,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| VaultError::EncryptFailed)
}

fn decrypt(
    key: &[u8; 32],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    ChaCha20Poly1305::new(key.into())
        .decrypt(
            &Nonce::try_from(nonce).map_err(|_| VaultError::Malformed)?,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| VaultError::AuthenticationFailed)
}

fn snapshot_aad(header: &[u8]) -> Vec<u8> {
    let mut aad = b"End-To-End Everywhere software vault v1\0".to_vec();
    aad.extend_from_slice(SOFTWARE_VAULT_PROFILE.as_bytes());
    aad.extend_from_slice(header);
    aad
}

fn check_context(sequence: u64, context: &[u8]) -> Result<(), VaultError> {
    if sequence == 0 || context.is_empty() || context.len() > 1024 {
        Err(VaultError::InvalidContext)
    } else {
        Ok(())
    }
}

fn framing(bytes: &[u8], magic: &[u8; 4], header: usize, limit: usize) -> Result<(), VaultError> {
    if bytes.len() > limit {
        return Err(VaultError::LimitExceeded);
    }
    if bytes.len() < header + 16 || bytes.get(..4) != Some(magic) {
        return Err(VaultError::Malformed);
    }
    let version = u16::from_be_bytes([bytes[4], bytes[5]]);
    if version != 1 && !(magic == b"E2SV" && version == VAULT_SNAPSHOT_VERSION) {
        return Err(VaultError::UnsupportedVersion);
    }
    let length = number32(bytes, header - 4) as usize;
    if length < 16 || header.checked_add(length) != Some(bytes.len()) {
        return Err(VaultError::Malformed);
    }
    Ok(())
}

fn number32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("validated framing"),
    )
}

fn number64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("validated framing"),
    )
}

fn class_tag(class: SecretClass) -> u8 {
    match class {
        SecretClass::DeviceIdentityRoot => 1,
        SecretClass::ProtocolStateWrappingRoot => 2,
        SecretClass::RecoveryRoot => 3,
        SecretClass::TransparencyCheckpoint => 4,
        SecretClass::Credential => 5,
    }
}

fn decode_roots(bytes: &[u8], version: u16) -> Result<BTreeMap<SecretHandle, Root>, VaultError> {
    if !matches!(version, 1 | 2) {
        return Err(VaultError::UnsupportedVersion);
    }
    let mut reader = Reader { bytes, offset: 0 };
    let count = u16::from_be_bytes(
        reader
            .take(2)?
            .try_into()
            .map_err(|_| VaultError::Malformed)?,
    ) as usize;
    if count > MAX_ROOTS {
        return Err(VaultError::LimitExceeded);
    }
    let mut roots = BTreeMap::new();
    let mut previous: Option<SecretHandle> = None;
    for _ in 0..count {
        let len = u16::from_be_bytes(
            reader
                .take(2)?
                .try_into()
                .map_err(|_| VaultError::Malformed)?,
        ) as usize;
        if len == 0 || len > MAX_HANDLE {
            return Err(VaultError::Malformed);
        }
        let handle = SecretHandle::parse(
            std::str::from_utf8(reader.take(len)?).map_err(|_| VaultError::Malformed)?,
        )?;
        if previous.as_ref().is_some_and(|p| p >= &handle) {
            return Err(VaultError::Malformed);
        }
        previous = Some(handle.clone());
        let class = match reader.take(1)?[0] {
            1 => SecretClass::DeviceIdentityRoot,
            2 => SecretClass::ProtocolStateWrappingRoot,
            3 => SecretClass::RecoveryRoot,
            4 => SecretClass::TransparencyCheckpoint,
            5 => SecretClass::Credential,
            _ => return Err(VaultError::Malformed),
        };
        let generation = u64::from_be_bytes(
            reader
                .take(8)?
                .try_into()
                .map_err(|_| VaultError::Malformed)?,
        );
        if generation == 0 {
            return Err(VaultError::Malformed);
        }
        let retired = if version == 1 {
            false
        } else {
            match reader.take(1)?[0] {
                0 => false,
                1 => true,
                _ => return Err(VaultError::Malformed),
            }
        };
        let key = if retired {
            None
        } else {
            Some(Zeroizing::new(
                reader
                    .take(32)?
                    .try_into()
                    .map_err(|_| VaultError::Malformed)?,
            ))
        };
        roots.insert(
            handle,
            Root {
                class,
                generation,
                key,
            },
        );
    }
    if reader.offset != bytes.len() {
        return Err(VaultError::Malformed);
    }
    Ok(roots)
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], VaultError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(VaultError::Malformed)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(VaultError::Malformed)?;
        self.offset = end;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn password() -> Zeroizing<Vec<u8>> {
        Zeroizing::new(b"an example long unlock phrase".to_vec())
    }

    fn vault() -> SoftwareVault {
        SoftwareVault::create(
            &ProfileId::parse(SOFTWARE_VAULT_PROFILE).unwrap(),
            password(),
            VaultKdf::default(),
            KdfBudget::default(),
        )
        .unwrap()
    }

    fn request(handle: &str) -> ProvisionRequest {
        ProvisionRequest {
            handle: SecretHandle::parse(handle).unwrap(),
            class: SecretClass::ProtocolStateWrappingRoot,
            required_profile: ProfileId::parse(SOFTWARE_VAULT_PROFILE).unwrap(),
            minimum_generation: 1,
        }
    }

    #[test]
    fn exact_profile_and_password_kdf_resource_limits_fail_closed() {
        assert!(matches!(
            SoftwareVault::create(
                &ProfileId::parse(crate::HARDWARE_ISOLATED_PROFILE).unwrap(),
                password(),
                VaultKdf::default(),
                KdfBudget::default()
            ),
            Err(VaultError::KeyStore(KeyStoreError::UnsupportedProfile))
        ));
        assert_eq!(
            VaultKdf {
                memory_kib: 8192,
                ..VaultKdf::default()
            }
            .params(KdfBudget::default()),
            Err(VaultError::WeakKdf)
        );
        assert_eq!(
            VaultKdf {
                memory_kib: u32::MAX,
                ..VaultKdf::default()
            }
            .params(KdfBudget::default()),
            Err(VaultError::KdfBudgetExceeded)
        );
        assert!(VaultKdf::default().params(KdfBudget::default()).is_ok());
        assert!(VaultKdf {
            memory_kib: 2 * 1024 * 1024,
            iterations: 1,
            parallelism: 4
        }
        .params(KdfBudget {
            max_memory_kib: 2 * 1024 * 1024,
            ..KdfBudget::default()
        })
        .is_ok());
        assert_eq!(
            derive(
                b"short",
                &[0; 16],
                VaultKdf::default().params(KdfBudget::default()).unwrap()
            ),
            Err(VaultError::InvalidPassphrase)
        );
    }

    #[test]
    fn durable_roots_round_trip_and_software_claims_are_honest() {
        let mut vault = vault();
        let handle = request("endpoint/state").handle;
        let metadata = vault.provision(request("endpoint/state")).unwrap();
        assert_eq!(metadata.export_policy, ExportPolicy::SoftwareProtected);
        assert_eq!(
            vault.provision(request("endpoint/state")),
            Err(KeyStoreError::AlreadyExists)
        );
        let state = vault
            .seal_state(&handle, 7, b"endpoint-1", b"private protocol key")
            .unwrap();
        let snapshot = vault.snapshot().unwrap();
        let id = vault.vault_id();
        let revision = vault.revision();
        assert!(!snapshot.windows(20).any(|w| w == b"private protocol key"));
        drop(vault);
        let restored =
            SoftwareVault::unlock(&snapshot, password(), id, revision, KdfBudget::default())
                .unwrap();
        assert_eq!(
            &*restored
                .open_state(&handle, 7, b"endpoint-1", &state)
                .unwrap(),
            b"private protocol key"
        );
        assert!(!format!("{restored:?}").contains("example long"));
    }

    #[test]
    fn state_binds_handle_context_sequence_and_every_byte() {
        let mut vault = vault();
        for handle in ["root/a", "root/b"] {
            vault.provision(request(handle)).unwrap();
        }
        let a = request("root/a").handle;
        let b = request("root/b").handle;
        let state = vault.seal_state(&a, 2, b"ratchet", b"secret").unwrap();
        assert_eq!(
            vault.open_state(&a, 3, b"ratchet", &state),
            Err(VaultError::RollbackDetected)
        );
        assert_eq!(
            vault.open_state(&a, 2, b"other", &state),
            Err(VaultError::AuthenticationFailed)
        );
        assert_eq!(
            vault.open_state(&b, 2, b"ratchet", &state),
            Err(VaultError::AuthenticationFailed)
        );
        for i in 0..state.len() {
            let mut changed = state.clone();
            changed[i] ^= 1;
            assert!(
                vault.open_state(&a, 2, b"ratchet", &changed).is_err(),
                "byte {i}"
            );
        }
        assert_ne!(
            state,
            vault.seal_state(&a, 2, b"ratchet", b"secret").unwrap()
        );
    }

    #[test]
    fn snapshots_reject_wrong_password_tampering_and_rollback() {
        let vault = vault();
        let snapshot = vault.snapshot().unwrap();
        let id = vault.vault_id();
        assert!(matches!(
            SoftwareVault::unlock(
                &snapshot,
                Zeroizing::new(b"a different long password".to_vec()),
                id,
                1,
                KdfBudget::default()
            ),
            Err(VaultError::AuthenticationFailed)
        ));
        let mut changed = snapshot.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert!(matches!(
            SoftwareVault::unlock(&changed, password(), id, 1, KdfBudget::default()),
            Err(VaultError::AuthenticationFailed)
        ));
        assert!(matches!(
            SoftwareVault::unlock(&snapshot, password(), id, 2, KdfBudget::default()),
            Err(VaultError::RollbackDetected)
        ));
        assert!(matches!(
            SoftwareVault::unlock(&snapshot, password(), [0; 16], 1, KdfBudget::default()),
            Err(VaultError::WrongVault)
        ));
        changed = snapshot.clone();
        changed[6..10].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            SoftwareVault::unlock(&changed, password(), id, 1, KdfBudget::default()),
            Err(VaultError::KdfBudgetExceeded)
        ));
    }

    #[test]
    fn credential_change_preserves_roots_and_invalidates_old_unlock_secret() {
        let mut vault = vault();
        let handle = request("protocol/root").handle;
        vault.provision(request("protocol/root")).unwrap();
        let state = vault
            .seal_state(&handle, 1, b"endpoint", b"private protocol state")
            .unwrap();
        let old_snapshot = vault.snapshot().unwrap();
        let old_revision = vault.revision();
        let old_salt = vault.salt;
        let new_password = || Zeroizing::new(b"a different strong unlock phrase".to_vec());
        vault
            .change_passphrase(new_password(), VaultKdf::default(), KdfBudget::default())
            .unwrap();
        assert_eq!(vault.revision(), old_revision + 1);
        assert_ne!(vault.salt, old_salt);
        let new_snapshot = vault.snapshot().unwrap();
        let restored = SoftwareVault::unlock(
            &new_snapshot,
            new_password(),
            vault.vault_id(),
            vault.revision(),
            KdfBudget::default(),
        )
        .unwrap();
        assert_eq!(
            &*restored
                .open_state(&handle, 1, b"endpoint", &state)
                .unwrap(),
            b"private protocol state"
        );
        assert!(matches!(
            SoftwareVault::unlock(
                &new_snapshot,
                password(),
                vault.vault_id(),
                vault.revision(),
                KdfBudget::default()
            ),
            Err(VaultError::AuthenticationFailed)
        ));
        assert!(matches!(
            SoftwareVault::unlock(
                &old_snapshot,
                password(),
                vault.vault_id(),
                vault.revision(),
                KdfBudget::default()
            ),
            Err(VaultError::RollbackDetected)
        ));
    }

    #[test]
    fn failed_changes_and_revision_exhaustion_leave_existing_keys_usable() {
        let mut vault = vault();
        let handle = request("protocol/root").handle;
        vault.provision(request("protocol/root")).unwrap();
        let state = vault.seal_state(&handle, 1, b"context", b"secret").unwrap();
        let revision = vault.revision();
        let salt = vault.salt;
        assert_eq!(
            vault.change_passphrase(
                Zeroizing::new(b"short".to_vec()),
                VaultKdf::default(),
                KdfBudget::default()
            ),
            Err(VaultError::InvalidPassphrase)
        );
        assert_eq!(vault.revision(), revision);
        assert_eq!(vault.salt, salt);
        vault.revision = u64::MAX;
        assert_eq!(
            vault.change_passphrase(password(), VaultKdf::default(), KdfBudget::default()),
            Err(VaultError::KeyStore(KeyStoreError::GenerationExhausted))
        );
        assert_eq!(
            vault.retire_root(&handle),
            Err(VaultError::KeyStore(KeyStoreError::GenerationExhausted))
        );
        assert_eq!(
            &*vault.open_state(&handle, 1, b"context", &state).unwrap(),
            b"secret"
        );
    }

    #[test]
    fn retired_roots_stay_unusable_and_handles_cannot_be_reprovisioned_after_restart() {
        let mut vault = vault();
        let handle = request("protocol/root").handle;
        vault.provision(request("protocol/root")).unwrap();
        let state = vault.seal_state(&handle, 1, b"context", b"secret").unwrap();
        vault.retire_root(&handle).unwrap();
        assert_eq!(vault.metadata(&handle), Err(KeyStoreError::NotFound));
        assert_eq!(
            vault.provision(request("protocol/root")),
            Err(KeyStoreError::AlreadyExists)
        );
        let restored = SoftwareVault::unlock(
            &vault.snapshot().unwrap(),
            password(),
            vault.vault_id(),
            vault.revision(),
            KdfBudget::default(),
        )
        .unwrap();
        assert!(matches!(
            restored.open_state(&handle, 1, b"context", &state),
            Err(VaultError::KeyStore(KeyStoreError::NotFound))
        ));
        assert!(matches!(
            restored.seal_state(&handle, 2, b"context", b"new"),
            Err(VaultError::KeyStore(KeyStoreError::NotFound))
        ));
        assert!(restored.roots.get(&handle).unwrap().key.is_none());
    }

    #[test]
    fn authenticated_v1_snapshots_migrate_without_changing_protocol_roots() {
        let mut vault = vault();
        let handle = request("protocol/root").handle;
        vault.provision(request("protocol/root")).unwrap();
        let root = vault.roots.get(&handle).unwrap();
        let mut legacy_plaintext = Zeroizing::new(vec![0, 1]);
        legacy_plaintext.extend_from_slice(&(handle.as_str().len() as u16).to_be_bytes());
        legacy_plaintext.extend_from_slice(handle.as_str().as_bytes());
        legacy_plaintext.push(class_tag(root.class));
        legacy_plaintext.extend_from_slice(&root.generation.to_be_bytes());
        legacy_plaintext.extend_from_slice(root.key.as_ref().unwrap().as_ref());
        let mut header = vault.snapshot().unwrap()[..SNAPSHOT_HEADER].to_vec();
        header[4..6].copy_from_slice(&1_u16.to_be_bytes());
        header[58..70].copy_from_slice(&random::<12>().unwrap());
        header[70..74].copy_from_slice(&((legacy_plaintext.len() + 16) as u32).to_be_bytes());
        let encrypted = encrypt(
            &vault.wrapping_key,
            &header[58..70],
            &legacy_plaintext,
            &snapshot_aad(&header),
        )
        .unwrap();
        header.extend_from_slice(&encrypted);
        let state = vault
            .seal_state(&handle, 1, b"context", b"legacy state")
            .unwrap();
        let restored = SoftwareVault::unlock(
            &header,
            password(),
            vault.vault_id(),
            vault.revision(),
            KdfBudget::default(),
        )
        .unwrap();
        assert_eq!(
            &*restored.open_state(&handle, 1, b"context", &state).unwrap(),
            b"legacy state"
        );
        assert_eq!(&restored.snapshot().unwrap()[4..6], &2_u16.to_be_bytes());
        let mut malformed_plaintext = Zeroizing::new(legacy_plaintext.to_vec());
        let flag_offset = malformed_plaintext.len() - 32;
        malformed_plaintext.insert(flag_offset, 2);
        assert!(decode_roots(&malformed_plaintext, 2).is_err());
    }

    #[test]
    fn all_truncations_and_noncanonical_root_records_are_rejected() {
        let vault = vault();
        let snapshot = vault.snapshot().unwrap();
        for i in 0..snapshot.len() {
            assert!(SoftwareVault::unlock(
                &snapshot[..i],
                password(),
                vault.vault_id(),
                1,
                KdfBudget::default()
            )
            .is_err());
        }
        assert!(decode_roots(&[0, 0, 1], 2).is_err());
        assert!(decode_roots(&[0xff, 0xff], 2).is_err());
        assert!(decode_roots(&[0, 1, 0, 0], 2).is_err());
    }
}
