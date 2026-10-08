//! Provider boundary for authenticated local protocol state.

use crate::{
    software::{SoftwareVault, VaultError},
    validate_backend_for_profile, KeyStoreError, SecretClass, SecretHandle, SecureKeyStore,
};
use e2ee_core::EndpointId;
use zeroize::Zeroizing;

/// A root-key provider performs encryption without returning root-key bytes.
/// Platform adapters can implement this boundary without exporting their roots.
pub trait LocalStateCipher: SecureKeyStore {
    fn seal_state(
        &self,
        handle: &SecretHandle,
        sequence: u64,
        context: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, VaultError>;
    fn open_state(
        &self,
        handle: &SecretHandle,
        minimum_sequence: u64,
        context: &[u8],
        bytes: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, VaultError>;
}

impl LocalStateCipher for SoftwareVault {
    fn seal_state(
        &self,
        handle: &SecretHandle,
        sequence: u64,
        context: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, VaultError> {
        SoftwareVault::seal_state(self, handle, sequence, context, plaintext)
    }

    fn open_state(
        &self,
        handle: &SecretHandle,
        minimum_sequence: u64,
        context: &[u8],
        bytes: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        SoftwareVault::open_state(self, handle, minimum_sequence, context, bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolKeyKind {
    HpkeRecipient,
    Ed25519Signer,
}

/// Bind an encrypted key record to a protocol, endpoint and independently pinned
/// public key. This context isn't an identity verification or authorization proof.
pub fn protocol_key_context(
    store: &impl LocalStateCipher,
    handle: &SecretHandle,
    kind: ProtocolKeyKind,
    endpoint: &EndpointId,
    public_key: &[u8; 32],
) -> Result<Vec<u8>, VaultError> {
    let metadata = store.metadata(handle)?;
    validate_backend_for_profile(store.profile(), metadata.backend)?;
    if metadata.class != SecretClass::ProtocolStateWrappingRoot || metadata.generation == 0 {
        return Err(KeyStoreError::PolicyViolation.into());
    }
    if endpoint.as_str().len() > 256 {
        return Err(VaultError::InvalidContext);
    }
    let mut context = b"End-To-End Everywhere endpoint protocol key v1\0".to_vec();
    context.push(match kind {
        ProtocolKeyKind::HpkeRecipient => 1,
        ProtocolKeyKind::Ed25519Signer => 2,
    });
    context.extend_from_slice(&(endpoint.as_str().len() as u16).to_be_bytes());
    context.extend_from_slice(endpoint.as_str().as_bytes());
    context.extend_from_slice(public_key);
    Ok(context)
}
