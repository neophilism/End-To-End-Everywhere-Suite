//! Signing-key persistence bound to an endpoint and independently pinned key.

use crate::CapsuleSigningKey;
use e2ee_core::EndpointId;
use e2ee_keystore::{
    software::VaultError,
    state::{protocol_key_context, LocalStateCipher, ProtocolKeyKind},
    SecretHandle,
};
use zeroize::Zeroizing;

impl CapsuleSigningKey {
    pub fn seal_local(
        &self,
        store: &impl LocalStateCipher,
        handle: &SecretHandle,
        endpoint: &EndpointId,
        sequence: u64,
    ) -> Result<Vec<u8>, VaultError> {
        let context = protocol_key_context(
            store,
            handle,
            ProtocolKeyKind::Ed25519Signer,
            endpoint,
            &self.public_key(),
        )?;
        let seed = Zeroizing::new(self.0.to_bytes());
        store.seal_state(handle, sequence, &context, seed.as_ref())
    }

    pub fn open_local(
        store: &impl LocalStateCipher,
        handle: &SecretHandle,
        endpoint: &EndpointId,
        expected_public_key: &[u8; 32],
        minimum_sequence: u64,
        encrypted: &[u8],
    ) -> Result<Self, VaultError> {
        let context = protocol_key_context(
            store,
            handle,
            ProtocolKeyKind::Ed25519Signer,
            endpoint,
            expected_public_key,
        )?;
        let plaintext = store.open_state(handle, minimum_sequence, &context, encrypted)?;
        let seed = Zeroizing::new(
            plaintext
                .as_slice()
                .try_into()
                .map_err(|_| VaultError::Malformed)?,
        );
        let key = Self::from_seed(seed);
        if &key.public_key() != expected_public_key {
            return Err(VaultError::AuthenticationFailed);
        }
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{sign_capsule, verify_capsule_signature, TrustedSigner};
    use e2ee_capsule::CapsuleLimits;
    use e2ee_core::ProfileId;
    use e2ee_keystore::{
        software::{KdfBudget, SoftwareVault, VaultKdf},
        ProvisionRequest, SecretClass, SecureKeyStore, SOFTWARE_VAULT_PROFILE,
    };
    use e2ee_message::{
        encrypt_text, generate_recipient_keypair, RecipientPrivateKey, RecipientPublicKey,
    };

    #[test]
    fn encrypted_signer_restores_provenance_and_rejects_protocol_substitution() {
        let profile = ProfileId::parse(SOFTWARE_VAULT_PROFILE).unwrap();
        let password = || Zeroizing::new(b"a long local password secret".to_vec());
        let mut vault = SoftwareVault::create(
            &profile,
            password(),
            VaultKdf::default(),
            KdfBudget::default(),
        )
        .unwrap();
        let handle = SecretHandle::parse("endpoint/protocol-root").unwrap();
        vault
            .provision(ProvisionRequest {
                handle: handle.clone(),
                class: SecretClass::ProtocolStateWrappingRoot,
                required_profile: profile,
                minimum_generation: 1,
            })
            .unwrap();
        let endpoint = EndpointId::parse("endpoint-1").unwrap();
        let signer = CapsuleSigningKey::generate().unwrap();
        let public = signer.public_key();
        let encrypted = signer.seal_local(&vault, &handle, &endpoint, 3).unwrap();
        let snapshot = vault.snapshot().unwrap();
        let id = vault.vault_id();
        let revision = vault.revision();
        drop(signer);
        drop(vault);
        let vault =
            SoftwareVault::unlock(&snapshot, password(), id, revision, KdfBudget::default())
                .unwrap();
        let signer =
            CapsuleSigningKey::open_local(&vault, &handle, &endpoint, &public, 3, &encrypted)
                .unwrap();
        let recipient = generate_recipient_keypair();
        let capsule = encrypt_text(
            &RecipientPublicKey {
                recipient_hint: b"r".to_vec(),
                encoded_public_key: recipient.public_key,
            },
            "persisted signature",
            None,
        )
        .unwrap();
        let signature = sign_capsule(&signer, &capsule, "test", CapsuleLimits::default()).unwrap();
        assert!(verify_capsule_signature(
            &TrustedSigner::from_public_key(public).unwrap(),
            &capsule,
            &signature,
            "test",
            CapsuleLimits::default()
        )
        .is_ok());
        assert!(
            CapsuleSigningKey::open_local(&vault, &handle, &endpoint, &[0; 32], 3, &encrypted)
                .is_err()
        );
        assert!(CapsuleSigningKey::open_local(
            &vault,
            &handle,
            &EndpointId::parse("other").unwrap(),
            &public,
            3,
            &encrypted
        )
        .is_err());
        assert!(matches!(
            CapsuleSigningKey::open_local(&vault, &handle, &endpoint, &public, 4, &encrypted),
            Err(VaultError::RollbackDetected)
        ));
        assert!(RecipientPrivateKey::open_local(
            &vault, &handle, &endpoint, &public, 3, &encrypted
        )
        .is_err());
    }
}
