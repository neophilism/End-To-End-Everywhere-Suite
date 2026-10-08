//! Recipient-key persistence only through authenticated encrypted local state.

use crate::{Kem, KemTrait, MessageError, RecipientPrivateKey, Serializable};
use e2ee_core::EndpointId;
use e2ee_keystore::{
    software::VaultError,
    state::{protocol_key_context, LocalStateCipher, ProtocolKeyKind},
    SecretHandle,
};

impl RecipientPrivateKey {
    pub fn public_key(&self) -> Result<[u8; 32], MessageError> {
        let key = self.parse()?;
        <Kem as KemTrait>::sk_to_pk(&key)
            .to_bytes()
            .as_slice()
            .try_into()
            .map_err(|_| MessageError::InvalidPrivateKey)
    }

    /// Returns ciphertext, never serialized private-key bytes.
    pub fn seal_local(
        &self,
        store: &impl LocalStateCipher,
        handle: &SecretHandle,
        endpoint: &EndpointId,
        sequence: u64,
    ) -> Result<Vec<u8>, VaultError> {
        let public = self.public_key().map_err(|_| VaultError::Malformed)?;
        let context = protocol_key_context(
            store,
            handle,
            ProtocolKeyKind::HpkeRecipient,
            endpoint,
            &public,
        )?;
        store.seal_state(handle, sequence, &context, &self.encoded_private_key)
    }

    /// The endpoint, public key and sequence floor must be supplied from trusted
    /// client state, not adopted from the incoming encrypted key record.
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
            ProtocolKeyKind::HpkeRecipient,
            endpoint,
            expected_public_key,
        )?;
        let plaintext = store.open_state(handle, minimum_sequence, &context, encrypted)?;
        let key = Self::from_bytes(plaintext.to_vec()).map_err(|_| VaultError::Malformed)?;
        if &key.public_key().map_err(|_| VaultError::Malformed)? != expected_public_key {
            return Err(VaultError::AuthenticationFailed);
        }
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{decrypt_text, encrypt_text, generate_recipient_keypair, RecipientPublicKey};
    use e2ee_core::ProfileId;
    use e2ee_keystore::{
        software::{KdfBudget, SoftwareVault, VaultKdf},
        ProvisionRequest, SecretClass, SecureKeyStore, SOFTWARE_VAULT_PROFILE,
    };
    use zeroize::Zeroizing;

    fn vault() -> (SoftwareVault, SecretHandle) {
        let profile = ProfileId::parse(SOFTWARE_VAULT_PROFILE).unwrap();
        let mut vault = SoftwareVault::create(
            &profile,
            Zeroizing::new(b"long example unlock secret".to_vec()),
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
        (vault, handle)
    }

    #[test]
    fn recipient_key_survives_lock_and_opens_a_real_capsule() {
        let (vault, handle) = vault();
        let endpoint = EndpointId::parse("endpoint-1").unwrap();
        let keypair = generate_recipient_keypair();
        let public = keypair.private_key.public_key().unwrap();
        let recipient = RecipientPublicKey {
            recipient_hint: b"endpoint-1".to_vec(),
            encoded_public_key: public.to_vec(),
        };
        let capsule = encrypt_text(&recipient, "survives a restart", None).unwrap();
        let encrypted = keypair
            .private_key
            .seal_local(&vault, &handle, &endpoint, 1)
            .unwrap();
        drop(keypair);
        let restored =
            RecipientPrivateKey::open_local(&vault, &handle, &endpoint, &public, 1, &encrypted)
                .unwrap();
        assert_eq!(
            decrypt_text(b"endpoint-1", &restored, &capsule)
                .unwrap()
                .text,
            "survives a restart"
        );
        assert!(RecipientPrivateKey::open_local(
            &vault,
            &handle,
            &EndpointId::parse("endpoint-2").unwrap(),
            &public,
            1,
            &encrypted
        )
        .is_err());
        assert!(RecipientPrivateKey::open_local(
            &vault, &handle, &endpoint, &[0; 32], 1, &encrypted
        )
        .is_err());
        assert!(matches!(
            RecipientPrivateKey::open_local(&vault, &handle, &endpoint, &public, 2, &encrypted),
            Err(VaultError::RollbackDetected)
        ));
    }

    #[test]
    fn credential_roots_cannot_wrap_endpoint_protocol_keys() {
        let (mut vault, _) = vault();
        let handle = SecretHandle::parse("credential/root").unwrap();
        vault
            .provision(ProvisionRequest {
                handle: handle.clone(),
                class: SecretClass::Credential,
                required_profile: ProfileId::parse(SOFTWARE_VAULT_PROFILE).unwrap(),
                minimum_generation: 1,
            })
            .unwrap();
        let keypair = generate_recipient_keypair();
        assert_eq!(
            keypair
                .private_key
                .seal_local(&vault, &handle, &EndpointId::parse("ep").unwrap(), 1),
            Err(VaultError::KeyStore(
                e2ee_keystore::KeyStoreError::PolicyViolation
            ))
        );
    }
}
