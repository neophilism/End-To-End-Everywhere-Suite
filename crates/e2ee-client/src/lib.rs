#![forbid(unsafe_code)]

//! Shared consumer-client workflows. Services never receive unlocked keys.
//! Contact fingerprints must be compared through an independent channel.

use e2ee_capsule::CapsuleLimits;
use e2ee_core::EndpointId;
use e2ee_keystore::{software::VaultError, state::LocalStateCipher, SecretHandle};
use e2ee_message::{
    decrypt_text, encrypt_text_for_recipients, generate_recipient_keypair, MessageError,
    RecipientPrivateKey, RecipientPublicKey,
};
use e2ee_provenance::{
    sign_capsule, CapsuleSigningKey, ProvenanceError, TrustedSigner, VerifiedProvenance,
};
use e2ee_transport::{Delivery, TransportError};
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::Zeroizing;

pub mod contacts;
pub mod files;
pub mod portable;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointCard {
    pub endpoint_id: EndpointId,
    pub recipient_public_key: [u8; 32],
    pub signer_public_key: [u8; 32],
}

impl EndpointCard {
    pub fn validate(&self) -> Result<(), ClientError> {
        if self.endpoint_id.as_str().len() > 128 {
            return Err(ClientError::InvalidEndpoint);
        }
        e2ee_message::recipients::validate_recipient_keys(&[self.recipient()])?;
        TrustedSigner::from_public_key(self.signer_public_key)?;
        Ok(())
    }

    pub fn fingerprint(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"End-To-End Everywhere endpoint contact card v1\0");
        hash.update((self.endpoint_id.as_str().len() as u64).to_be_bytes());
        hash.update(self.endpoint_id.as_str().as_bytes());
        hash.update(self.recipient_public_key);
        hash.update(self.signer_public_key);
        hash.finalize().into()
    }

    fn recipient(&self) -> RecipientPublicKey {
        RecipientPublicKey {
            recipient_hint: self.endpoint_id.as_str().as_bytes().to_vec(),
            encoded_public_key: self.recipient_public_key.to_vec(),
        }
    }
}

/// A contact is usable only after its complete card fingerprint matches the
/// value supplied by the human verifier through an independent channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedContact(EndpointCard);

impl VerifiedContact {
    pub fn confirm(
        card: EndpointCard,
        independently_observed: [u8; 32],
    ) -> Result<Self, ClientError> {
        card.validate()?;
        if card.fingerprint() != independently_observed {
            return Err(ClientError::FingerprintMismatch);
        }
        Ok(Self(card))
    }

    pub fn card(&self) -> &EndpointCard {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionPolicy {
    pub idle_timeout_ms: u64,
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self {
            idle_timeout_ms: 5 * 60 * 1000,
        }
    }
}

impl SessionPolicy {
    fn validate(self) -> Result<(), ClientError> {
        if self.idle_timeout_ms == 0 || self.idle_timeout_ms > 24 * 60 * 60 * 1000 {
            Err(ClientError::InvalidPolicy)
        } else {
            Ok(())
        }
    }
}

pub enum SignatureMode<'a> {
    Signed { context: &'a str },
    Unsigned,
}

pub enum SenderPolicy<'a> {
    RequireSignature {
        sender: &'a VerifiedContact,
        context: &'a str,
    },
    /// This explicit mode accepts unsigned content with no sender identity claim.
    /// A present signature cannot be silently ignored under this mode.
    PermitUnsigned,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientError {
    Locked,
    AlreadyUnlocked,
    ClockRegressed,
    InvalidPolicy,
    InvalidEndpoint,
    FingerprintMismatch,
    UnexpectedSignature,
    InvalidState,
    Message(MessageError),
    Provenance(ProvenanceError),
    Transport(TransportError),
    Vault(VaultError),
    File(e2ee_file::FileError),
    Contact(contacts::ContactError),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Locked => "unlock the client before using endpoint keys",
            Self::AlreadyUnlocked => "lock the client before restoring key state",
            Self::ClockRegressed => "client monotonic clock moved backwards; session was locked",
            Self::InvalidPolicy => "client inactivity timeout is invalid",
            Self::InvalidEndpoint => "client endpoint identity is invalid",
            Self::FingerprintMismatch => {
                "contact fingerprint does not match the independently verified value"
            }
            Self::UnexpectedSignature => {
                "signed content requires a pinned sender and expected context"
            }
            Self::InvalidState => "encrypted endpoint state is invalid",
            Self::Message(_) => "Capsule text encryption or decryption failed",
            Self::Provenance(_) => "Capsule provenance operation failed",
            Self::Transport(_) => "delivery or required sender verification failed",
            Self::Vault(_) => "encrypted local endpoint-state operation failed",
            Self::File(_) => "Capsule file encryption or decryption failed",
            Self::Contact(_) => "contact verification or lifecycle policy failed",
        })
    }
}

impl std::error::Error for ClientError {}

macro_rules! error_from {
    ($type:ty, $variant:ident) => {
        impl From<$type> for ClientError {
            fn from(value: $type) -> Self {
                Self::$variant(value)
            }
        }
    };
}
error_from!(MessageError, Message);
error_from!(ProvenanceError, Provenance);
error_from!(TransportError, Transport);
error_from!(VaultError, Vault);
error_from!(e2ee_file::FileError, File);
error_from!(contacts::ContactError, Contact);

/// Ciphertext-only endpoint state; public-key pins are kept separately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedEndpointKeys {
    recipient: Vec<u8>,
    signer: Vec<u8>,
}

impl EncryptedEndpointKeys {
    pub fn from_ciphertexts(recipient: Vec<u8>, signer: Vec<u8>) -> Result<Self, ClientError> {
        // A 32-byte protocol key occupies 86 bytes in a local-state v1 record.
        // This intentionally rejects alternate versions until explicitly supported.
        if recipient.len() != 86 || signer.len() != 86 {
            return Err(ClientError::InvalidState);
        }
        Ok(Self { recipient, signer })
    }

    pub fn ciphertexts(&self) -> (&[u8], &[u8]) {
        (&self.recipient, &self.signer)
    }
}

struct EndpointKeys {
    recipient: RecipientPrivateKey,
    signer: CapsuleSigningKey,
}

pub struct EndpointSession {
    card: EndpointCard,
    keys: Option<EndpointKeys>,
    policy: SessionPolicy,
    last_activity_ms: u64,
}

impl fmt::Debug for EndpointSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EndpointSession")
            .field("card", &self.card)
            .field("unlocked", &self.is_unlocked())
            .field("keys", &"[REDACTED]")
            .finish()
    }
}

pub struct OpenedText {
    pub message_id: [u8; 16],
    pub content_type: String,
    pub provenance: Option<VerifiedProvenance>,
    text: Zeroizing<String>,
}

impl OpenedText {
    pub fn text(&self) -> &str {
        &self.text
    }
}

impl fmt::Debug for OpenedText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenedText")
            .field("provenance", &self.provenance)
            .field("text", &"[REDACTED]")
            .finish()
    }
}

impl EndpointSession {
    /// Creates this installation's local endpoint. This does not enroll a new
    /// device into an existing user's account or transfer another device's keys.
    pub fn create_local(
        endpoint_id: EndpointId,
        policy: SessionPolicy,
        now_ms: u64,
    ) -> Result<Self, ClientError> {
        policy.validate()?;
        if endpoint_id.as_str().len() > 128 {
            return Err(ClientError::InvalidEndpoint);
        }
        let recipient = generate_recipient_keypair().private_key;
        let signer = CapsuleSigningKey::generate()?;
        let card = EndpointCard {
            endpoint_id,
            recipient_public_key: recipient.public_key()?,
            signer_public_key: signer.public_key(),
        };
        card.validate()?;
        Ok(Self {
            card,
            keys: Some(EndpointKeys { recipient, signer }),
            policy,
            last_activity_ms: now_ms,
        })
    }

    /// For restart: the card must come from independently trusted local pins.
    pub fn from_pinned_card(
        card: EndpointCard,
        policy: SessionPolicy,
        now_ms: u64,
    ) -> Result<Self, ClientError> {
        policy.validate()?;
        card.validate()?;
        Ok(Self {
            card,
            keys: None,
            policy,
            last_activity_ms: now_ms,
        })
    }

    pub fn card(&self) -> &EndpointCard {
        &self.card
    }
    pub fn is_unlocked(&self) -> bool {
        self.keys.is_some()
    }

    /// Clear both ephemeral key objects. Hosts must also clear their unlocked
    /// root provider and any displayed/copied plaintext on lock/suspend/logout.
    pub fn lock(&mut self) {
        self.keys = None;
    }

    /// Hosts call this from their inactivity timer and use monotonic elapsed time.
    pub fn tick(&mut self, now_ms: u64) -> Result<bool, ClientError> {
        if now_ms < self.last_activity_ms {
            self.lock();
            return Err(ClientError::ClockRegressed);
        }
        if now_ms - self.last_activity_ms >= self.policy.idle_timeout_ms {
            self.lock();
        }
        Ok(self.is_unlocked())
    }

    pub fn persist(
        &mut self,
        store: &impl LocalStateCipher,
        root: &SecretHandle,
        sequence: u64,
        now_ms: u64,
    ) -> Result<EncryptedEndpointKeys, ClientError> {
        self.require_unlocked(now_ms)?;
        let keys = self.keys.as_ref().ok_or(ClientError::Locked)?;
        let recipient = keys
            .recipient
            .seal_local(store, root, &self.card.endpoint_id, sequence)?;
        let signer = keys
            .signer
            .seal_local(store, root, &self.card.endpoint_id, sequence)?;
        let record = EncryptedEndpointKeys::from_ciphertexts(recipient, signer)?;
        self.last_activity_ms = now_ms;
        Ok(record)
    }

    pub fn restore(
        &mut self,
        store: &impl LocalStateCipher,
        root: &SecretHandle,
        minimum_sequence: u64,
        record: &EncryptedEndpointKeys,
        now_ms: u64,
    ) -> Result<(), ClientError> {
        if self.is_unlocked() {
            return Err(ClientError::AlreadyUnlocked);
        }
        if now_ms < self.last_activity_ms {
            return Err(ClientError::ClockRegressed);
        }
        let recipient = RecipientPrivateKey::open_local(
            store,
            root,
            &self.card.endpoint_id,
            &self.card.recipient_public_key,
            minimum_sequence,
            &record.recipient,
        )?;
        let signer = CapsuleSigningKey::open_local(
            store,
            root,
            &self.card.endpoint_id,
            &self.card.signer_public_key,
            minimum_sequence,
            &record.signer,
        )?;
        self.keys = Some(EndpointKeys { recipient, signer });
        self.last_activity_ms = now_ms;
        Ok(())
    }

    pub fn encrypt_text(
        &mut self,
        recipients: &[VerifiedContact],
        text: &str,
        signature: SignatureMode<'_>,
        now_ms: u64,
    ) -> Result<Delivery, ClientError> {
        self.require_unlocked(now_ms)?;
        let recipients: Vec<_> = recipients.iter().map(|r| r.0.recipient()).collect();
        let capsule = encrypt_text_for_recipients(&recipients, text, None)?;
        let signature = match signature {
            SignatureMode::Unsigned => None,
            SignatureMode::Signed { context } => Some(sign_capsule(
                &self.keys.as_ref().ok_or(ClientError::Locked)?.signer,
                &capsule,
                context,
                CapsuleLimits::default(),
            )?),
        };
        self.last_activity_ms = now_ms;
        Ok(Delivery { capsule, signature })
    }

    pub fn open_text(
        &mut self,
        delivery: &Delivery,
        sender: SenderPolicy<'_>,
        now_ms: u64,
    ) -> Result<OpenedText, ClientError> {
        self.require_unlocked(now_ms)?;
        let provenance = match sender {
            SenderPolicy::RequireSignature { sender, context } => {
                Some(delivery.verify_required_signature(
                    &TrustedSigner::from_public_key(sender.0.signer_public_key)?,
                    context,
                    CapsuleLimits::default(),
                )?)
            }
            SenderPolicy::PermitUnsigned => {
                if delivery.signature.is_some() {
                    return Err(ClientError::UnexpectedSignature);
                }
                None
            }
        };
        let text = decrypt_text(
            self.card.endpoint_id.as_str().as_bytes(),
            &self.keys.as_ref().ok_or(ClientError::Locked)?.recipient,
            &delivery.capsule,
        )?;
        self.last_activity_ms = now_ms;
        Ok(OpenedText {
            message_id: text.message_id,
            content_type: text.content_type,
            provenance,
            text: Zeroizing::new(text.text),
        })
    }

    fn require_unlocked(&mut self, now_ms: u64) -> Result<(), ClientError> {
        if !self.tick(now_ms)? {
            return Err(ClientError::Locked);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use e2ee_core::ProfileId;
    use e2ee_keystore::{
        software::{KdfBudget, SoftwareVault, VaultKdf},
        ProvisionRequest, SecretClass, SecureKeyStore, SOFTWARE_VAULT_PROFILE,
    };

    fn session(id: &str) -> EndpointSession {
        EndpointSession::create_local(
            EndpointId::parse(id).unwrap(),
            SessionPolicy {
                idle_timeout_ms: 100,
            },
            0,
        )
        .unwrap()
    }

    fn verified(session: &EndpointSession) -> VerifiedContact {
        VerifiedContact::confirm(session.card().clone(), session.card().fingerprint()).unwrap()
    }

    #[test]
    fn fingerprints_cover_identity_and_both_keys() {
        let alice = session("alice");
        assert!(VerifiedContact::confirm(alice.card().clone(), [0; 32]).is_err());
        let original = alice.card().fingerprint();
        for changed in [
            EndpointCard {
                endpoint_id: EndpointId::parse("other").unwrap(),
                ..alice.card().clone()
            },
            EndpointCard {
                recipient_public_key: [1; 32],
                ..alice.card().clone()
            },
            EndpointCard {
                signer_public_key: [2; 32],
                ..alice.card().clone()
            },
        ] {
            assert_ne!(original, changed.fingerprint());
        }
    }

    #[test]
    fn verified_recipients_receive_signed_text_and_sender_policy_fails_closed() {
        let mut alice = session("alice");
        let mut bob = session("bob");
        let mut eve = session("eve");
        let alice_pin = verified(&alice);
        let bob_pin = verified(&bob);
        let eve_pin = verified(&eve);
        let delivery = alice
            .encrypt_text(
                &[bob_pin, eve_pin.clone()],
                "private hello",
                SignatureMode::Signed {
                    context: "conversation-1",
                },
                1,
            )
            .unwrap();
        let opened = bob
            .open_text(
                &delivery,
                SenderPolicy::RequireSignature {
                    sender: &alice_pin,
                    context: "conversation-1",
                },
                2,
            )
            .unwrap();
        assert_eq!(opened.text(), "private hello");
        assert!(opened.provenance.is_some());
        assert!(!format!("{opened:?}").contains("private hello"));
        assert!(eve
            .open_text(
                &delivery,
                SenderPolicy::RequireSignature {
                    sender: &alice_pin,
                    context: "conversation-1"
                },
                2
            )
            .is_ok());
        assert!(bob
            .open_text(
                &delivery,
                SenderPolicy::RequireSignature {
                    sender: &eve_pin,
                    context: "conversation-1"
                },
                3
            )
            .is_err());
        assert!(bob
            .open_text(
                &delivery,
                SenderPolicy::RequireSignature {
                    sender: &alice_pin,
                    context: "other"
                },
                3
            )
            .is_err());
        assert!(matches!(
            bob.open_text(&delivery, SenderPolicy::PermitUnsigned, 3),
            Err(ClientError::UnexpectedSignature)
        ));
    }

    #[test]
    fn unsigned_content_never_satisfies_required_sender_verification() {
        let mut alice = session("alice");
        let mut bob = session("bob");
        let delivery = alice
            .encrypt_text(
                &[verified(&bob)],
                "anonymous text",
                SignatureMode::Unsigned,
                1,
            )
            .unwrap();
        assert!(bob
            .open_text(
                &delivery,
                SenderPolicy::RequireSignature {
                    sender: &verified(&alice),
                    context: "test"
                },
                1
            )
            .is_err());
        let opened = bob
            .open_text(&delivery, SenderPolicy::PermitUnsigned, 1)
            .unwrap();
        assert_eq!(opened.text(), "anonymous text");
        assert!(opened.provenance.is_none());
    }

    #[test]
    fn inactivity_manual_lock_and_clock_regression_clear_endpoint_keys() {
        let mut alice = session("alice");
        let pin = verified(&session("bob"));
        assert!(alice.tick(99).unwrap());
        assert!(!alice.tick(100).unwrap());
        assert!(matches!(
            alice.encrypt_text(
                std::slice::from_ref(&pin),
                "secret",
                SignatureMode::Unsigned,
                100
            ),
            Err(ClientError::Locked)
        ));
        let mut alice = session("alice");
        alice
            .encrypt_text(&[pin], "secret", SignatureMode::Unsigned, 10)
            .unwrap();
        assert_eq!(alice.tick(9), Err(ClientError::ClockRegressed));
        assert!(!alice.is_unlocked());
        let mut alice = session("alice");
        alice.lock();
        assert!(!alice.is_unlocked());
    }

    #[test]
    fn encrypted_restore_is_atomic_and_preserves_pinned_identity() {
        let profile = ProfileId::parse(SOFTWARE_VAULT_PROFILE).unwrap();
        let mut vault = SoftwareVault::create(
            &profile,
            Zeroizing::new(b"long enough vault unlock phrase".to_vec()),
            VaultKdf::default(),
            KdfBudget::default(),
        )
        .unwrap();
        let root = SecretHandle::parse("client/protocol-state").unwrap();
        vault
            .provision(ProvisionRequest {
                handle: root.clone(),
                class: SecretClass::ProtocolStateWrappingRoot,
                required_profile: profile,
                minimum_generation: 1,
            })
            .unwrap();
        let mut alice = session("alice");
        let card = alice.card().clone();
        let record = alice.persist(&vault, &root, 4, 1).unwrap();
        alice.lock();
        let (recipient, signer) = record.ciphertexts();
        let mut changed = signer.to_vec();
        changed[40] ^= 1;
        let bad = EncryptedEndpointKeys::from_ciphertexts(recipient.to_vec(), changed).unwrap();
        assert!(alice.restore(&vault, &root, 4, &bad, 2).is_err());
        assert!(!alice.is_unlocked());
        alice.restore(&vault, &root, 4, &record, 2).unwrap();
        assert_eq!(alice.card(), &card);
        assert!(matches!(
            alice.restore(&vault, &root, 4, &record, 2),
            Err(ClientError::AlreadyUnlocked)
        ));
        let mut impostor = EndpointSession::from_pinned_card(
            session("alice").card().clone(),
            SessionPolicy::default(),
            0,
        )
        .unwrap();
        assert!(impostor.restore(&vault, &root, 4, &record, 1).is_err());
        assert!(!impostor.is_unlocked());
    }
}
