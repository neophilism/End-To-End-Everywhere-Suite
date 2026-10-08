//! Encrypted address-book state and explicit contact-key lifecycle decisions.

use crate::{
    ClientError, EndpointCard, EndpointSession, SenderPolicy, SignatureMode, VerifiedContact,
};
use e2ee_core::EndpointId;
use e2ee_file::FileOptions;
use e2ee_keystore::{
    software::VaultError, state::LocalStateCipher, validate_backend_for_profile, KeyStoreError,
    SecretClass, SecretHandle,
};
use e2ee_transport::Delivery;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};
use zeroize::Zeroizing;

const MAX_CONTACTS: usize = 1024;
const MAX_BOOK_BYTES: usize = 512 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContactStatus {
    Unverified,
    Verified,
    KeyChanged,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContactError {
    InvalidCard,
    NotFound,
    Unverified,
    KeyChanged,
    Revoked,
    FingerprintMismatch,
    DuplicateRecipient,
    InvalidSelection,
    CapacityExceeded,
    Malformed,
    Vault(VaultError),
}

impl fmt::Display for ContactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidCard => "contact card is invalid",
            Self::NotFound => "contact was not found",
            Self::Unverified => "verify this contact's fingerprint before sending",
            Self::KeyChanged => {
                "contact keys changed; compare the new fingerprint before continuing"
            }
            Self::Revoked => "contact is revoked; explicit reactivation is required",
            Self::FingerprintMismatch => {
                "independently observed contact fingerprint does not match"
            }
            Self::DuplicateRecipient => "recipient selection contains a duplicate contact",
            Self::InvalidSelection => "select one or more verified contacts",
            Self::CapacityExceeded => "contact address book exceeds its capacity",
            Self::Malformed => "encrypted address book contents are malformed",
            Self::Vault(_) => "encrypted address book operation failed",
        })
    }
}

impl std::error::Error for ContactError {}

impl From<VaultError> for ContactError {
    fn from(value: VaultError) -> Self {
        Self::Vault(value)
    }
}

struct Entry {
    card: EndpointCard,
    verified_fingerprint: Option<[u8; 32]>,
    requires_reverification: bool,
    revoked: bool,
}

impl Entry {
    fn status(&self) -> ContactStatus {
        if self.revoked {
            return ContactStatus::Revoked;
        }
        match self.verified_fingerprint {
            None => ContactStatus::Unverified,
            Some(pin) if !self.requires_reverification && pin == self.card.fingerprint() => {
                ContactStatus::Verified
            }
            Some(_) => ContactStatus::KeyChanged,
        }
    }
}

#[derive(Default)]
pub struct ContactBook {
    entries: BTreeMap<EndpointId, Entry>,
}

impl fmt::Debug for ContactBook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContactBook")
            .field("contact_count", &self.entries.len())
            .field("contacts", &"[REDACTED]")
            .finish()
    }
}

impl ContactBook {
    /// Current cards and lifecycle states, in canonical endpoint order. This
    /// view grants no trust and exposes no stored verification fingerprints.
    pub fn contacts(&self) -> impl Iterator<Item = (&EndpointCard, ContactStatus)> {
        self.entries
            .values()
            .map(|entry| (&entry.card, entry.status()))
    }

    /// Observing a card never grants or restores trust. Once a verified contact
    /// changes, even a later replay of its old card still requires re-verification.
    pub fn observe(&mut self, card: EndpointCard) -> Result<ContactStatus, ContactError> {
        card.validate().map_err(|_| ContactError::InvalidCard)?;
        if let Some(entry) = self.entries.get_mut(&card.endpoint_id) {
            if entry.card != card {
                entry.requires_reverification |= entry.verified_fingerprint.is_some();
                entry.card = card;
            }
            return Ok(entry.status());
        }
        if self.entries.len() >= MAX_CONTACTS {
            return Err(ContactError::CapacityExceeded);
        }
        self.entries.insert(
            card.endpoint_id.clone(),
            Entry {
                card,
                verified_fingerprint: None,
                requires_reverification: false,
                revoked: false,
            },
        );
        Ok(ContactStatus::Unverified)
    }

    pub fn card(&self, endpoint: &EndpointId) -> Result<&EndpointCard, ContactError> {
        Ok(&self
            .entries
            .get(endpoint)
            .ok_or(ContactError::NotFound)?
            .card)
    }

    pub fn status(&self, endpoint: &EndpointId) -> Result<ContactStatus, ContactError> {
        Ok(self
            .entries
            .get(endpoint)
            .ok_or(ContactError::NotFound)?
            .status())
    }

    pub fn verify(
        &mut self,
        endpoint: &EndpointId,
        independently_observed: [u8; 32],
    ) -> Result<(), ContactError> {
        let entry = self
            .entries
            .get_mut(endpoint)
            .ok_or(ContactError::NotFound)?;
        if entry.revoked {
            return Err(ContactError::Revoked);
        }
        confirm(entry, independently_observed)
    }

    pub fn revoke(&mut self, endpoint: &EndpointId) -> Result<(), ContactError> {
        self.entries
            .get_mut(endpoint)
            .ok_or(ContactError::NotFound)?
            .revoked = true;
        Ok(())
    }

    /// Explicit local action; revocation cannot be cleared by observe/import.
    pub fn reactivate(
        &mut self,
        endpoint: &EndpointId,
        independently_observed: [u8; 32],
    ) -> Result<(), ContactError> {
        let entry = self
            .entries
            .get_mut(endpoint)
            .ok_or(ContactError::NotFound)?;
        confirm(entry, independently_observed)?;
        entry.revoked = false;
        Ok(())
    }

    pub fn verified_contact(&self, endpoint: &EndpointId) -> Result<VerifiedContact, ContactError> {
        let entry = self.entries.get(endpoint).ok_or(ContactError::NotFound)?;
        match entry.status() {
            ContactStatus::Unverified => return Err(ContactError::Unverified),
            ContactStatus::KeyChanged => return Err(ContactError::KeyChanged),
            ContactStatus::Revoked => return Err(ContactError::Revoked),
            ContactStatus::Verified => (),
        }
        VerifiedContact::confirm(
            entry.card.clone(),
            entry.verified_fingerprint.ok_or(ContactError::Unverified)?,
        )
        .map_err(|_| ContactError::FingerprintMismatch)
    }

    pub fn resolve_recipients(
        &self,
        endpoints: &[EndpointId],
    ) -> Result<Vec<VerifiedContact>, ContactError> {
        if endpoints.is_empty() || endpoints.len() > MAX_CONTACTS {
            return Err(ContactError::InvalidSelection);
        }
        let mut seen = BTreeSet::new();
        endpoints
            .iter()
            .map(|id| {
                if !seen.insert(id) {
                    return Err(ContactError::DuplicateRecipient);
                }
                self.verified_contact(id)
            })
            .collect()
    }

    pub fn seal_local(
        &self,
        store: &impl LocalStateCipher,
        root: &SecretHandle,
        owner: &EndpointId,
        sequence: u64,
    ) -> Result<Vec<u8>, ContactError> {
        let context = context(store, root, owner)?;
        let mut plaintext = Zeroizing::new(b"E2CB\0\x01".to_vec());
        plaintext.extend_from_slice(&(self.entries.len() as u16).to_be_bytes());
        for entry in self.entries.values() {
            let card = entry.card.encode().map_err(|_| ContactError::InvalidCard)?;
            plaintext.extend_from_slice(&(card.len() as u16).to_be_bytes());
            plaintext.extend_from_slice(&card);
            plaintext.push(
                u8::from(entry.verified_fingerprint.is_some())
                    | (u8::from(entry.revoked) << 1)
                    | (u8::from(entry.requires_reverification) << 2),
            );
            if let Some(pin) = entry.verified_fingerprint {
                plaintext.extend_from_slice(&pin);
            }
        }
        if plaintext.len() > MAX_BOOK_BYTES {
            return Err(ContactError::CapacityExceeded);
        }
        Ok(store.seal_state(root, sequence, &context, &plaintext)?)
    }

    pub fn open_local(
        store: &impl LocalStateCipher,
        root: &SecretHandle,
        owner: &EndpointId,
        minimum_sequence: u64,
        ciphertext: &[u8],
    ) -> Result<Self, ContactError> {
        if ciphertext.len() > MAX_BOOK_BYTES + 54 {
            return Err(ContactError::CapacityExceeded);
        }
        let context = context(store, root, owner)?;
        let plaintext = store.open_state(root, minimum_sequence, &context, ciphertext)?;
        decode(&plaintext)
    }
}

fn confirm(entry: &mut Entry, independently_observed: [u8; 32]) -> Result<(), ContactError> {
    if entry.card.fingerprint() != independently_observed {
        return Err(ContactError::FingerprintMismatch);
    }
    entry.verified_fingerprint = Some(independently_observed);
    entry.requires_reverification = false;
    Ok(())
}

fn context(
    store: &impl LocalStateCipher,
    root: &SecretHandle,
    owner: &EndpointId,
) -> Result<Vec<u8>, ContactError> {
    let metadata = store
        .metadata(root)
        .map_err(|error| ContactError::Vault(error.into()))?;
    validate_backend_for_profile(store.profile(), metadata.backend)
        .map_err(|error| ContactError::Vault(error.into()))?;
    if metadata.class != SecretClass::ProtocolStateWrappingRoot {
        return Err(ContactError::Vault(KeyStoreError::PolicyViolation.into()));
    }
    if owner.as_str().len() > 128 {
        return Err(ContactError::InvalidCard);
    }
    let mut context = b"End-To-End Everywhere contact book v1\0".to_vec();
    context.extend_from_slice(&(owner.as_str().len() as u16).to_be_bytes());
    context.extend_from_slice(owner.as_str().as_bytes());
    Ok(context)
}

fn decode(bytes: &[u8]) -> Result<ContactBook, ContactError> {
    if bytes.len() < 8 || bytes.len() > MAX_BOOK_BYTES || bytes[..6] != *b"E2CB\0\x01" {
        return Err(ContactError::Malformed);
    }
    let count = usize::from(u16::from_be_bytes([bytes[6], bytes[7]]));
    if count > MAX_CONTACTS {
        return Err(ContactError::CapacityExceeded);
    }
    let mut offset = 8_usize;
    let mut entries = BTreeMap::new();
    let mut previous: Option<EndpointId> = None;
    for _ in 0..count {
        let length = take(bytes, &mut offset, 2)?;
        let length = usize::from(u16::from_be_bytes([length[0], length[1]]));
        let card = EndpointCard::decode(take(bytes, &mut offset, length)?)
            .map_err(|_| ContactError::InvalidCard)?;
        if previous.as_ref().is_some_and(|p| p >= &card.endpoint_id) {
            return Err(ContactError::Malformed);
        }
        previous = Some(card.endpoint_id.clone());
        let flags = take(bytes, &mut offset, 1)?[0];
        if flags > 7 || flags & 4 != 0 && flags & 1 == 0 {
            return Err(ContactError::Malformed);
        }
        let verified_fingerprint = if flags & 1 != 0 {
            Some(
                take(bytes, &mut offset, 32)?
                    .try_into()
                    .map_err(|_| ContactError::Malformed)?,
            )
        } else {
            None
        };
        entries.insert(
            card.endpoint_id.clone(),
            Entry {
                card,
                verified_fingerprint,
                revoked: flags & 2 != 0,
                requires_reverification: flags & 4 != 0,
            },
        );
    }
    if offset != bytes.len() {
        return Err(ContactError::Malformed);
    }
    Ok(ContactBook { entries })
}

fn take<'a>(bytes: &'a [u8], offset: &mut usize, length: usize) -> Result<&'a [u8], ContactError> {
    let end = offset.checked_add(length).ok_or(ContactError::Malformed)?;
    let value = bytes.get(*offset..end).ok_or(ContactError::Malformed)?;
    *offset = end;
    Ok(value)
}

impl EndpointSession {
    pub fn encrypt_text_to_contacts(
        &mut self,
        book: &ContactBook,
        endpoints: &[EndpointId],
        text: &str,
        signature: SignatureMode<'_>,
        now_ms: u64,
    ) -> Result<Delivery, ClientError> {
        self.require_unlocked(now_ms)?;
        self.encrypt_text(
            &book.resolve_recipients(endpoints)?,
            text,
            signature,
            now_ms,
        )
    }

    pub fn encrypt_file_to_contacts(
        &mut self,
        book: &ContactBook,
        endpoints: &[EndpointId],
        options: &FileOptions,
        bytes: &[u8],
        signature: SignatureMode<'_>,
        now_ms: u64,
    ) -> Result<Delivery, ClientError> {
        self.require_unlocked(now_ms)?;
        self.encrypt_file(
            &book.resolve_recipients(endpoints)?,
            options,
            bytes,
            signature,
            now_ms,
        )
    }

    pub fn open_text_from_contact(
        &mut self,
        book: &ContactBook,
        sender: &EndpointId,
        context: &str,
        delivery: &Delivery,
        now_ms: u64,
    ) -> Result<crate::OpenedText, ClientError> {
        self.require_unlocked(now_ms)?;
        let sender = book.verified_contact(sender)?;
        self.open_text(
            delivery,
            SenderPolicy::RequireSignature {
                sender: &sender,
                context,
            },
            now_ms,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SessionPolicy;
    use e2ee_core::ProfileId;
    use e2ee_keystore::{
        software::{KdfBudget, SoftwareVault, VaultKdf},
        ProvisionRequest, SecureKeyStore, SOFTWARE_VAULT_PROFILE,
    };

    fn session(id: &str) -> EndpointSession {
        EndpointSession::create_local(EndpointId::parse(id).unwrap(), SessionPolicy::default(), 0)
            .unwrap()
    }

    #[test]
    fn changed_and_replayed_keys_require_explicit_reverification() {
        let original = session("bob").card().clone();
        let replacement = session("bob").card().clone();
        let id = original.endpoint_id.clone();
        let mut book = ContactBook::default();
        assert_eq!(
            book.observe(original.clone()).unwrap(),
            ContactStatus::Unverified
        );
        assert_eq!(book.verified_contact(&id), Err(ContactError::Unverified));
        assert_eq!(
            book.verify(&id, [0; 32]),
            Err(ContactError::FingerprintMismatch)
        );
        book.verify(&id, original.fingerprint()).unwrap();
        assert_eq!(
            book.observe(original.clone()).unwrap(),
            ContactStatus::Verified
        );
        assert_eq!(
            book.observe(replacement.clone()).unwrap(),
            ContactStatus::KeyChanged
        );
        assert_eq!(book.verified_contact(&id), Err(ContactError::KeyChanged));
        assert_eq!(
            book.observe(original.clone()).unwrap(),
            ContactStatus::KeyChanged
        );
        book.observe(replacement.clone()).unwrap();
        assert_eq!(
            book.verify(&id, original.fingerprint()),
            Err(ContactError::FingerprintMismatch)
        );
        book.verify(&id, replacement.fingerprint()).unwrap();
        assert_eq!(book.status(&id).unwrap(), ContactStatus::Verified);
    }

    #[test]
    fn revocation_blocks_new_operations_and_cannot_be_reset_by_import() {
        let mut alice = session("alice");
        let bob = session("bob");
        let id = bob.card().endpoint_id.clone();
        let mut book = ContactBook::default();
        book.observe(bob.card().clone()).unwrap();
        assert!(alice
            .encrypt_text_to_contacts(
                &book,
                std::slice::from_ref(&id),
                "secret",
                SignatureMode::Unsigned,
                1
            )
            .is_err());
        book.verify(&id, bob.card().fingerprint()).unwrap();
        assert!(alice
            .encrypt_text_to_contacts(
                &book,
                std::slice::from_ref(&id),
                "secret",
                SignatureMode::Unsigned,
                1
            )
            .is_ok());
        book.revoke(&id).unwrap();
        assert_eq!(
            book.observe(bob.card().clone()).unwrap(),
            ContactStatus::Revoked
        );
        assert_eq!(
            book.verify(&id, bob.card().fingerprint()),
            Err(ContactError::Revoked)
        );
        assert!(alice
            .encrypt_text_to_contacts(
                &book,
                std::slice::from_ref(&id),
                "secret",
                SignatureMode::Unsigned,
                2
            )
            .is_err());
        assert_eq!(
            book.reactivate(&id, [0; 32]),
            Err(ContactError::FingerprintMismatch)
        );
        book.reactivate(&id, bob.card().fingerprint()).unwrap();
        assert!(book.resolve_recipients(&[id.clone(), id]).is_err());
        assert!(book.resolve_recipients(&[]).is_err());
    }

    #[test]
    fn encrypted_contact_state_preserves_lifecycle_and_binds_owner_and_floor() {
        let mut book = ContactBook::default();
        let bob = session("bob").card().clone();
        let eve = session("eve").card().clone();
        book.observe(bob.clone()).unwrap();
        book.verify(&bob.endpoint_id, bob.fingerprint()).unwrap();
        book.observe(eve.clone()).unwrap();
        book.revoke(&eve.endpoint_id).unwrap();
        let profile = ProfileId::parse(SOFTWARE_VAULT_PROFILE).unwrap();
        let mut vault = SoftwareVault::create(
            &profile,
            Zeroizing::new(b"long local address book secret".to_vec()),
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
        let owner = EndpointId::parse("alice").unwrap();
        let ciphertext = book.seal_local(&vault, &root, &owner, 5).unwrap();
        let restored = ContactBook::open_local(&vault, &root, &owner, 5, &ciphertext).unwrap();
        assert_eq!(
            restored.status(&bob.endpoint_id).unwrap(),
            ContactStatus::Verified
        );
        assert_eq!(
            restored.status(&eve.endpoint_id).unwrap(),
            ContactStatus::Revoked
        );
        assert!(ContactBook::open_local(
            &vault,
            &root,
            &EndpointId::parse("other").unwrap(),
            5,
            &ciphertext
        )
        .is_err());
        assert!(ContactBook::open_local(&vault, &root, &owner, 6, &ciphertext).is_err());
        assert!(!format!("{restored:?}").contains("bob"));
    }

    #[test]
    fn address_book_parser_rejects_duplicates_flags_truncation_and_trailing_bytes() {
        assert!(decode(b"E2CB\0\x01\0\0").is_ok());
        assert!(decode(b"E2CB\0\x01\0\0\0").is_err());
        let card = session("bob").card().encode().unwrap();
        let mut one = b"E2CB\0\x01\0\x01".to_vec();
        one.extend_from_slice(&(card.len() as u16).to_be_bytes());
        one.extend_from_slice(&card);
        one.push(0);
        for i in 0..one.len() {
            assert!(decode(&one[..i]).is_err());
        }
        assert!(decode(&one).is_ok());
        *one.last_mut().unwrap() = 4;
        assert!(decode(&one).is_err());
        *one.last_mut().unwrap() = 0;
        let mut duplicate = one.clone();
        duplicate[6..8].copy_from_slice(&2_u16.to_be_bytes());
        duplicate.extend_from_slice(&one[8..]);
        assert!(decode(&duplicate).is_err());
    }
}
