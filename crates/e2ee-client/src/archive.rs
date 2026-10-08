//! One encrypted archive and one combined lifetime for local vault/client state.

use crate::{
    contacts::{ContactBook, ContactError},
    ClientError, EncryptedEndpointKeys, EndpointCard, EndpointSession, SessionPolicy,
};
use e2ee_core::{EndpointId, ProfileId};
use e2ee_keystore::{
    software::{
        KdfBudget, SoftwareVault, VaultError, VaultKdf, MAX_SNAPSHOT_BYTES, MAX_STATE_BYTES,
    },
    ProvisionRequest, SecretClass, SecretHandle, SecureKeyStore,
};
use e2ee_storage::{PrivateStateStore, StateDigest, StorageError};
use std::fmt;
use zeroize::Zeroizing;

const ARCHIVE_PREFIX: &[u8; 6] = b"E2CA\0\x01";
const PAYLOAD_PREFIX: &[u8; 6] = b"E2AP\0\x01";
const ANCHOR_PREFIX: &[u8; 6] = b"E2AT\0\x01";
const CONTEXT: &[u8] = b"End-To-End Everywhere complete local client archive v1\0";
const ROOT: &str = "client/archive/protocol-state/v1";
pub const MAX_ARCHIVE_BYTES: usize = 14 + MAX_SNAPSHOT_BYTES + MAX_STATE_BYTES + 54;

/// Retain this value in an independently trusted anchor. Storing it beside a
/// replayable archive does not confer rollback resistance or independent pins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveAnchor {
    pub vault_id: [u8; 16],
    pub minimum_revision: u64,
    pub minimum_sequence: u64,
    pub endpoint_fingerprint: [u8; 32],
}

impl ArchiveAnchor {
    pub fn encode(&self) -> Result<Vec<u8>, ArchiveError> {
        self.validate()?;
        let mut bytes = ANCHOR_PREFIX.to_vec();
        bytes.extend_from_slice(&self.vault_id);
        bytes.extend_from_slice(&self.minimum_revision.to_be_bytes());
        bytes.extend_from_slice(&self.minimum_sequence.to_be_bytes());
        bytes.extend_from_slice(&self.endpoint_fingerprint);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ArchiveError> {
        if bytes.len() != 70 || bytes[..6] != *ANCHOR_PREFIX {
            return Err(ArchiveError::Malformed);
        }
        let anchor = Self {
            vault_id: bytes[6..22]
                .try_into()
                .map_err(|_| ArchiveError::Malformed)?,
            minimum_revision: number64(&bytes[22..30])?,
            minimum_sequence: number64(&bytes[30..38])?,
            endpoint_fingerprint: bytes[38..]
                .try_into()
                .map_err(|_| ArchiveError::Malformed)?,
        };
        anchor.validate()?;
        Ok(anchor)
    }

    fn validate(&self) -> Result<(), ArchiveError> {
        if self.minimum_revision == 0 || self.minimum_sequence == 0 {
            return Err(ArchiveError::Malformed);
        }
        Ok(())
    }
}

pub enum RestorePolicy<'a> {
    Anchored(&'a ArchiveAnchor),
    /// Explicit basic local password protection. No independently pinned vault,
    /// endpoint identity or rollback floor is available under this policy.
    PasswordOnly,
}

#[derive(Debug)]
pub enum ArchiveError {
    Locked,
    Malformed,
    LimitExceeded,
    PinMismatch,
    SequenceExhausted,
    Client(ClientError),
    Contact(ContactError),
    Vault(VaultError),
    Storage(StorageError),
}

impl fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Locked => f.write_str("local archive client is locked"),
            Self::Malformed => f.write_str("local client archive is malformed"),
            Self::LimitExceeded => f.write_str("local client archive exceeds its size limit"),
            Self::PinMismatch => {
                f.write_str("archive endpoint differs from the trusted fingerprint")
            }
            Self::SequenceExhausted => f.write_str("local archive sequence is exhausted"),
            Self::Client(error) => error.fmt(f),
            Self::Contact(error) => error.fmt(f),
            Self::Vault(error) => error.fmt(f),
            Self::Storage(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for ArchiveError {}

macro_rules! error_from {
    ($type:ty, $variant:ident) => {
        impl From<$type> for ArchiveError {
            fn from(value: $type) -> Self {
                Self::$variant(value)
            }
        }
    };
}
error_from!(ClientError, Client);
error_from!(ContactError, Contact);
error_from!(VaultError, Vault);
error_from!(StorageError, Storage);

struct Unlocked {
    vault: SoftwareVault,
    session: EndpointSession,
    contacts: ContactBook,
    sequence: u64,
}

/// Software-vault archive controller. Lock drops the root provider and both
/// endpoint keys together. Hosts still handle OS suspend/logout and plaintext.
pub struct LocalClient {
    card: EndpointCard,
    unlocked: Option<Unlocked>,
}

impl fmt::Debug for LocalClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalClient")
            .field("unlocked", &self.unlocked.is_some())
            .field("state", &"[REDACTED]")
            .finish()
    }
}

impl LocalClient {
    /// Select the exact software profile explicitly. No native/hardware request
    /// is silently downgraded. Save the new client before reporting creation.
    pub fn create(
        endpoint: EndpointId,
        required_profile: &ProfileId,
        passphrase: Zeroizing<Vec<u8>>,
        kdf: VaultKdf,
        budget: KdfBudget,
        session_policy: SessionPolicy,
        now_ms: u64,
    ) -> Result<Self, ArchiveError> {
        let mut vault = SoftwareVault::create(required_profile, passphrase, kdf, budget)?;
        vault
            .provision(ProvisionRequest {
                handle: root(),
                class: SecretClass::ProtocolStateWrappingRoot,
                required_profile: required_profile.clone(),
                minimum_generation: 1,
            })
            .map_err(VaultError::from)?;
        let session = EndpointSession::create_local(endpoint, session_policy, now_ms)?;
        Ok(Self {
            card: session.card().clone(),
            unlocked: Some(Unlocked {
                vault,
                session,
                contacts: ContactBook::default(),
                sequence: 0,
            }),
        })
    }

    pub fn open(
        bytes: &[u8],
        passphrase: Zeroizing<Vec<u8>>,
        policy: RestorePolicy<'_>,
        budget: KdfBudget,
        session_policy: SessionPolicy,
        now_ms: u64,
    ) -> Result<Self, ArchiveError> {
        let (snapshot, encrypted_payload) = split_archive(bytes)?;
        let (id, revision, sequence, pin) = match policy {
            RestorePolicy::Anchored(anchor) => {
                anchor.validate()?;
                (
                    anchor.vault_id,
                    anchor.minimum_revision,
                    anchor.minimum_sequence,
                    Some(anchor.endpoint_fingerprint),
                )
            }
            RestorePolicy::PasswordOnly => {
                // This ID is an untrusted lookup hint, not an independent pin.
                // Vault authentication still uses the supplied local password.
                let id = snapshot
                    .get(18..34)
                    .ok_or(ArchiveError::Malformed)?
                    .try_into()
                    .map_err(|_| ArchiveError::Malformed)?;
                (id, 1, 1, None)
            }
        };
        let vault = SoftwareVault::unlock(snapshot, passphrase, id, revision, budget)?;
        let payload = vault.open_state(&root(), sequence, CONTEXT, encrypted_payload)?;
        let decoded = decode_payload(&payload)?;
        // Enforce a single authenticated sequence for the whole archive and all
        // nested components, rather than accepting mixed snapshots of key state.
        if encrypted_payload.get(14..22) != Some(decoded.sequence.to_be_bytes().as_slice()) {
            return Err(ArchiveError::Malformed);
        }
        if pin.is_some_and(|pin| pin != decoded.card.fingerprint()) {
            return Err(ArchiveError::PinMismatch);
        }
        let (recipient, signer) = decoded.keys.ciphertexts();
        for record in [recipient, signer, decoded.contacts] {
            if record.get(14..22) != Some(decoded.sequence.to_be_bytes().as_slice()) {
                return Err(ArchiveError::Malformed);
            }
        }
        let contacts = ContactBook::open_local(
            &vault,
            &root(),
            &decoded.card.endpoint_id,
            decoded.sequence,
            decoded.contacts,
        )?;
        let mut session =
            EndpointSession::from_pinned_card(decoded.card.clone(), session_policy, now_ms)?;
        session.restore(&vault, &root(), decoded.sequence, &decoded.keys, now_ms)?;
        Ok(Self {
            card: decoded.card,
            unlocked: Some(Unlocked {
                vault,
                session,
                contacts,
                sequence: decoded.sequence,
            }),
        })
    }

    pub fn card(&self) -> &EndpointCard {
        &self.card
    }

    pub fn lock(&mut self) {
        self.unlocked = None;
    }

    pub fn tick(&mut self, now_ms: u64) -> Result<bool, ArchiveError> {
        let result = match &mut self.unlocked {
            Some(state) => state.session.tick(now_ms),
            None => return Ok(false),
        };
        if !matches!(result, Ok(true)) {
            self.lock();
        }
        Ok(result?)
    }

    /// Both references belong to this unlocked transaction. Contact operations
    /// must use the current book, so key changes and revocation are respected.
    pub fn session_and_contacts(
        &mut self,
        now_ms: u64,
    ) -> Result<(&mut EndpointSession, &mut ContactBook), ArchiveError> {
        self.require_unlocked(now_ms)?;
        let state = self.unlocked.as_mut().ok_or(ArchiveError::Locked)?;
        Ok((&mut state.session, &mut state.contacts))
    }

    pub fn change_passphrase(
        &mut self,
        passphrase: Zeroizing<Vec<u8>>,
        kdf: VaultKdf,
        budget: KdfBudget,
        now_ms: u64,
    ) -> Result<(), ArchiveError> {
        self.require_unlocked(now_ms)?;
        self.unlocked
            .as_mut()
            .ok_or(ArchiveError::Locked)?
            .vault
            .change_passphrase(passphrase, kdf, budget)?;
        Ok(())
    }

    /// One durable commit of vault, endpoint keys and contacts. The in-memory
    /// sequence advances only after file and directory sync succeed. Store the
    /// returned anchor independently *after* this succeeds. On an uncertain
    /// durability error, discard/reload this transaction before trying again.
    pub fn save(
        &mut self,
        store: &mut PrivateStateStore,
        expected: Option<StateDigest>,
        now_ms: u64,
    ) -> Result<ArchiveAnchor, ArchiveError> {
        self.require_unlocked(now_ms)?;
        let state = self.unlocked.as_mut().ok_or(ArchiveError::Locked)?;
        let sequence = state
            .sequence
            .checked_add(1)
            .ok_or(ArchiveError::SequenceExhausted)?;
        let keys = state
            .session
            .persist(&state.vault, &root(), sequence, now_ms)?;
        let contacts =
            state
                .contacts
                .seal_local(&state.vault, &root(), &self.card.endpoint_id, sequence)?;
        let card = self.card.encode()?;
        let mut payload = Zeroizing::new(PAYLOAD_PREFIX.to_vec());
        payload.extend_from_slice(&sequence.to_be_bytes());
        payload.extend_from_slice(&(card.len() as u16).to_be_bytes());
        payload.extend_from_slice(&card);
        payload.extend_from_slice(&keys.encode());
        payload.extend_from_slice(&(contacts.len() as u32).to_be_bytes());
        payload.extend_from_slice(&contacts);
        let encrypted = state
            .vault
            .seal_state(&root(), sequence, CONTEXT, &payload)?;
        let snapshot = state.vault.snapshot()?;
        let mut archive = ARCHIVE_PREFIX.to_vec();
        archive.extend_from_slice(&(snapshot.len() as u32).to_be_bytes());
        archive.extend_from_slice(&(encrypted.len() as u32).to_be_bytes());
        archive.extend_from_slice(&snapshot);
        archive.extend_from_slice(&encrypted);
        store.commit(expected, &archive)?;
        state.sequence = sequence;
        Ok(ArchiveAnchor {
            vault_id: state.vault.vault_id(),
            minimum_revision: state.vault.revision(),
            minimum_sequence: sequence,
            endpoint_fingerprint: self.card.fingerprint(),
        })
    }

    fn require_unlocked(&mut self, now_ms: u64) -> Result<(), ArchiveError> {
        if !self.tick(now_ms)? {
            return Err(ArchiveError::Locked);
        }
        Ok(())
    }
}

fn root() -> SecretHandle {
    SecretHandle::parse(ROOT).expect("the fixed archive root handle is valid")
}

fn split_archive(bytes: &[u8]) -> Result<(&[u8], &[u8]), ArchiveError> {
    if bytes.len() > MAX_ARCHIVE_BYTES {
        return Err(ArchiveError::LimitExceeded);
    }
    if bytes.len() < 14 || bytes[..6] != *ARCHIVE_PREFIX {
        return Err(ArchiveError::Malformed);
    }
    let snapshot_len = number32(&bytes[6..10])?;
    let payload_len = number32(&bytes[10..14])?;
    if !(90..=MAX_SNAPSHOT_BYTES).contains(&snapshot_len)
        || !(54..=MAX_STATE_BYTES + 54).contains(&payload_len)
    {
        return Err(ArchiveError::LimitExceeded);
    }
    if 14_usize
        .checked_add(snapshot_len)
        .and_then(|n| n.checked_add(payload_len))
        != Some(bytes.len())
    {
        return Err(ArchiveError::Malformed);
    }
    Ok((&bytes[14..14 + snapshot_len], &bytes[14 + snapshot_len..]))
}

struct DecodedPayload<'a> {
    sequence: u64,
    card: EndpointCard,
    keys: EncryptedEndpointKeys,
    contacts: &'a [u8],
}

fn decode_payload(bytes: &[u8]) -> Result<DecodedPayload<'_>, ArchiveError> {
    if bytes.len() < 16 || bytes.len() > MAX_STATE_BYTES || bytes[..6] != *PAYLOAD_PREFIX {
        return Err(ArchiveError::Malformed);
    }
    let sequence = number64(&bytes[6..14])?;
    if sequence == 0 {
        return Err(ArchiveError::Malformed);
    }
    let card_len = usize::from(u16::from_be_bytes([bytes[14], bytes[15]]));
    let mut offset = 16;
    let card = EndpointCard::decode(take(bytes, &mut offset, card_len)?)?;
    let keys = EncryptedEndpointKeys::decode(take(bytes, &mut offset, 182)?)?;
    let contacts_len = number32(take(bytes, &mut offset, 4)?)?;
    let contacts = take(bytes, &mut offset, contacts_len)?;
    if offset != bytes.len() {
        return Err(ArchiveError::Malformed);
    }
    Ok(DecodedPayload {
        sequence,
        card,
        keys,
        contacts,
    })
}

fn take<'a>(bytes: &'a [u8], offset: &mut usize, length: usize) -> Result<&'a [u8], ArchiveError> {
    let end = offset.checked_add(length).ok_or(ArchiveError::Malformed)?;
    let value = bytes.get(*offset..end).ok_or(ArchiveError::Malformed)?;
    *offset = end;
    Ok(value)
}

fn number32(bytes: &[u8]) -> Result<usize, ArchiveError> {
    usize::try_from(u32::from_be_bytes(
        bytes.try_into().map_err(|_| ArchiveError::Malformed)?,
    ))
    .map_err(|_| ArchiveError::LimitExceeded)
}

fn number64(bytes: &[u8]) -> Result<u64, ArchiveError> {
    Ok(u64::from_be_bytes(
        bytes.try_into().map_err(|_| ArchiveError::Malformed)?,
    ))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::{contacts::ContactStatus, SignatureMode};
    use e2ee_keystore::SOFTWARE_VAULT_PROFILE;
    use std::{fs, os::unix::fs::DirBuilderExt, path::PathBuf};

    struct TempDirectory(PathBuf);
    impl TempDirectory {
        fn new(id: &str) -> Self {
            let card = EndpointSession::create_local(
                EndpointId::parse(id).unwrap(),
                SessionPolicy::default(),
                0,
            )
            .unwrap();
            let path = std::env::temp_dir()
                .join(format!("e2ee-archive-{}", card.card().fingerprint_hex()));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
        fn store(&self) -> PrivateStateStore {
            PrivateStateStore::create(self.0.join("state")).unwrap()
        }
    }
    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn password() -> Zeroizing<Vec<u8>> {
        Zeroizing::new(b"a strong local archive test passphrase".to_vec())
    }
    fn create(id: &str) -> LocalClient {
        LocalClient::create(
            EndpointId::parse(id).unwrap(),
            &ProfileId::parse(SOFTWARE_VAULT_PROFILE).unwrap(),
            password(),
            VaultKdf::default(),
            KdfBudget::default(),
            SessionPolicy::default(),
            0,
        )
        .unwrap()
    }
    fn open(bytes: &[u8], policy: RestorePolicy<'_>) -> Result<LocalClient, ArchiveError> {
        LocalClient::open(
            bytes,
            password(),
            policy,
            KdfBudget::default(),
            SessionPolicy::default(),
            0,
        )
    }

    #[test]
    fn complete_archive_survives_restart_and_opens_real_signed_delivery() {
        let alice_temp = TempDirectory::new("alice");
        let bob_temp = TempDirectory::new("bob");
        let mut alice_store = alice_temp.store();
        let mut bob_store = bob_temp.store();
        let mut alice = create("alice");
        let mut bob = create("bob");
        let alice_card = alice.card().clone();
        let bob_card = bob.card().clone();
        for (client, contact) in [(&mut alice, &bob_card), (&mut bob, &alice_card)] {
            let (_, book) = client.session_and_contacts(0).unwrap();
            book.observe(contact.clone()).unwrap();
            book.verify(&contact.endpoint_id, contact.fingerprint())
                .unwrap();
        }
        let alice_anchor = alice.save(&mut alice_store, None, 1).unwrap();
        let bob_anchor = bob.save(&mut bob_store, None, 1).unwrap();
        drop(alice);
        drop(bob);
        drop(alice_store);
        drop(bob_store);
        let alice_store = PrivateStateStore::open(alice_temp.0.join("state")).unwrap();
        let bob_store = PrivateStateStore::open(bob_temp.0.join("state")).unwrap();
        let alice_bytes = alice_store.read().unwrap().unwrap().bytes;
        let bob_bytes = bob_store.read().unwrap().unwrap().bytes;
        assert!(!alice_bytes.windows(5).any(|window| window == b"alice"));
        let mut alice = open(&alice_bytes, RestorePolicy::Anchored(&alice_anchor)).unwrap();
        let mut bob = open(&bob_bytes, RestorePolicy::Anchored(&bob_anchor)).unwrap();
        assert_eq!(alice.card(), &alice_card);
        assert_eq!(bob.card(), &bob_card);
        let (session, contacts) = alice.session_and_contacts(1).unwrap();
        let delivery = session
            .encrypt_text_to_contacts(
                contacts,
                &[bob_card.endpoint_id],
                "restart secret",
                SignatureMode::Signed {
                    context: "archive-test",
                },
                1,
            )
            .unwrap();
        let (session, contacts) = bob.session_and_contacts(2).unwrap();
        let opened = session
            .open_text_from_contact(
                contacts,
                &alice_card.endpoint_id,
                "archive-test",
                &delivery,
                2,
            )
            .unwrap();
        assert_eq!(opened.text(), "restart secret");
        assert!(opened.provenance.is_some());
        assert!(!format!("{alice:?}").contains("alice"));
    }

    #[test]
    fn trusted_floors_reject_contact_rollback_while_basic_mode_makes_no_such_claim() {
        let temp = TempDirectory::new("rollback");
        let mut store = temp.store();
        let mut client = create("alice");
        let bob = EndpointSession::create_local(
            EndpointId::parse("bob").unwrap(),
            SessionPolicy::default(),
            0,
        )
        .unwrap()
        .card()
        .clone();
        let (_, book) = client.session_and_contacts(0).unwrap();
        book.observe(bob.clone()).unwrap();
        book.verify(&bob.endpoint_id, bob.fingerprint()).unwrap();
        let old_anchor = client.save(&mut store, None, 1).unwrap();
        let old = store.read().unwrap().unwrap();
        client
            .session_and_contacts(2)
            .unwrap()
            .1
            .revoke(&bob.endpoint_id)
            .unwrap();
        let new_anchor = client.save(&mut store, Some(old.digest), 2).unwrap();
        assert_eq!(new_anchor.minimum_sequence, old_anchor.minimum_sequence + 1);
        let latest = store.read().unwrap().unwrap();
        let mut restored = open(&latest.bytes, RestorePolicy::Anchored(&new_anchor)).unwrap();
        assert_eq!(
            restored
                .session_and_contacts(0)
                .unwrap()
                .1
                .status(&bob.endpoint_id)
                .unwrap(),
            ContactStatus::Revoked
        );
        assert!(open(&old.bytes, RestorePolicy::Anchored(&new_anchor)).is_err());
        let mut basic = open(&old.bytes, RestorePolicy::PasswordOnly).unwrap();
        assert_eq!(
            basic
                .session_and_contacts(0)
                .unwrap()
                .1
                .status(&bob.endpoint_id)
                .unwrap(),
            ContactStatus::Verified
        );
        assert!(client.save(&mut store, Some(old.digest), 3).is_err());
        let next = client.save(&mut store, Some(latest.digest), 3).unwrap();
        assert_eq!(next.minimum_sequence, new_anchor.minimum_sequence + 1);
    }

    #[test]
    fn credential_change_is_durable_and_preserves_the_endpoint() {
        let temp = TempDirectory::new("credential");
        let mut store = temp.store();
        let mut client = create("alice");
        let card = client.card().clone();
        client.save(&mut store, None, 1).unwrap();
        let old = store.read().unwrap().unwrap();
        client
            .change_passphrase(
                Zeroizing::new(b"new strong archive unlock secret".to_vec()),
                VaultKdf::default(),
                KdfBudget::default(),
                2,
            )
            .unwrap();
        let anchor = client.save(&mut store, Some(old.digest), 2).unwrap();
        let bytes = store.read().unwrap().unwrap().bytes;
        assert!(open(&bytes, RestorePolicy::Anchored(&anchor)).is_err());
        let restored = LocalClient::open(
            &bytes,
            Zeroizing::new(b"new strong archive unlock secret".to_vec()),
            RestorePolicy::Anchored(&anchor),
            KdfBudget::default(),
            SessionPolicy::default(),
            0,
        )
        .unwrap();
        assert_eq!(restored.card(), &card);
        assert!(open(&old.bytes, RestorePolicy::PasswordOnly).is_ok());
    }

    #[test]
    fn wrong_password_tampering_and_wrong_pins_fail_before_unlock() {
        let temp = TempDirectory::new("tamper");
        let mut store = temp.store();
        let mut client = create("alice");
        let anchor = client.save(&mut store, None, 1).unwrap();
        let bytes = store.read().unwrap().unwrap().bytes;
        let mut wrong_pin = anchor.clone();
        wrong_pin.endpoint_fingerprint[0] ^= 1;
        assert!(matches!(
            open(&bytes, RestorePolicy::Anchored(&wrong_pin)),
            Err(ArchiveError::PinMismatch)
        ));
        let mut tampered = bytes.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(open(&tampered, RestorePolicy::Anchored(&anchor)).is_err());
        assert!(LocalClient::open(
            &bytes,
            Zeroizing::new(b"incorrect archive password".to_vec()),
            RestorePolicy::Anchored(&anchor),
            KdfBudget::default(),
            SessionPolicy::default(),
            0
        )
        .is_err());
        client.lock();
        assert!(matches!(
            client.save(&mut store, Some([0; 32]), 2),
            Err(ArchiveError::Locked)
        ));
    }

    #[test]
    fn combined_timeout_and_clock_regression_lock_root_and_endpoint_keys() {
        let mut client = create("alice");
        assert!(client.tick(5 * 60 * 1000 - 1).unwrap());
        assert!(!client.tick(5 * 60 * 1000).unwrap());
        assert!(matches!(
            client.session_and_contacts(5 * 60 * 1000),
            Err(ArchiveError::Locked)
        ));
        let mut client = create("alice");
        client.unlocked.as_mut().unwrap().session.last_activity_ms = 10;
        assert!(client.tick(9).is_err());
        assert!(client.unlocked.is_none());
    }

    #[test]
    fn authenticated_mixed_component_sequences_are_rejected() {
        let temp = TempDirectory::new("mixed");
        let mut store = temp.store();
        let mut client = create("alice");
        client.save(&mut store, None, 1).unwrap();
        let old = store.read().unwrap().unwrap();
        let anchor = client.save(&mut store, Some(old.digest), 2).unwrap();
        let latest = store.read().unwrap().unwrap();
        let (snapshot, latest_encrypted) = split_archive(&latest.bytes).unwrap();
        let (_, old_encrypted) = split_archive(&old.bytes).unwrap();
        let vault = &client.unlocked.as_ref().unwrap().vault;
        let old_payload = vault
            .open_state(&root(), 1, CONTEXT, old_encrypted)
            .unwrap();
        let old_keys = decode_payload(&old_payload).unwrap().keys.encode();
        let mut payload = vault
            .open_state(&root(), 2, CONTEXT, latest_encrypted)
            .unwrap();
        for end in 0..payload.len() {
            assert!(decode_payload(&payload[..end]).is_err());
        }
        let card_len = usize::from(u16::from_be_bytes([payload[14], payload[15]]));
        payload[16 + card_len..16 + card_len + 182].copy_from_slice(&old_keys);
        let mixed = vault.seal_state(&root(), 2, CONTEXT, &payload).unwrap();
        let mut archive = ARCHIVE_PREFIX.to_vec();
        archive.extend_from_slice(&(snapshot.len() as u32).to_be_bytes());
        archive.extend_from_slice(&(mixed.len() as u32).to_be_bytes());
        archive.extend_from_slice(snapshot);
        archive.extend_from_slice(&mixed);
        assert!(matches!(
            open(&archive, RestorePolicy::Anchored(&anchor)),
            Err(ArchiveError::Malformed)
        ));
    }

    #[test]
    fn versioned_parsers_reject_truncation_lengths_versions_and_invalid_floors() {
        let anchor = ArchiveAnchor {
            vault_id: [1; 16],
            minimum_revision: 2,
            minimum_sequence: 3,
            endpoint_fingerprint: [4; 32],
        };
        let bytes = anchor.encode().unwrap();
        assert_eq!(ArchiveAnchor::decode(&bytes).unwrap(), anchor);
        for end in 0..bytes.len() {
            assert!(ArchiveAnchor::decode(&bytes[..end]).is_err());
        }
        let mut invalid = bytes.clone();
        invalid[5] = 2;
        assert!(ArchiveAnchor::decode(&invalid).is_err());
        invalid = bytes.clone();
        invalid[30..38].fill(0);
        assert!(ArchiveAnchor::decode(&invalid).is_err());
        let mut framing = ARCHIVE_PREFIX.to_vec();
        framing.extend_from_slice(&90_u32.to_be_bytes());
        framing.extend_from_slice(&54_u32.to_be_bytes());
        framing.resize(14 + 90 + 54, 0);
        assert!(split_archive(&framing).is_ok());
        for end in 0..framing.len() {
            assert!(split_archive(&framing[..end]).is_err());
        }
        let mut trailing = framing.clone();
        trailing.push(0);
        assert!(split_archive(&trailing).is_err());
        framing[6..10].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            split_archive(&framing),
            Err(ArchiveError::LimitExceeded)
        ));
        assert!(decode_payload(b"E2AP\0\x01\0\0").is_err());
    }
}
