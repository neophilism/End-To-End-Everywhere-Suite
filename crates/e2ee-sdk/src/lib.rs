#![forbid(unsafe_code)]
#![doc = include_str!("../../../docs/application-sdk.md")]

//! Pre-alpha Rust application boundary. This crate adds no cryptographic profile.
//! The host supplies an independently trusted, durable monotonic anchor store,
//! a private local archive store, monotonic time, and safe plaintext handling.

use e2ee_client::{
    archive::{ArchiveError, LocalClient, RestorePolicy},
    contacts::ContactError,
    ClientError, SignatureMode,
};
use e2ee_core::ProfileId;
use e2ee_keystore::SOFTWARE_VAULT_PROFILE;
use std::fmt;

pub use e2ee_client::{
    archive::ArchiveAnchor, contacts::ContactStatus, files::OpenedFile, EndpointCard, OpenedText,
    SessionPolicy,
};
pub use e2ee_core::EndpointId;
pub use e2ee_file::FileOptions;
pub use e2ee_keystore::software::{KdfBudget, VaultKdf};
pub use e2ee_storage::{PrivateStateStore, StateDigest, StorageError};
pub use e2ee_transport::Delivery;
pub use zeroize::Zeroizing;

/// Identifies this API preview; it does not promise a stable ABI or wire protocol.
pub const SDK_API_PREVIEW_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorError {
    Unavailable,
    Conflict,
}

impl fmt::Display for AnchorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "trusted anchor storage is unavailable; reload before retrying",
            Self::Conflict => "trusted anchor changed; reload before retrying",
        })
    }
}
impl std::error::Error for AnchorError {}

/// One independently protected anchor slot for this installation's archive.
///
/// The host must implement integrity, durable atomic compare-and-swap and
/// monotonicity. A file beside the replayable archive, process memory, or a
/// server-controlled account value alone does not meet this contract. Success
/// means the next floor survives restart. An uncertain outcome MUST be an error.
/// Never use `advance` to delete an anchor or lower its revision/sequence.
pub trait AnchorRepository {
    fn current(&mut self) -> Result<Option<ArchiveAnchor>, AnchorError>;
    fn advance(
        &mut self,
        expected: Option<&ArchiveAnchor>,
        next: &ArchiveAnchor,
    ) -> Result<(), AnchorError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SoftwareOptions {
    pub kdf: VaultKdf,
    pub budget: KdfBudget,
    pub session: SessionPolicy,
}

#[derive(Debug)]
pub enum SdkError {
    MissingArchive,
    MissingAnchor,
    ExistingAnchor,
    ReloadRequired,
    Anchor(AnchorError),
    Archive(ArchiveError),
    Storage(StorageError),
    Contact(ContactError),
    Client(ClientError),
}

impl fmt::Display for SdkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingArchive => f.write_str("local archive does not exist"),
            Self::MissingAnchor => {
                f.write_str("an independently trusted archive anchor is required")
            }
            Self::ExistingAnchor => f.write_str("trusted anchor slot is already occupied"),
            Self::ReloadRequired => {
                f.write_str("transaction outcome requires a fresh anchored reload")
            }
            Self::Anchor(error) => error.fmt(f),
            Self::Archive(error) => error.fmt(f),
            Self::Storage(error) => error.fmt(f),
            Self::Contact(error) => error.fmt(f),
            Self::Client(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for SdkError {}

macro_rules! from_error {
    ($type:ty, $variant:ident) => {
        impl From<$type> for SdkError {
            fn from(error: $type) -> Self {
                Self::$variant(error)
            }
        }
    };
}
from_error!(AnchorError, Anchor);
from_error!(ArchiveError, Archive);
from_error!(StorageError, Storage);
from_error!(ContactError, Contact);
from_error!(ClientError, Client);

/// Owns the exclusive archive writer guard and the unlocked endpoint together.
/// No mutable contact book or key handles escape this application boundary.
/// Hosts call `tick` and `lock` on idle, suspend/logout and screen lock.
pub struct SoftwareClient<A: AnchorRepository> {
    client: LocalClient,
    store: PrivateStateStore,
    digest: StateDigest,
    anchor: ArchiveAnchor,
    anchors: A,
    needs_reload: bool,
}

/// Complete ciphertext snapshot. The enclosed floor is informational; recovery
/// MUST use the independent repository, never adopt this bundled value as trust.
pub struct EncryptedBackup {
    bytes: Vec<u8>,
    anchor: ArchiveAnchor,
}
impl EncryptedBackup {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn checkpoint_anchor(&self) -> &ArchiveAnchor {
        &self.anchor
    }
}
impl fmt::Debug for EncryptedBackup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedBackup")
            .field("byte_count", &self.bytes.len())
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

impl<A: AnchorRepository> fmt::Debug for SoftwareClient<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SoftwareClient")
            .field("needs_reload", &self.needs_reload)
            .field("state", &"[REDACTED]")
            .finish()
    }
}

impl<A: AnchorRepository> SoftwareClient<A> {
    /// Explicit software fallback. Creates no hardware-isolation claim.
    /// The caller creates a private empty store; success commits both archive
    /// and independent anchor. Failure may leave a committed archive: inspect
    /// and recover it rather than deleting or automatically recreating it.
    pub fn create(
        store: PrivateStateStore,
        mut anchors: A,
        endpoint: EndpointId,
        passphrase: Zeroizing<Vec<u8>>,
        options: SoftwareOptions,
        now_ms: u64,
    ) -> Result<Self, SdkError> {
        if anchors.current()?.is_some() {
            return Err(SdkError::ExistingAnchor);
        }
        let client = LocalClient::create(
            endpoint,
            &ProfileId::parse(SOFTWARE_VAULT_PROFILE).expect("fixed software profile is valid"),
            passphrase,
            options.kdf,
            options.budget,
            options.session,
            now_ms,
        )?;
        Self::commit_installation(store, anchors, client, None, now_ms)
    }

    /// Recover the same local endpoint into an empty store. This is not new
    /// device enrollment and does not revoke retained copies of endpoint keys.
    /// Authentication against the independent floor precedes every write.
    pub fn restore_backup(
        store: PrivateStateStore,
        mut anchors: A,
        ciphertext: &[u8],
        passphrase: Zeroizing<Vec<u8>>,
        options: SoftwareOptions,
        now_ms: u64,
    ) -> Result<Self, SdkError> {
        let previous = anchors.current()?.ok_or(SdkError::MissingAnchor)?;
        if store.read()?.is_some() {
            return Err(StorageError::Conflict.into());
        }
        let client = LocalClient::open(
            ciphertext,
            passphrase,
            RestorePolicy::Anchored(&previous),
            options.budget,
            options.session,
            now_ms,
        )?;
        Self::commit_installation(store, anchors, client, Some(previous), now_ms)
    }

    fn commit_installation(
        mut store: PrivateStateStore,
        mut anchors: A,
        mut client: LocalClient,
        previous: Option<ArchiveAnchor>,
        now_ms: u64,
    ) -> Result<Self, SdkError> {
        let anchor = client.save(&mut store, None, now_ms)?;
        let digest = store.read()?.ok_or(SdkError::MissingArchive)?.digest;
        if let Err(error) = anchors.advance(previous.as_ref(), &anchor) {
            client.lock();
            return Err(error.into());
        }
        Ok(Self {
            client,
            store,
            digest,
            anchor,
            anchors,
            needs_reload: false,
        })
    }

    /// Restores only against the host's independently retained floor. Recovery
    /// without that floor remains an explicit lower-level archival operation.
    pub fn open(
        store: PrivateStateStore,
        mut anchors: A,
        passphrase: Zeroizing<Vec<u8>>,
        options: SoftwareOptions,
        now_ms: u64,
    ) -> Result<Self, SdkError> {
        let anchor = anchors.current()?.ok_or(SdkError::MissingAnchor)?;
        let saved = store.read()?.ok_or(SdkError::MissingArchive)?;
        let client = LocalClient::open(
            &saved.bytes,
            passphrase,
            RestorePolicy::Anchored(&anchor),
            options.budget,
            options.session,
            now_ms,
        )?;
        Ok(Self {
            client,
            store,
            digest: saved.digest,
            anchor,
            anchors,
            needs_reload: false,
        })
    }

    pub fn card(&self) -> &EndpointCard {
        self.client.card()
    }
    pub fn trusted_anchor(&self) -> &ArchiveAnchor {
        &self.anchor
    }
    pub fn needs_reload(&self) -> bool {
        self.needs_reload
    }

    /// Advance the archive and independent floor, then export that exact
    /// encrypted checkpoint. A failed/uncertain export never lowers the floor.
    pub fn checkpoint_backup(&mut self, now_ms: u64) -> Result<EncryptedBackup, SdkError> {
        self.active()?;
        self.save_changes(now_ms)?;
        let result = (|| {
            let saved = self.store.read()?.ok_or(SdkError::MissingArchive)?;
            if saved.digest != self.digest {
                return Err(StorageError::Conflict.into());
            }
            Ok(EncryptedBackup {
                bytes: saved.bytes,
                anchor: self.anchor.clone(),
            })
        })();
        result.map_err(|error| self.fail(error))
    }
    pub fn lock(&mut self) {
        self.client.lock();
    }
    pub fn tick(&mut self, now_ms: u64) -> Result<bool, SdkError> {
        self.active()?;
        Ok(self.client.tick(now_ms)?)
    }

    pub fn contacts(
        &mut self,
        now_ms: u64,
    ) -> Result<Vec<(EndpointCard, ContactStatus)>, SdkError> {
        self.active()?;
        let (_, contacts) = self.client.session_and_contacts(now_ms)?;
        Ok(contacts
            .contacts()
            .map(|(card, status)| (card.clone(), status))
            .collect())
    }

    /// Observation never grants trust. Success includes durable trust-state save.
    pub fn observe_contact(
        &mut self,
        card: EndpointCard,
        now_ms: u64,
    ) -> Result<ContactStatus, SdkError> {
        self.active()?;
        let (_, contacts) = self.client.session_and_contacts(now_ms)?;
        let status = contacts.observe(card)?;
        self.save_changes(now_ms)?;
        Ok(status)
    }

    pub fn verify_contact(
        &mut self,
        id: &EndpointId,
        independently_observed: [u8; 32],
        now_ms: u64,
    ) -> Result<(), SdkError> {
        self.active()?;
        self.client
            .session_and_contacts(now_ms)?
            .1
            .verify(id, independently_observed)?;
        self.save_changes(now_ms)
    }

    pub fn revoke_contact(&mut self, id: &EndpointId, now_ms: u64) -> Result<(), SdkError> {
        self.active()?;
        self.client.session_and_contacts(now_ms)?.1.revoke(id)?;
        self.save_changes(now_ms)
    }

    pub fn reactivate_contact(
        &mut self,
        id: &EndpointId,
        independently_observed: [u8; 32],
        now_ms: u64,
    ) -> Result<(), SdkError> {
        self.active()?;
        self.client
            .session_and_contacts(now_ms)?
            .1
            .reactivate(id, independently_observed)?;
        self.save_changes(now_ms)
    }

    pub fn seal_text(
        &mut self,
        recipients: &[EndpointId],
        context: &str,
        text: &str,
        now_ms: u64,
    ) -> Result<Delivery, SdkError> {
        self.active()?;
        let (session, contacts) = self.client.session_and_contacts(now_ms)?;
        let recipients = contacts.resolve_recipients(recipients)?;
        Ok(session.encrypt_text(&recipients, text, SignatureMode::Signed { context }, now_ms)?)
    }

    pub fn seal_file(
        &mut self,
        recipients: &[EndpointId],
        context: &str,
        file: &FileOptions,
        bytes: &[u8],
        now_ms: u64,
    ) -> Result<Delivery, SdkError> {
        self.active()?;
        let (session, contacts) = self.client.session_and_contacts(now_ms)?;
        let recipients = contacts.resolve_recipients(recipients)?;
        Ok(session.encrypt_file(
            &recipients,
            file,
            bytes,
            SignatureMode::Signed { context },
            now_ms,
        )?)
    }

    /// Returns plaintext only after the archive AND trusted anchor are committed.
    /// Anchor-store failure locks the controller and drops the plaintext result.
    pub fn receive_text(
        &mut self,
        sender: &EndpointId,
        context: &str,
        delivery: &Delivery,
        now_ms: u64,
    ) -> Result<OpenedText, SdkError> {
        self.active()?;
        let result = self.client.receive_text_once(
            &mut self.store,
            self.digest,
            sender,
            context,
            delivery,
            now_ms,
        );
        let (opened, anchor) = self.receive_result(result)?;
        self.finish_commit(anchor)?;
        Ok(opened)
    }

    /// Embedded filename/media type are metadata; the SDK never writes,
    /// renders, executes, or chooses a plaintext destination for attachments.
    pub fn receive_file(
        &mut self,
        sender: &EndpointId,
        context: &str,
        delivery: &Delivery,
        now_ms: u64,
    ) -> Result<OpenedFile, SdkError> {
        self.active()?;
        let result = self.client.receive_file_once(
            &mut self.store,
            self.digest,
            sender,
            context,
            delivery,
            now_ms,
        );
        let (opened, anchor) = self.receive_result(result)?;
        self.finish_commit(anchor)?;
        Ok(opened)
    }

    pub fn change_passphrase(
        &mut self,
        passphrase: Zeroizing<Vec<u8>>,
        kdf: VaultKdf,
        budget: KdfBudget,
        now_ms: u64,
    ) -> Result<(), SdkError> {
        self.active()?;
        self.client
            .change_passphrase(passphrase, kdf, budget, now_ms)?;
        self.save_changes(now_ms)
    }

    fn active(&self) -> Result<(), SdkError> {
        if self.needs_reload {
            Err(SdkError::ReloadRequired)
        } else {
            Ok(())
        }
    }

    fn fail(&mut self, error: SdkError) -> SdkError {
        self.needs_reload = true;
        self.client.lock();
        error
    }

    fn receive_result<T>(&mut self, result: Result<T, ArchiveError>) -> Result<T, SdkError> {
        match result {
            Ok(value) => Ok(value),
            // Save failures and expired sessions lock the lower-level client.
            // A fresh anchored open is required before this controller can act.
            Err(error) if !self.client.is_unlocked() => Err(self.fail(error.into())),
            Err(error) => Err(error.into()),
        }
    }

    fn save_changes(&mut self, now_ms: u64) -> Result<(), SdkError> {
        match self.client.save(&mut self.store, Some(self.digest), now_ms) {
            Ok(anchor) => self.finish_commit(anchor),
            Err(error) => Err(self.fail(error.into())),
        }
    }

    fn finish_commit(&mut self, next: ArchiveAnchor) -> Result<(), SdkError> {
        let result = (|| {
            let saved = self.store.read()?.ok_or(SdkError::MissingArchive)?;
            self.anchors.advance(Some(&self.anchor), &next)?;
            self.digest = saved.digest;
            self.anchor = next;
            Ok(())
        })();
        result.map_err(|error| self.fail(error))
    }
}
