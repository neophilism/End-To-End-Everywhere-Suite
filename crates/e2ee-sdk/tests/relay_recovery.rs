#![cfg(unix)]

//! End-to-end *local process* contract test: untrusted relay transport +
//! anchored recipient transactions. No durable relay or real service is used.

use e2ee_sdk::{
    AnchorError, AnchorRepository, ArchiveAnchor, EndpointId, PrivateStateStore, SdkError,
    SoftwareClient, SoftwareOptions, Zeroizing,
};
use e2ee_transport::{
    relay::{InMemoryRelay, MailboxId, RelayLimits, UploadToken},
    Delivery,
};
use std::{
    cell::RefCell,
    fs,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    rc::Rc,
    time::{SystemTime, UNIX_EPOCH},
};

struct Sandbox(PathBuf);

impl Sandbox {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir()
            .join(format!("e2ee-relay-sdk-{}-{nonce}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Failure {
    None,
    BeforeAdvance,
    AfterAdvance,
}

struct AnchorState {
    floor: Option<ArchiveAnchor>,
    failure: Failure,
    archive_path: PathBuf,
    saved_bytes: Vec<u8>,
}

// Only a fault-injection test double. An in-memory floor provides NO
// independent integrity or rollback protection in a real client.
#[derive(Clone)]
struct Anchors(Rc<RefCell<AnchorState>>);

impl Anchors {
    fn new(path: &std::path::Path) -> Self {
        Self(Rc::new(RefCell::new(AnchorState {
            floor: None,
            failure: Failure::None,
            archive_path: path.join("state.e2es"),
            saved_bytes: Vec::new(),
        })))
    }

    fn fail(&self, failure: Failure) {
        self.0.borrow_mut().failure = failure;
    }

    fn current_floor(&self) -> Option<ArchiveAnchor> {
        self.0.borrow().floor.clone()
    }
}

impl AnchorRepository for Anchors {
    fn current(&mut self) -> Result<Option<ArchiveAnchor>, AnchorError> {
        Ok(self.current_floor())
    }

    fn advance(
        &mut self,
        expected: Option<&ArchiveAnchor>,
        next: &ArchiveAnchor,
    ) -> Result<(), AnchorError> {
        let mut state = self.0.borrow_mut();
        if state.floor.as_ref() != expected {
            return Err(AnchorError::Conflict);
        }
        if let Some(previous) = expected {
            assert_eq!(previous.vault_id, next.vault_id);
            assert_eq!(previous.endpoint_fingerprint, next.endpoint_fingerprint);
            assert!(next.minimum_revision >= previous.minimum_revision);
            assert!(next.minimum_sequence > previous.minimum_sequence);
        }
        let saved = fs::read(&state.archive_path).unwrap();
        assert_ne!(saved, state.saved_bytes);
        if state.failure == Failure::BeforeAdvance {
            return Err(AnchorError::Unavailable);
        }
        state.floor = Some(next.clone());
        state.saved_bytes = saved;
        if state.failure == Failure::AfterAdvance {
            return Err(AnchorError::Unavailable);
        }
        Ok(())
    }
}

fn id(value: &str) -> EndpointId {
    EndpointId::parse(value).unwrap()
}

fn password() -> Zeroizing<Vec<u8>> {
    Zeroizing::new(b"separate test-only passphrase".to_vec())
}

fn create(path: &std::path::Path, name: &str, anchors: &Anchors) -> SoftwareClient<Anchors> {
    SoftwareClient::create(
        PrivateStateStore::create(path).unwrap(),
        anchors.clone(),
        id(name),
        password(),
        SoftwareOptions::default(),
        0,
    )
    .unwrap()
}

fn open(path: &std::path::Path, anchors: &Anchors) -> SoftwareClient<Anchors> {
    SoftwareClient::open(
        PrivateStateStore::open(path).unwrap(),
        anchors.clone(),
        password(),
        SoftwareOptions::default(),
        0,
    )
    .unwrap()
}

fn verify_each_other(a: &mut SoftwareClient<Anchors>, b: &mut SoftwareClient<Anchors>) {
    let ac = a.card().clone();
    let bc = b.card().clone();
    a.observe_contact(bc.clone(), 1).unwrap();
    a.verify_contact(&bc.endpoint_id, bc.fingerprint(), 2)
        .unwrap();
    b.observe_contact(ac.clone(), 1).unwrap();
    b.verify_contact(&ac.endpoint_id, ac.fingerprint(), 2)
        .unwrap();
}

#[test]
fn relay_preserves_authenticated_capsule_until_endpoint_commits_and_acknowledges() {
    let root = Sandbox::new();
    let alice_path = root.0.join("alice");
    let bob_path = root.0.join("bob");
    let aa = Anchors::new(&alice_path);
    let ba = Anchors::new(&bob_path);
    let mut alice = create(&alice_path, "alice", &aa);
    let mut bob = create(&bob_path, "bob", &ba);
    verify_each_other(&mut alice, &mut bob);

    let mailbox = MailboxId::new([1; 32]).unwrap();
    let mut relay = InMemoryRelay::new(RelayLimits::default(), Default::default()).unwrap();
    let signed = alice
        .seal_text(&[id("bob")], "relay-message", "encrypted through mailbox", 3)
        .unwrap();
    let wire = signed.encode(Default::default()).unwrap();
    let sequence = relay
        .enqueue(mailbox, UploadToken::new([1; 16]).unwrap(), &wire, 100, 10)
        .unwrap();
    assert_eq!(
        relay.enqueue(mailbox, UploadToken::new([1; 16]).unwrap(), &wire, 100, 11),
        Ok(sequence)
    );
    let page = relay.page(mailbox, None, 8, 12).unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].bytes, wire);
    let decoded = Delivery::decode(&page[0].bytes, Default::default()).unwrap();

    let before_floor = ba.current_floor();
    assert!(bob
        .receive_text(&id("alice"), "incorrect-context", &decoded, 3)
        .is_err());
    assert_eq!(ba.current_floor(), before_floor);
    assert_eq!(relay.page(mailbox, None, 8, 13).unwrap().len(), 1);
    assert_eq!(
        bob.receive_text(&id("alice"), "relay-message", &decoded, 4)
            .unwrap()
            .text(),
        "encrypted through mailbox"
    );
    assert_ne!(ba.current_floor(), before_floor);
    // Reading and authenticating are not relay acknowledgements.
    assert_eq!(relay.page(mailbox, None, 8, 14).unwrap().len(), 1);
    assert!(relay.acknowledge(mailbox, sequence, 15).unwrap());
    assert!(relay.page(mailbox, None, 8, 16).unwrap().is_empty());

    drop(bob);
    let mut reloaded = open(&bob_path, &ba);
    assert!(reloaded
        .receive_text(&id("alice"), "relay-message", &decoded, 1)
        .unwrap_err()
        .to_string()
        .contains("already received"));
}

#[test]
fn receive_anchor_failure_keeps_relay_delivery_for_recovery_without_plaintext_release() {
    for failure in [Failure::BeforeAdvance, Failure::AfterAdvance] {
        let root = Sandbox::new();
        let alice_path = root.0.join("alice");
        let bob_path = root.0.join("bob");
        let aa = Anchors::new(&alice_path);
        let ba = Anchors::new(&bob_path);
        let mut alice = create(&alice_path, "alice", &aa);
        let mut bob = create(&bob_path, "bob", &ba);
        verify_each_other(&mut alice, &mut bob);

        let mailbox = MailboxId::new([7; 32]).unwrap();
        let upload_token = UploadToken::new([9; 16]).unwrap();
        let mut relay = InMemoryRelay::new(RelayLimits::default(), Default::default()).unwrap();
        let original = alice
            .seal_text(&[id("bob")], "relay-recovery", "secret must not escape", 3)
            .unwrap();
        let wire = original.encode(Default::default()).unwrap();
        let sequence = relay.enqueue(mailbox, upload_token, &wire, 500, 10).unwrap();
        let delivery = Delivery::decode(
            &relay.page(mailbox, None, 1, 11).unwrap()[0].bytes,
            Default::default(),
        )
        .unwrap();

        ba.fail(failure);
        assert!(matches!(
            bob.receive_text(&id("alice"), "relay-recovery", &delivery, 3),
            Err(SdkError::Anchor(AnchorError::Unavailable))
        ));
        assert!(bob.needs_reload());
        // A failed or uncertain local transaction MUST NOT delete the relay copy.
        assert_eq!(relay.page(mailbox, None, 1, 12).unwrap().len(), 1);

        drop(bob);
        ba.fail(Failure::None);
        let mut bob = open(&bob_path, &ba);
        assert!(bob
            .receive_text(&id("alice"), "relay-recovery", &delivery, 1)
            .unwrap_err()
            .to_string()
            .contains("already received"));
        assert!(relay.acknowledge(mailbox, sequence, 13).unwrap());
        assert!(relay.page(mailbox, None, 1, 14).unwrap().is_empty());
    }
}
