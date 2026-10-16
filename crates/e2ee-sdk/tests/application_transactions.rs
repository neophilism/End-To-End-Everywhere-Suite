#![cfg(unix)]

use e2ee_sdk::{
    AnchorError, AnchorRepository, ArchiveAnchor, ContactStatus, EndpointId, FileOptions,
    PrivateStateStore, SdkError, SoftwareClient, SoftwareOptions, Zeroizing,
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
        let path = std::env::temp_dir().join(format!("e2ee-sdk-{}-{nonce}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Failure {
    None,
    BeforeWrite,
    AfterWrite,
}
struct AnchorState {
    value: Option<ArchiveAnchor>,
    failure: Failure,
    archive: PathBuf,
    last_archive: Vec<u8>,
}

// Test double only: process memory is NOT an independent durable anchor store.
#[derive(Clone)]
struct TestAnchors(Rc<RefCell<AnchorState>>);
impl TestAnchors {
    fn new(path: &std::path::Path) -> Self {
        Self(Rc::new(RefCell::new(AnchorState {
            value: None,
            failure: Failure::None,
            archive: path.join("state.e2es"),
            last_archive: Vec::new(),
        })))
    }
    fn floor(&self) -> Option<ArchiveAnchor> {
        self.0.borrow().value.clone()
    }
    fn fail(&self, failure: Failure) {
        self.0.borrow_mut().failure = failure;
    }
}
impl AnchorRepository for TestAnchors {
    fn current(&mut self) -> Result<Option<ArchiveAnchor>, AnchorError> {
        Ok(self.floor())
    }
    fn advance(
        &mut self,
        expected: Option<&ArchiveAnchor>,
        next: &ArchiveAnchor,
    ) -> Result<(), AnchorError> {
        let mut state = self.0.borrow_mut();
        if state.value.as_ref() != expected {
            return Err(AnchorError::Conflict);
        }
        if let Some(previous) = expected {
            assert_eq!(previous.vault_id, next.vault_id);
            assert_eq!(previous.endpoint_fingerprint, next.endpoint_fingerprint);
            assert!(next.minimum_revision >= previous.minimum_revision);
            assert!(next.minimum_sequence > previous.minimum_sequence);
        }
        // Every anchor update must occur AFTER a new encrypted archive is visible.
        let saved = fs::read(&state.archive).unwrap();
        assert!(!saved.is_empty());
        assert_ne!(saved, state.last_archive);
        if state.failure == Failure::BeforeWrite {
            return Err(AnchorError::Unavailable);
        }
        state.value = Some(next.clone());
        state.last_archive = saved;
        if state.failure == Failure::AfterWrite {
            return Err(AnchorError::Unavailable);
        }
        Ok(())
    }
}
fn password() -> Zeroizing<Vec<u8>> {
    Zeroizing::new(b"SDK application test passphrase".to_vec())
}
fn id(value: &str) -> EndpointId {
    EndpointId::parse(value).unwrap()
}
fn create(
    path: &std::path::Path,
    name: &str,
    anchors: &TestAnchors,
) -> SoftwareClient<TestAnchors> {
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
fn open(
    path: &std::path::Path,
    anchors: &TestAnchors,
) -> Result<SoftwareClient<TestAnchors>, SdkError> {
    SoftwareClient::open(
        PrivateStateStore::open(path).unwrap(),
        anchors.clone(),
        password(),
        SoftwareOptions::default(),
        0,
    )
}
fn pair(a: &mut SoftwareClient<TestAnchors>, b: &mut SoftwareClient<TestAnchors>) {
    let ac = a.card().clone();
    let bc = b.card().clone();
    assert_eq!(
        a.observe_contact(bc.clone(), 1).unwrap(),
        ContactStatus::Unverified
    );
    assert!(a
        .seal_text(
            std::slice::from_ref(&bc.endpoint_id),
            "sdk-test",
            "blocked",
            1
        )
        .is_err());
    a.verify_contact(&bc.endpoint_id, bc.fingerprint(), 2)
        .unwrap();
    b.observe_contact(ac.clone(), 1).unwrap();
    b.verify_contact(&ac.endpoint_id, ac.fingerprint(), 2)
        .unwrap();
}

#[test]
fn consumer_controller_commits_trust_receipts_and_anchors_and_blocks_archive_rollback() {
    let root = Sandbox::new();
    let ap = root.0.join("alice");
    let bp = root.0.join("bob");
    let aa = TestAnchors::new(&ap);
    let ba = TestAnchors::new(&bp);
    let mut alice = create(&ap, "alice", &aa);
    let mut bob = create(&bp, "bob", &ba);
    pair(&mut alice, &mut bob);
    let delivery = alice
        .seal_text(&[id("bob")], "sdk-test", "private application text", 3)
        .unwrap();
    let before_floor = ba.floor();
    let before_archive = fs::read(bp.join("state.e2es")).unwrap();
    assert!(bob
        .receive_text(&id("alice"), "wrong", &delivery, 3)
        .is_err());
    assert_eq!(ba.floor(), before_floor);
    assert_eq!(fs::read(bp.join("state.e2es")).unwrap(), before_archive);
    let opened = bob
        .receive_text(&id("alice"), "sdk-test", &delivery, 4)
        .unwrap();
    assert_eq!(opened.text(), "private application text");
    assert_eq!(Some(bob.trusted_anchor().clone()), ba.floor());
    assert_ne!(ba.floor(), before_floor);
    assert!(!format!("{opened:?}").contains("private application text"));
    assert!(!format!("{bob:?}").contains("alice"));
    let current_archive = fs::read(bp.join("state.e2es")).unwrap();
    drop(bob);
    fs::write(bp.join("state.e2es"), &before_archive).unwrap();
    assert!(open(&bp, &ba).is_err());
    fs::write(bp.join("state.e2es"), &current_archive).unwrap();
    let mut bob = open(&bp, &ba).unwrap();
    assert!(bob
        .receive_text(&id("alice"), "sdk-test", &delivery, 1)
        .unwrap_err()
        .to_string()
        .contains("already received"));
    let bytes = [0, 255, 13, 10, 1, 128];
    let file = alice
        .seal_file(
            &[id("bob")],
            "sdk-file",
            &FileOptions::new("metadata-only.bin", "application/octet-stream"),
            &bytes,
            5,
        )
        .unwrap();
    let opened = bob
        .receive_file(&id("alice"), "sdk-file", &file, 2)
        .unwrap();
    assert_eq!(opened.bytes(), bytes);
    assert_eq!(opened.filename(), "metadata-only.bin");
    assert!(bob
        .receive_file(&id("alice"), "sdk-file", &file, 3)
        .is_err());
    bob.revoke_contact(&id("alice"), 4).unwrap();
    drop(bob);
    let mut bob = open(&bp, &ba).unwrap();
    assert_eq!(bob.contacts(0).unwrap()[0].1, ContactStatus::Revoked);
    let fresh = alice
        .seal_text(&[id("bob")], "sdk-test", "after revocation", 6)
        .unwrap();
    assert!(bob
        .receive_text(&id("alice"), "sdk-test", &fresh, 1)
        .is_err());
    assert!(bob.tick(300_000).is_ok_and(|unlocked| !unlocked));
    assert!(bob
        .seal_text(&[id("alice")], "sdk-test", "locked", 300_001)
        .is_err());
}

#[test]
fn anchor_failures_before_and_after_write_release_no_plaintext_and_require_reload() {
    let root = Sandbox::new();
    let ap = root.0.join("alice");
    let bp = root.0.join("bob");
    let aa = TestAnchors::new(&ap);
    let ba = TestAnchors::new(&bp);
    let mut alice = create(&ap, "alice", &aa);
    let mut bob = create(&bp, "bob", &ba);
    pair(&mut alice, &mut bob);
    for (n, failure) in [Failure::BeforeWrite, Failure::AfterWrite]
        .into_iter()
        .enumerate()
    {
        let delivery = alice
            .seal_text(
                &[id("bob")],
                "sdk-test",
                "never returned on failed anchor write",
                3 + n as u64,
            )
            .unwrap();
        let before_floor = ba.floor();
        let before_archive = fs::read(bp.join("state.e2es")).unwrap();
        ba.fail(failure);
        assert!(matches!(
            bob.receive_text(&id("alice"), "sdk-test", &delivery, 3),
            Err(SdkError::Anchor(AnchorError::Unavailable))
        ));
        assert!(bob.needs_reload());
        assert!(matches!(bob.contacts(4), Err(SdkError::ReloadRequired)));
        assert!(matches!(
            bob.receive_text(&id("alice"), "sdk-test", &delivery, 4),
            Err(SdkError::ReloadRequired)
        ));
        assert_ne!(fs::read(bp.join("state.e2es")).unwrap(), before_archive);
        if failure == Failure::BeforeWrite {
            assert_eq!(ba.floor(), before_floor);
        } else {
            assert_ne!(ba.floor(), before_floor);
        }
        drop(bob);
        ba.fail(Failure::None);
        bob = open(&bp, &ba).unwrap();
        assert!(bob
            .receive_text(&id("alice"), "sdk-test", &delivery, 1)
            .unwrap_err()
            .to_string()
            .contains("already received"));
        assert!(!bob.needs_reload());
    }
}

#[test]
fn missing_anchor_has_no_password_only_fallback() {
    let root = Sandbox::new();
    let path = root.0.join("empty");
    let anchors = TestAnchors::new(&path);
    let store = PrivateStateStore::create(&path).unwrap();
    assert!(matches!(
        SoftwareClient::open(store, anchors, password(), SoftwareOptions::default(), 0),
        Err(SdkError::MissingAnchor)
    ));
}
