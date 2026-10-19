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
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

static NEXT_SANDBOX: AtomicU64 = AtomicU64::new(0);

struct Sandbox(PathBuf);
impl Sandbox {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let unique = NEXT_SANDBOX.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("e2ee-sdk-{}-{nonce}-{unique}", std::process::id()));
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
    reads_before_failure: Option<usize>,
    advance_then_replace: bool,
    advance_then_fail_read: bool,
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
            reads_before_failure: None,
            advance_then_replace: false,
            advance_then_fail_read: false,
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
        let mut state = self.0.borrow_mut();
        if let Some(remaining) = &mut state.reads_before_failure {
            if *remaining == 0 {
                return Err(AnchorError::Unavailable);
            }
            *remaining -= 1;
        }
        Ok(state.value.clone())
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
        if state.advance_then_replace {
            state.advance_then_replace = false;
            let mut replacement = next.clone();
            replacement.minimum_sequence += 1;
            state.value = Some(replacement);
        }
        if state.advance_then_fail_read {
            state.advance_then_fail_read = false;
            state.reads_before_failure = Some(0);
        }
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

#[test]
fn checkpoint_restore_preserves_keys_receipts_and_trusted_floors_including_an_uncertain_restore() {
    let root = Sandbox::new();
    let ap = root.0.join("alice");
    let bp = root.0.join("bob");
    let aa = TestAnchors::new(&ap);
    let ba = TestAnchors::new(&bp);
    let mut alice = create(&ap, "alice", &aa);
    let mut bob = create(&bp, "bob", &ba);
    pair(&mut alice, &mut bob);
    let delivery = alice
        .seal_text(&[id("bob")], "backup-test", "received before recovery", 3)
        .unwrap();
    bob.receive_text(&id("alice"), "backup-test", &delivery, 3)
        .unwrap();
    let backup = bob.checkpoint_backup(4).unwrap();
    assert_eq!(Some(backup.checkpoint_anchor().clone()), ba.floor());
    assert_eq!(backup.bytes(), fs::read(bp.join("state.e2es")).unwrap());
    assert!(!format!("{backup:?}").contains("received before recovery"));
    drop(bob);

    let recovered_path = root.0.join("recovered-bob");
    ba.0.borrow_mut().archive = recovered_path.join("state.e2es");
    let previous_floor = ba.floor();
    ba.fail(Failure::BeforeWrite);
    let result = SoftwareClient::restore_backup(
        PrivateStateStore::create(&recovered_path).unwrap(),
        ba.clone(),
        backup.bytes(),
        password(),
        SoftwareOptions::default(),
        0,
    );
    assert!(matches!(
        result,
        Err(SdkError::Anchor(AnchorError::Unavailable))
    ));
    assert_eq!(ba.floor(), previous_floor);
    assert!(recovered_path.join("state.e2es").is_file());
    ba.fail(Failure::None);
    let mut recovered = open(&recovered_path, &ba).unwrap();
    assert!(recovered
        .receive_text(&id("alice"), "backup-test", &delivery, 1)
        .unwrap_err()
        .to_string()
        .contains("already received"));
    let latest = recovered.checkpoint_backup(2).unwrap();
    drop(recovered);

    let stale_path = root.0.join("stale-restore");
    let store = PrivateStateStore::create(&stale_path).unwrap();
    assert!(SoftwareClient::restore_backup(
        store,
        ba.clone(),
        backup.bytes(),
        password(),
        SoftwareOptions::default(),
        0
    )
    .is_err());
    assert!(PrivateStateStore::open(&stale_path)
        .unwrap()
        .read()
        .unwrap()
        .is_none());
    let final_path = root.0.join("final-recovery");
    ba.0.borrow_mut().archive = final_path.join("state.e2es");
    let mut final_client = SoftwareClient::restore_backup(
        PrivateStateStore::create(&final_path).unwrap(),
        ba.clone(),
        latest.bytes(),
        password(),
        SoftwareOptions::default(),
        0,
    )
    .unwrap();
    assert_eq!(final_client.card().endpoint_id, id("bob"));
    assert!(final_client
        .receive_text(&id("alice"), "backup-test", &delivery, 1)
        .unwrap_err()
        .to_string()
        .contains("already received"));
    assert_eq!(
        final_client.contacts(2).unwrap()[0].1,
        ContactStatus::Verified
    );
    let saved = fs::read(final_path.join("state.e2es")).unwrap();
    drop(final_client);
    assert!(matches!(
        SoftwareClient::restore_backup(
            PrivateStateStore::open(&final_path).unwrap(),
            ba,
            latest.bytes(),
            password(),
            SoftwareOptions::default(),
            0
        ),
        Err(SdkError::Storage(_))
    ));
    assert_eq!(fs::read(final_path.join("state.e2es")).unwrap(), saved);
}

#[test]
fn recovery_and_revocation_supersede_an_already_unlocked_controller() {
    let root = Sandbox::new();
    let ap = root.0.join("alice");
    let bp = root.0.join("bob");
    let aa = TestAnchors::new(&ap);
    let ba = TestAnchors::new(&bp);
    let mut alice = create(&ap, "alice", &aa);
    let mut bob = create(&bp, "bob", &ba);
    pair(&mut alice, &mut bob);
    let backup = alice.checkpoint_backup(3).unwrap();
    let before_archive = fs::read(ap.join("state.e2es")).unwrap();
    let recovered_path = root.0.join("recovered-alice");
    aa.0.borrow_mut().archive = recovered_path.join("state.e2es");
    let mut recovered = SoftwareClient::restore_backup(
        PrivateStateStore::create(&recovered_path).unwrap(),
        aa.clone(),
        backup.bytes(),
        password(),
        SoftwareOptions::default(),
        0,
    )
    .unwrap();
    recovered.revoke_contact(&id("bob"), 1).unwrap();
    let floor = aa.floor();
    assert!(matches!(
        alice.seal_file(
            &[id("bob")],
            "stale-controller",
            &FileOptions::new("private.bin", "application/octet-stream"),
            b"must never return a signed delivery under stale trust",
            4,
        ),
        Err(SdkError::Anchor(AnchorError::Conflict))
    ));
    assert!(alice.needs_reload());
    assert!(matches!(alice.contacts(5), Err(SdkError::ReloadRequired)));
    assert!(matches!(
        alice.seal_text(&[id("bob")], "stale-controller", "blocked", 6),
        Err(SdkError::ReloadRequired)
    ));
    assert_eq!(fs::read(ap.join("state.e2es")).unwrap(), before_archive);
    assert_eq!(aa.floor(), floor);
    assert_eq!(recovered.contacts(2).unwrap()[0].1, ContactStatus::Revoked);
}

#[test]
fn missing_changed_and_unavailable_floors_lock_without_archive_writes_or_delivery_release() {
    let root = Sandbox::new();
    let ap = root.0.join("alice");
    let bp = root.0.join("bob");
    let aa = TestAnchors::new(&ap);
    let ba = TestAnchors::new(&bp);
    let mut alice = create(&ap, "alice", &aa);
    let mut bob = create(&bp, "bob", &ba);
    pair(&mut alice, &mut bob);
    let floor = aa.floor().unwrap();
    let before_archive = fs::read(ap.join("state.e2es")).unwrap();
    drop(alice);
    let mut newer = floor.clone();
    newer.minimum_sequence += 1;
    for replacement in [None, Some(newer)] {
        let mut alice = open(&ap, &aa).unwrap();
        aa.0.borrow_mut().value = replacement;
        assert!(matches!(
            alice.contacts(1),
            Err(SdkError::Anchor(AnchorError::Conflict))
        ));
        assert!(alice.needs_reload());
        aa.0.borrow_mut().value = Some(floor.clone());
        assert!(matches!(alice.tick(2), Err(SdkError::ReloadRequired)));
        assert_eq!(fs::read(ap.join("state.e2es")).unwrap(), before_archive);
    }
    for attachment in [false, true] {
        for reads in [0, 1] {
            let mut alice = open(&ap, &aa).unwrap();
            aa.0.borrow_mut().reads_before_failure = Some(reads);
            let result = if attachment {
                alice.seal_file(
                    &[id("bob")],
                    "read-failure",
                    &FileOptions::new("private.bin", "application/octet-stream"),
                    b"not released",
                    1,
                )
            } else {
                alice.seal_text(&[id("bob")], "read-failure", "not released", 1)
            };
            assert!(matches!(
                result,
                Err(SdkError::Anchor(AnchorError::Unavailable))
            ));
            assert!(alice.needs_reload());
            aa.0.borrow_mut().reads_before_failure = None;
            assert!(matches!(alice.contacts(2), Err(SdkError::ReloadRequired)));
            assert_eq!(aa.floor(), Some(floor.clone()));
            assert_eq!(fs::read(ap.join("state.e2es")).unwrap(), before_archive);
        }
    }
}

struct ChangeDuringUnlock {
    inner: TestAnchors,
    reads: usize,
}
impl AnchorRepository for ChangeDuringUnlock {
    fn current(&mut self) -> Result<Option<ArchiveAnchor>, AnchorError> {
        self.reads += 1;
        if self.reads == 2 {
            let mut next = self.inner.floor().unwrap();
            next.minimum_sequence += 1;
            self.inner.0.borrow_mut().value = Some(next);
        }
        self.inner.current()
    }
    fn advance(
        &mut self,
        expected: Option<&ArchiveAnchor>,
        next: &ArchiveAnchor,
    ) -> Result<(), AnchorError> {
        self.inner.advance(expected, next)
    }
}

#[test]
fn unlock_rechecks_the_floor_after_authenticating_the_archive() {
    let root = Sandbox::new();
    let ap = root.0.join("alice");
    let aa = TestAnchors::new(&ap);
    drop(create(&ap, "alice", &aa));
    let before_archive = fs::read(ap.join("state.e2es")).unwrap();
    aa.0.borrow_mut().reads_before_failure = Some(1);
    assert!(matches!(
        open(&ap, &aa),
        Err(SdkError::Anchor(AnchorError::Unavailable))
    ));
    assert_eq!(fs::read(ap.join("state.e2es")).unwrap(), before_archive);
    aa.0.borrow_mut().reads_before_failure = None;
    assert!(open(&ap, &aa).is_ok());
    assert!(matches!(
        SoftwareClient::open(
            PrivateStateStore::open(&ap).unwrap(),
            ChangeDuringUnlock {
                inner: aa.clone(),
                reads: 0,
            },
            password(),
            SoftwareOptions::default(),
            0,
        ),
        Err(SdkError::Anchor(AnchorError::Conflict))
    ));
    assert_eq!(fs::read(ap.join("state.e2es")).unwrap(), before_archive);
}

#[test]
fn post_commit_floor_change_or_read_failure_prevents_reporting_success() {
    // The archive and first trusted advance may already have committed.
    // The caller must never treat the uncertain return as an unused receipt.
    for fail_read in [false, true] {
        let root = Sandbox::new();
        let ap = root.0.join("alice");
        let bp = root.0.join("bob");
        let aa = TestAnchors::new(&ap);
        let ba = TestAnchors::new(&bp);
        let mut alice = create(&ap, "alice", &aa);
        let mut bob = create(&bp, "bob", &ba);
        pair(&mut alice, &mut bob);
        let delivery = alice
            .seal_text(
                &[id("bob")],
                "post-commit",
                "never returned on uncertain floor",
                3,
            )
            .unwrap();
        {
            let mut state = ba.0.borrow_mut();
            state.advance_then_replace = !fail_read;
            state.advance_then_fail_read = fail_read;
        }
        let result = bob.receive_text(&id("alice"), "post-commit", &delivery, 3);
        if fail_read {
            assert!(matches!(
                result,
                Err(SdkError::Anchor(AnchorError::Unavailable))
            ));
        } else {
            assert!(matches!(
                result,
                Err(SdkError::Anchor(AnchorError::Conflict))
            ));
        }
        assert!(bob.needs_reload());
        assert!(matches!(bob.contacts(4), Err(SdkError::ReloadRequired)));
        assert!(fs::read(bp.join("state.e2es")).unwrap().len() > 100);
    }
}

#[test]
fn installation_commit_rechecks_authoritative_floor() {
    for fail_read in [false, true] {
        let root = Sandbox::new();
        let ap = root.0.join("alice");
        let anchors = TestAnchors::new(&ap);
        {
            let mut state = anchors.0.borrow_mut();
            state.advance_then_replace = !fail_read;
            state.advance_then_fail_read = fail_read;
        }
        let result = SoftwareClient::create(
            PrivateStateStore::create(&ap).unwrap(),
            anchors.clone(),
            id("alice"),
            password(),
            SoftwareOptions::default(),
            0,
        );
        if fail_read {
            assert!(matches!(
                result,
                Err(SdkError::Anchor(AnchorError::Unavailable))
            ));
        } else {
            assert!(matches!(
                result,
                Err(SdkError::Anchor(AnchorError::Conflict))
            ));
        }
        assert!(fs::read(ap.join("state.e2es")).unwrap().len() > 100);
    }
}
