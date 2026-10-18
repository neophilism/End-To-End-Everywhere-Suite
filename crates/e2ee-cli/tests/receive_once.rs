#![cfg(unix)]
use e2ee_capsule::CapsuleLimits;
use e2ee_transport::{encode_armored, Delivery};
use std::{
    fs,
    io::Write,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
const PASSWORD: &[u8] = b"strong inbox test vault password\n";
static NEXT_SANDBOX: AtomicU64 = AtomicU64::new(0);

struct Sandbox(PathBuf);
impl Sandbox {
    fn new() -> Self {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let serial = NEXT_SANDBOX.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!(
            "e2ee-inbox-{}-{seed}-{serial}",
            std::process::id()
        ));
        fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
        Self(p)
    }
}
impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn invoke(state: &Path, anchor: Option<&str>, format: Option<&str>, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_e2ee"));
    command.arg("--state").arg(state).arg("--software-vault");
    if let Some(a) = anchor {
        command.args(["--anchor", a]);
    } else {
        command.arg("--password-only");
    }
    if let Some(format) = format {
        command.arg(format);
    }
    let mut child = command
        .arg("--password-stdin")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let _ = child.stdin.take().unwrap().write_all(PASSWORD);
    child.wait_with_output().unwrap()
}
fn ok(output: &Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
fn anchor(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr)
        .lines()
        .find_map(|s| s.strip_prefix("ANCHOR "))
        .unwrap()
        .to_owned()
}
fn trust(one: &Path, other: &Path, id: &str) -> String {
    let card = invoke(other, None, None, &["card"]);
    ok(&card);
    let card = String::from_utf8(card.stdout).unwrap();
    ok(&invoke(one, None, None, &["import", card.trim()]));
    let identity = invoke(other, None, None, &["identity"]);
    ok(&identity);
    let identity = String::from_utf8(identity.stdout).unwrap();
    let fingerprint = identity
        .lines()
        .find_map(|l| l.strip_prefix("Fingerprint: "))
        .unwrap();
    let verified = invoke(one, None, None, &["verify", id, fingerprint]);
    ok(&verified);
    anchor(&verified)
}
#[test]
fn anchored_receive_persists_replay_state_across_processes_and_transport_encodings() {
    let root = Sandbox::new();
    let alice = root.0.join("alice");
    let bob = root.0.join("bob");
    ok(&invoke(&alice, None, None, &["init", "alice"]));
    ok(&invoke(&bob, None, None, &["init", "bob"]));
    trust(&alice, &bob, "bob");
    let before_anchor = trust(&bob, &alice, "alice");
    let plaintext = root.0.join("input.txt");
    let delivery = root.0.join("message.e2ed");
    let output = root.0.join("received.txt");
    fs::write(&plaintext, "An authenticated inbox message.").unwrap();
    ok(&invoke(
        &alice,
        None,
        None,
        &[
            "seal-text",
            "bob",
            "inbox-v1",
            plaintext.to_str().unwrap(),
            delivery.to_str().unwrap(),
        ],
    ));
    let old_archive = fs::read(bob.join("state.e2es")).unwrap();
    let args = [
        "receive-text",
        "alice",
        "inbox-v1",
        delivery.to_str().unwrap(),
        output.to_str().unwrap(),
    ];
    let no_anchor = invoke(&bob, None, None, &args);
    assert!(!no_anchor.status.success());
    assert!(!output.exists());
    let wrong = invoke(
        &bob,
        Some(&before_anchor),
        None,
        &[
            "receive-text",
            "alice",
            "wrong-context",
            delivery.to_str().unwrap(),
            output.to_str().unwrap(),
        ],
    );
    assert!(!wrong.status.success());
    assert!(!output.exists());
    assert_eq!(fs::read(bob.join("state.e2es")).unwrap(), old_archive);
    std::os::unix::fs::symlink(root.0.join("absent-target"), &output).unwrap();
    let dangling = invoke(&bob, Some(&before_anchor), None, &args);
    assert!(!dangling.status.success());
    assert_eq!(fs::read(bob.join("state.e2es")).unwrap(), old_archive);
    fs::remove_file(&output).unwrap();
    fs::write(&output, "keep-existing-file").unwrap();
    let existing = invoke(&bob, Some(&before_anchor), None, &args);
    assert!(!existing.status.success());
    assert_eq!(fs::read_to_string(&output).unwrap(), "keep-existing-file");
    assert_eq!(fs::read(bob.join("state.e2es")).unwrap(), old_archive);
    fs::remove_file(&output).unwrap();
    let received = invoke(&bob, Some(&before_anchor), None, &args);
    ok(&received);
    let latest_anchor = anchor(&received);
    assert_eq!(
        fs::read_to_string(&output).unwrap(),
        "An authenticated inbox message."
    );
    assert_eq!(
        fs::metadata(&output).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(!String::from_utf8_lossy(&received.stdout).contains("An authenticated inbox message."));
    let current_archive = fs::read(bob.join("state.e2es")).unwrap();
    assert_ne!(current_archive, old_archive);
    let duplicate = root.0.join("duplicate.txt");
    let duplicate_args = [
        "receive-text",
        "alice",
        "inbox-v1",
        delivery.to_str().unwrap(),
        duplicate.to_str().unwrap(),
    ];
    let rejected = invoke(&bob, Some(&latest_anchor), None, &duplicate_args);
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("already received"));
    assert!(!duplicate.exists());
    assert_eq!(fs::read(bob.join("state.e2es")).unwrap(), current_archive);
    let decoded =
        Delivery::decode(&fs::read(&delivery).unwrap(), CapsuleLimits::default()).unwrap();
    let armored = root.0.join("armored.txt");
    fs::write(
        &armored,
        encode_armored(&decoded, CapsuleLimits::default()).unwrap(),
    )
    .unwrap();
    let armored_replay = invoke(
        &bob,
        Some(&latest_anchor),
        Some("--armor"),
        &[
            "receive-text",
            "alice",
            "inbox-v1",
            armored.to_str().unwrap(),
            duplicate.to_str().unwrap(),
        ],
    );
    assert!(!armored_replay.status.success());
    assert!(!duplicate.exists());
    fs::write(bob.join("state.e2es"), &old_archive).unwrap();
    let rollback = invoke(&bob, Some(&latest_anchor), None, &duplicate_args);
    assert!(!rollback.status.success());
    assert!(!duplicate.exists());
    fs::write(bob.join("state.e2es"), &current_archive).unwrap();
    let archived = root.0.join("archival.txt");
    ok(&invoke(
        &bob,
        Some(&latest_anchor),
        None,
        &[
            "open-text",
            "alice",
            "inbox-v1",
            delivery.to_str().unwrap(),
            archived.to_str().unwrap(),
        ],
    ));
    assert_eq!(
        fs::read_to_string(archived).unwrap(),
        "An authenticated inbox message."
    );
}

#[test]
fn signed_attachment_receive_once_uses_explicit_private_output_and_shared_history() {
    let root = Sandbox::new();
    let alice = root.0.join("alice");
    let bob = root.0.join("bob");
    ok(&invoke(&alice, None, None, &["init", "alice"]));
    ok(&invoke(&bob, None, None, &["init", "bob"]));
    trust(&alice, &bob, "bob");
    let before_anchor = trust(&bob, &alice, "alice");
    let source = root.0.join("sender-chosen-name.bin");
    let delivery = root.0.join("attachment.e2ed");
    let output = root.0.join("recipient-chosen-name.bin");
    let payload = [0, 255, 1, 128, 0, 10, 13, 42];
    fs::write(&source, payload).unwrap();
    ok(&invoke(
        &alice,
        None,
        None,
        &[
            "seal-file",
            "bob",
            "attachment-v1",
            source.to_str().unwrap(),
            delivery.to_str().unwrap(),
        ],
    ));
    let before_archive = fs::read(bob.join("state.e2es")).unwrap();
    // Text decoding cannot consume a file receipt, even with a valid signature.
    let wrong_kind = invoke(
        &bob,
        Some(&before_anchor),
        None,
        &[
            "receive-text",
            "alice",
            "attachment-v1",
            delivery.to_str().unwrap(),
            output.to_str().unwrap(),
        ],
    );
    assert!(!wrong_kind.status.success());
    assert!(!output.exists());
    assert_eq!(fs::read(bob.join("state.e2es")).unwrap(), before_archive);
    let args = [
        "receive-file",
        "alice",
        "attachment-v1",
        delivery.to_str().unwrap(),
        output.to_str().unwrap(),
    ];
    let no_anchor = invoke(&bob, None, None, &args);
    assert!(!no_anchor.status.success());
    assert!(!output.exists());
    fs::write(&output, b"preserve existing").unwrap();
    let existing = invoke(&bob, Some(&before_anchor), None, &args);
    assert!(!existing.status.success());
    assert_eq!(fs::read(&output).unwrap(), b"preserve existing");
    assert_eq!(fs::read(bob.join("state.e2es")).unwrap(), before_archive);
    fs::remove_file(&output).unwrap();
    let received = invoke(&bob, Some(&before_anchor), None, &args);
    ok(&received);
    let latest_anchor = anchor(&received);
    assert_eq!(fs::read(&output).unwrap(), payload);
    assert_eq!(
        fs::metadata(&output).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(!received.stdout.windows(payload.len()).any(|w| w == payload));
    let duplicate = root.0.join("duplicate.bin");
    let rejected = invoke(
        &bob,
        Some(&latest_anchor),
        None,
        &[
            "receive-file",
            "alice",
            "attachment-v1",
            delivery.to_str().unwrap(),
            duplicate.to_str().unwrap(),
        ],
    );
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("already received"));
    assert!(!duplicate.exists());
    // Deliberate archival export remains available after a receipt is committed.
    ok(&invoke(
        &bob,
        Some(&latest_anchor),
        None,
        &[
            "open-file",
            "alice",
            "attachment-v1",
            delivery.to_str().unwrap(),
            duplicate.to_str().unwrap(),
        ],
    ));
    assert_eq!(fs::read(duplicate).unwrap(), payload);
}

#[test]
fn anchored_backup_restore_recovers_private_keys_without_overwrite_or_rollback_fallback() {
    let root = Sandbox::new();
    let original = root.0.join("original");
    let initialized = invoke(&original, None, None, &["init", "backup-owner"]);
    ok(&initialized);
    let initial_anchor = anchor(&initialized);
    let input = root.0.join("note.txt");
    let note = root.0.join("note.e2ed");
    fs::write(&input, "Recover this private note after local state loss.").unwrap();
    ok(&invoke(
        &original,
        Some(&initial_anchor),
        None,
        &[
            "seal-note",
            "backup-note",
            input.to_str().unwrap(),
            note.to_str().unwrap(),
        ],
    ));
    let backup = root.0.join("backup.e2ca");
    let before = fs::read(original.join("state.e2es")).unwrap();
    std::os::unix::fs::symlink(root.0.join("absent-backup-target"), &backup).unwrap();
    let dangling = invoke(
        &original,
        Some(&initial_anchor),
        None,
        &["backup", backup.to_str().unwrap()],
    );
    assert!(!dangling.status.success());
    assert_eq!(fs::read(original.join("state.e2es")).unwrap(), before);
    fs::remove_file(&backup).unwrap();
    fs::write(&backup, b"keep existing").unwrap();
    let exists = invoke(
        &original,
        Some(&initial_anchor),
        None,
        &["backup", backup.to_str().unwrap()],
    );
    assert!(!exists.status.success());
    assert_eq!(fs::read(&backup).unwrap(), b"keep existing");
    assert_eq!(fs::read(original.join("state.e2es")).unwrap(), before);
    fs::remove_file(&backup).unwrap();
    let exported = invoke(
        &original,
        Some(&initial_anchor),
        None,
        &["backup", backup.to_str().unwrap()],
    );
    ok(&exported);
    let checkpoint = anchor(&exported);
    let ciphertext = fs::read(&backup).unwrap();
    assert_eq!(ciphertext, fs::read(original.join("state.e2es")).unwrap());
    assert_eq!(
        fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_ne!(checkpoint, initial_anchor);
    let restored = root.0.join("restored");
    let fifo = root.0.join("not-a-backup.pipe");
    assert!(Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap()
        .success());
    let nonregular = invoke(
        &restored,
        Some(&checkpoint),
        None,
        &["restore", fifo.to_str().unwrap()],
    );
    assert!(!nonregular.status.success());
    assert!(!restored.exists());
    let link = root.0.join("backup-link.e2ca");
    std::os::unix::fs::symlink(&backup, &link).unwrap();
    let redirected = invoke(
        &restored,
        Some(&checkpoint),
        None,
        &["restore", link.to_str().unwrap()],
    );
    assert!(!redirected.status.success());
    assert!(!restored.exists());
    let no_floor = invoke(
        &restored,
        None,
        None,
        &["restore", backup.to_str().unwrap()],
    );
    assert!(!no_floor.status.success());
    assert!(!restored.exists());
    let broken = root.0.join("broken.e2ca");
    let mut changed = ciphertext.clone();
    *changed.last_mut().unwrap() ^= 1;
    fs::write(&broken, changed).unwrap();
    let invalid = invoke(
        &restored,
        Some(&checkpoint),
        None,
        &["restore", broken.to_str().unwrap()],
    );
    assert!(!invalid.status.success());
    assert!(!restored.exists());
    let recovered = invoke(
        &restored,
        Some(&checkpoint),
        None,
        &["restore", backup.to_str().unwrap()],
    );
    ok(&recovered);
    let latest = anchor(&recovered);
    assert_ne!(latest, checkpoint);
    assert!(String::from_utf8_lossy(&recovered.stdout).contains("does not enroll a new device"));
    let original_fingerprint = String::from_utf8_lossy(&initialized.stdout)
        .lines()
        .find(|l| l.starts_with("Fingerprint: "))
        .unwrap()
        .to_owned();
    assert!(String::from_utf8_lossy(&recovered.stdout).contains(&original_fingerprint));
    let opened = root.0.join("recovered-note.txt");
    ok(&invoke(
        &restored,
        Some(&latest),
        None,
        &[
            "open-note",
            "backup-note",
            note.to_str().unwrap(),
            opened.to_str().unwrap(),
        ],
    ));
    assert_eq!(
        fs::read_to_string(opened).unwrap(),
        "Recover this private note after local state loss."
    );
    let another = root.0.join("stale-restore");
    let stale = invoke(
        &another,
        Some(&latest),
        None,
        &["restore", backup.to_str().unwrap()],
    );
    assert!(!stale.status.success());
    assert!(!another.exists());
    let current = fs::read(restored.join("state.e2es")).unwrap();
    let overwrite = invoke(
        &restored,
        Some(&latest),
        None,
        &["restore", backup.to_str().unwrap()],
    );
    assert!(!overwrite.status.success());
    assert_eq!(fs::read(restored.join("state.e2es")).unwrap(), current);
    let unavailable = root.0.join("missing-parent").join("export.e2ca");
    let failed = invoke(
        &restored,
        Some(&latest),
        None,
        &["backup", unavailable.to_str().unwrap()],
    );
    assert!(!failed.status.success());
    assert!(!unavailable.exists());
    assert!(String::from_utf8_lossy(&failed.stderr).contains("Backup checkpoint committed"));
    let advanced = anchor(&failed);
    assert_ne!(advanced, latest);
    ok(&invoke(&restored, Some(&advanced), None, &["identity"]));
}
