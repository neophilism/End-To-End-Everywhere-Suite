#![cfg(unix)]
use e2ee_capsule::CapsuleLimits;
use e2ee_transport::{encode_armored, Delivery};
use std::{
    fs,
    io::Write,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};
const PASSWORD: &[u8] = b"strong inbox test vault password\n";
struct Sandbox(PathBuf);
impl Sandbox {
    fn new() -> Self {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("e2ee-inbox-{}-{seed}", std::process::id()));
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
