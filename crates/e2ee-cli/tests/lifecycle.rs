#![cfg(unix)]

use std::{
    fs,
    io::Write,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

struct TempDirectory(PathBuf);
impl TempDirectory {
    fn new() -> Self {
        let name = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("e2ee-cli-{}-{name}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn invoke(directory: &Path, command: &[&str], credentials: &[u8], anchor: Option<&str>) -> Output {
    let mut process = Command::new(env!("CARGO_BIN_EXE_e2ee"));
    process
        .args(["--state"])
        .arg(directory)
        .arg("--software-vault");
    if let Some(anchor) = anchor {
        process.args(["--anchor", anchor]);
    } else {
        process.arg("--password-only");
    }
    process
        .arg("--password-stdin")
        .args(command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = process.spawn().unwrap();
    child.stdin.take().unwrap().write_all(credentials).unwrap();
    child.wait_with_output().unwrap()
}

fn token(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr)
        .lines()
        .find_map(|line| line.strip_prefix("ANCHOR "))
        .unwrap()
        .to_owned()
}

#[test]
fn actual_binary_preserves_contact_trust_and_changes_password_across_invocations() {
    let temp = TempDirectory::new();
    let alice = temp.0.join("alice-state");
    let bob = temp.0.join("bob-state");
    let password = b"a long test vault passphrase\n";
    let initialized = invoke(&alice, &["init", "alice"], password, None);
    assert!(
        initialized.status.success(),
        "{}",
        String::from_utf8_lossy(&initialized.stderr)
    );
    assert!(!initialized
        .stdout
        .windows(password.len() - 1)
        .any(|w| w == &password[..password.len() - 1]));
    assert!(invoke(&bob, &["init", "bob"], password, None)
        .status
        .success());
    let bob_identity = invoke(&bob, &["identity"], password, None);
    let identity = String::from_utf8(bob_identity.stdout).unwrap();
    let fingerprint = identity
        .lines()
        .find_map(|line| line.strip_prefix("Fingerprint: "))
        .unwrap();
    let bob_card = invoke(&bob, &["card"], password, None);
    let uri = String::from_utf8(bob_card.stdout).unwrap();
    let imported = invoke(&alice, &["import", uri.trim()], password, None);
    assert!(imported.status.success());
    let contacts = invoke(&alice, &["contacts"], password, None);
    assert!(String::from_utf8_lossy(&contacts.stdout).contains("bob\tunverified\t"));
    assert!(
        !invoke(&alice, &["verify", "bob", &"00".repeat(32)], password, None)
            .status
            .success()
    );
    let verified = invoke(
        &alice,
        &["verify", "bob", fingerprint],
        password,
        Some(&token(&imported)),
    );
    assert!(verified.status.success());
    let saved_anchor = token(&verified);
    let contacts = invoke(&alice, &["contacts"], password, Some(&saved_anchor));
    assert!(String::from_utf8_lossy(&contacts.stdout).contains("bob\tverified\t"));
    assert!(invoke(&alice, &["revoke", "bob"], password, None)
        .status
        .success());
    assert!(invoke(&alice, &["import", uri.trim()], password, None)
        .status
        .success());
    assert!(
        !invoke(&alice, &["verify", "bob", fingerprint], password, None)
            .status
            .success()
    );
    assert!(
        invoke(&alice, &["reactivate", "bob", fingerprint], password, None)
            .status
            .success()
    );
    let old_archive = fs::read(alice.join("state.e2es")).unwrap();
    let changed = invoke(
        &alice,
        &["passwd"],
        b"a long test vault passphrase\na new stronger test passphrase\n",
        None,
    );
    assert!(changed.status.success());
    assert!(!invoke(&alice, &["identity"], password, None)
        .status
        .success());
    let new_password = b"a new stronger test passphrase\n";
    assert!(
        invoke(&alice, &["identity"], new_password, Some(&token(&changed)))
            .status
            .success()
    );
    // Replaying an old authenticated archive is denied by the externally held
    // new anchor. This is real filesystem rollback, not a mocked provider.
    fs::write(alice.join("state.e2es"), old_archive).unwrap();
    assert!(
        !invoke(&alice, &["identity"], password, Some(&token(&changed)))
            .status
            .success()
    );
    assert!(invoke(&alice, &["identity"], password, None)
        .status
        .success());
}

#[test]
fn credential_and_argument_failures_do_not_create_or_replace_state() {
    let temp = TempDirectory::new();
    let directory = temp.0.join("state");
    assert!(!invoke(&directory, &["init", "alice"], b"short\n", None)
        .status
        .success());
    assert!(!directory.exists());
    assert!(!invoke(
        &directory,
        &["init", "alice"],
        b"a valid long test password\nextra\n",
        None
    )
    .status
    .success());
    assert!(!directory.exists());
    assert!(invoke(
        &directory,
        &["init", "alice"],
        b"a valid long test password\n",
        None
    )
    .status
    .success());
    let before = fs::read(directory.join("state.e2es")).unwrap();
    assert!(!invoke(
        &directory,
        &["init", "alice"],
        b"a valid long test password\n",
        None
    )
    .status
    .success());
    assert!(!invoke(
        &directory,
        &["verify", "bob", "bad-fingerprint"],
        b"a valid long test password\n",
        None
    )
    .status
    .success());
    assert_eq!(fs::read(directory.join("state.e2es")).unwrap(), before);
}
