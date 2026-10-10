#![cfg(unix)]

use std::{
    fs,
    io::Write,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

static WORKSPACE_SERIAL: AtomicU64 = AtomicU64::new(0);

const PASSWORD: &[u8] = b"a long armor test passphrase\n";

struct Workspace(PathBuf);
impl Workspace {
    fn new() -> Self {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let serial = WORKSPACE_SERIAL.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("e2ee-armor-{}-{seed}-{serial}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn invoke(state: &Path, armored: bool, command: &[&str]) -> Output {
    let mut process = Command::new(env!("CARGO_BIN_EXE_e2ee"));
    process.arg("--state").arg(state).args([
        "--software-vault",
        "--password-only",
        "--password-stdin",
    ]);
    if armored {
        process.arg("--armor");
    }
    let mut child = process
        .args(command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(PASSWORD).unwrap();
    child.wait_with_output().unwrap()
}

fn succeeded(output: Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn verify_contact(observer: &Path, remote: &Path, id: &str) {
    let card = succeeded(invoke(remote, false, &["card"]));
    succeeded(invoke(observer, false, &["import", card.trim()]));
    let identity = succeeded(invoke(remote, false, &["identity"]));
    let fingerprint = identity
        .lines()
        .find_map(|line| line.strip_prefix("Fingerprint: "))
        .unwrap();
    succeeded(invoke(observer, false, &["verify", id, fingerprint]));
}

#[test]
fn text_and_file_armor_roundtrip_rejects_wrong_mode_and_tampering() {
    let temp = Workspace::new();
    let alice = temp.0.join("alice");
    let bob = temp.0.join("bob");
    succeeded(invoke(&alice, false, &["init", "alice"]));
    succeeded(invoke(&bob, false, &["init", "bob"]));
    verify_contact(&alice, &bob, "bob");
    verify_contact(&bob, &alice, "alice");

    let message = temp.0.join("original.txt");
    let encrypted = temp.0.join("message.asc");
    let decrypted = temp.0.join("opened.txt");
    let plaintext = "Private email body — this must never appear in the armor.";
    fs::write(&message, plaintext).unwrap();
    succeeded(invoke(
        &alice,
        true,
        &[
            "seal-text",
            "bob",
            "email-body-v1",
            message.to_str().unwrap(),
            encrypted.to_str().unwrap(),
        ],
    ));
    let armor = fs::read_to_string(&encrypted).unwrap();
    assert!(armor.starts_with("-----BEGIN E2E DELIVERY-----\n"));
    assert!(armor.ends_with("-----END E2E DELIVERY-----\n"));
    assert!(!armor.contains(plaintext));
    assert_eq!(
        fs::metadata(&encrypted).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(!invoke(
        &bob,
        false,
        &[
            "open-text",
            "alice",
            "email-body-v1",
            encrypted.to_str().unwrap(),
            decrypted.to_str().unwrap(),
        ],
    )
    .status
    .success());
    assert!(!decrypted.exists());
    succeeded(invoke(
        &bob,
        true,
        &[
            "open-text",
            "alice",
            "email-body-v1",
            encrypted.to_str().unwrap(),
            decrypted.to_str().unwrap(),
        ],
    ));
    assert_eq!(fs::read_to_string(&decrypted).unwrap(), plaintext);
    assert_eq!(
        fs::metadata(&decrypted).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let malformed = temp.0.join("malformed.asc");
    let rejected = temp.0.join("rejected.txt");
    fs::write(&malformed, format!("{armor}APPENDED CONTENT")).unwrap();
    assert!(!invoke(
        &bob,
        true,
        &[
            "open-text",
            "alice",
            "email-body-v1",
            malformed.to_str().unwrap(),
            rejected.to_str().unwrap(),
        ],
    )
    .status
    .success());
    assert!(!rejected.exists());

    let binary_file = temp.0.join("original.bin");
    let armored_file = temp.0.join("file.asc");
    let recovered_file = temp.0.join("recovered.bin");
    let data: Vec<u8> = (0..9000).map(|index| (index % 253) as u8).collect();
    fs::write(&binary_file, &data).unwrap();
    succeeded(invoke(
        &alice,
        true,
        &[
            "seal-file",
            "bob",
            "file-share-v1",
            binary_file.to_str().unwrap(),
            armored_file.to_str().unwrap(),
        ],
    ));
    succeeded(invoke(
        &bob,
        true,
        &[
            "open-file",
            "alice",
            "file-share-v1",
            armored_file.to_str().unwrap(),
            recovered_file.to_str().unwrap(),
        ],
    ));
    assert_eq!(fs::read(&recovered_file).unwrap(), data);
}

#[test]
fn armor_is_rejected_for_nondelivery_commands() {
    let temp = Workspace::new();
    let state = temp.0.join("identity");
    succeeded(invoke(&state, false, &["init", "alice"]));
    let result = invoke(&state, true, &["identity"]);
    assert!(!result.status.success());
    assert_eq!(result.status.code(), Some(2));
    assert!(result.stdout.is_empty());
}
