#![cfg(unix)]

use std::{
    fs,
    io::Write,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

const PASSWORD: &[u8] = b"a strong personal note test passphrase\n";

struct Temp(PathBuf);

impl Temp {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("e2ee-note-{}-{nonce}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn call(state: &Path, format: Option<&str>, command: &[&str]) -> Output {
    let mut process = Command::new(env!("CARGO_BIN_EXE_e2ee"));
    process.arg("--state").arg(state).args([
        "--software-vault",
        "--password-only",
        "--password-stdin",
    ]);
    if let Some(format) = format {
        process.arg(format);
    }
    let mut child = process
        .args(command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let _ = child.stdin.take().unwrap().write_all(PASSWORD);
    child.wait_with_output().unwrap()
}

fn assert_ok(output: &Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn seal(state: &Path, format: Option<&str>, source: &Path, destination: &Path) -> Output {
    call(
        state,
        format,
        &[
            "seal-note",
            "personal-notes-v1",
            source.to_str().unwrap(),
            destination.to_str().unwrap(),
        ],
    )
}

fn open(
    state: &Path,
    format: Option<&str>,
    context: &str,
    source: &Path,
    destination: &Path,
) -> Output {
    call(
        state,
        format,
        &[
            "open-note",
            context,
            source.to_str().unwrap(),
            destination.to_str().unwrap(),
        ],
    )
}

#[test]
fn self_encrypted_notes_survive_restart_and_require_matching_identity_and_context() {
    let temp = Temp::new();
    let alice = temp.0.join("alice");
    let other = temp.0.join("other");
    assert_ok(&call(&alice, None, &["init", "alice"]));
    assert_ok(&call(&other, None, &["init", "other"]));
    let plaintext = "A private local note, not for other identities.";
    let draft = temp.0.join("draft.txt");
    fs::write(&draft, plaintext).unwrap();

    let sealed = temp.0.join("note.e2ed");
    assert_ok(&seal(&alice, None, &draft, &sealed));
    assert_eq!(
        fs::metadata(&sealed).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let opened = temp.0.join("opened.txt");
    let wrong_context = open(&alice, None, "not-personal-notes-v1", &sealed, &opened);
    assert!(!wrong_context.status.success());
    assert!(!opened.exists());

    let wrong_identity = open(&other, None, "personal-notes-v1", &sealed, &opened);
    assert!(!wrong_identity.status.success());
    assert!(!opened.exists());

    assert_ok(&open(&alice, None, "personal-notes-v1", &sealed, &opened));
    assert_eq!(fs::read_to_string(&opened).unwrap(), plaintext);
    assert_eq!(
        fs::metadata(&opened).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let overwrite = open(&alice, None, "personal-notes-v1", &sealed, &opened);
    assert!(!overwrite.status.success());

    let armored = temp.0.join("note.asc");
    let opened_armor = temp.0.join("armor-opened.txt");
    assert_ok(&seal(&alice, Some("--armor"), &draft, &armored));
    let armor_bytes = fs::read_to_string(&armored).unwrap();
    assert!(armor_bytes.starts_with("-----BEGIN E2E DELIVERY-----"));
    assert_ok(&open(
        &alice,
        Some("--armor"),
        "personal-notes-v1",
        &armored,
        &opened_armor,
    ));
    assert_eq!(fs::read_to_string(&opened_armor).unwrap(), plaintext);

    let uri = temp.0.join("note-uri.txt");
    let opened_uri = temp.0.join("uri-opened.txt");
    assert_ok(&seal(&alice, Some("--uri"), &draft, &uri));
    assert!(fs::read_to_string(&uri).unwrap().starts_with("e2ed:v1:"));
    assert_ok(&open(
        &alice,
        Some("--uri"),
        "personal-notes-v1",
        &uri,
        &opened_uri,
    ));
    assert_eq!(fs::read_to_string(&opened_uri).unwrap(), plaintext);
}

#[test]
fn malformed_self_note_does_not_create_plaintext_file() {
    let temp = Temp::new();
    let alice = temp.0.join("alice");
    assert_ok(&call(&alice, None, &["init", "alice"]));
    let draft = temp.0.join("draft.txt");
    fs::write(&draft, "classified note").unwrap();
    let encrypted = temp.0.join("note.e2ed");
    assert_ok(&seal(&alice, None, &draft, &encrypted));
    let mut bytes = fs::read(&encrypted).unwrap();
    let index = bytes.len() / 2;
    bytes[index] ^= 1;
    let modified = temp.0.join("modified.e2ed");
    fs::write(&modified, bytes).unwrap();
    let destination = temp.0.join("never.txt");
    let result = open(&alice, None, "personal-notes-v1", &modified, &destination);
    assert!(!result.status.success());
    assert!(!destination.exists());
}
