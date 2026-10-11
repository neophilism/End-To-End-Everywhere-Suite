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

const PASSWORD: &[u8] = b"sender retained copy test password\n";

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let serial = WORKSPACE_SERIAL.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("e2ee-copy-{}-{nanos}-{serial}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn cli(state: &Path, include_self: bool, args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_e2ee"));
    cmd.arg("--state")
        .arg(state)
        .args(["--software-vault", "--password-only", "--password-stdin"]);
    if include_self {
        cmd.arg("--include-self");
    }
    let mut process = cmd
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    process.stdin.take().unwrap().write_all(PASSWORD).unwrap();
    process.wait_with_output().unwrap()
}
fn success(output: Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}
fn contact(source: &Path, peer: &Path, id: &str) {
    let card = success(cli(peer, false, &["card"]));
    success(cli(source, false, &["import", card.trim()]));
    let details = success(cli(peer, false, &["identity"]));
    let fingerprint = details
        .lines()
        .find_map(|line| line.strip_prefix("Fingerprint: "))
        .unwrap();
    success(cli(source, false, &["verify", id, fingerprint]));
}

#[test]
fn sender_retains_signed_encrypted_text_and_file_copies_only_on_opt_in() {
    let dir = Temp::new();
    let alice = dir.0.join("alice");
    let bob = dir.0.join("bob");
    success(cli(&alice, false, &["init", "alice"]));
    success(cli(&bob, false, &["init", "bob"]));
    contact(&alice, &bob, "bob");
    contact(&bob, &alice, "alice");
    let draft = dir.0.join("draft.txt");
    let no_self = dir.0.join("normal.e2ed");
    let my_copy = dir.0.join("retained.e2ed");
    let no_output = dir.0.join("not-available.txt");
    let restored = dir.0.join("restored.txt");
    let recipient = dir.0.join("bob-opened.txt");
    fs::write(&draft, "encrypted signed outgoing memo").unwrap();

    success(cli(
        &alice,
        false,
        &[
            "seal-text",
            "bob",
            "outgoing-v1",
            draft.to_str().unwrap(),
            no_self.to_str().unwrap(),
        ],
    ));
    let failed = cli(
        &alice,
        false,
        &[
            "open-note",
            "outgoing-v1",
            no_self.to_str().unwrap(),
            no_output.to_str().unwrap(),
        ],
    );
    assert!(!failed.status.success());
    assert!(!no_output.exists());

    success(cli(
        &alice,
        true,
        &[
            "seal-text",
            "bob",
            "outgoing-v1",
            draft.to_str().unwrap(),
            my_copy.to_str().unwrap(),
        ],
    ));
    success(cli(
        &alice,
        false,
        &[
            "open-note",
            "outgoing-v1",
            my_copy.to_str().unwrap(),
            restored.to_str().unwrap(),
        ],
    ));
    assert_eq!(
        fs::read_to_string(&restored).unwrap(),
        "encrypted signed outgoing memo"
    );
    success(cli(
        &bob,
        false,
        &[
            "open-text",
            "alice",
            "outgoing-v1",
            my_copy.to_str().unwrap(),
            recipient.to_str().unwrap(),
        ],
    ));
    assert_eq!(fs::read(&recipient).unwrap(), fs::read(&restored).unwrap());
    assert_eq!(
        fs::metadata(&restored).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let original = dir.0.join("attachment.bin");
    let encrypted = dir.0.join("attachment.e2ed");
    let local_open = dir.0.join("my-attachment.bin");
    let remote_open = dir.0.join("bob-attachment.bin");
    let bytes = vec![0, 255, 12, 40, 30, 0, 77, 79];
    fs::write(&original, &bytes).unwrap();
    success(cli(
        &alice,
        true,
        &[
            "seal-file",
            "bob",
            "attachments-v1",
            original.to_str().unwrap(),
            encrypted.to_str().unwrap(),
        ],
    ));
    success(cli(
        &alice,
        false,
        &[
            "open-self-file",
            "attachments-v1",
            encrypted.to_str().unwrap(),
            local_open.to_str().unwrap(),
        ],
    ));
    success(cli(
        &bob,
        false,
        &[
            "open-file",
            "alice",
            "attachments-v1",
            encrypted.to_str().unwrap(),
            remote_open.to_str().unwrap(),
        ],
    ));
    assert_eq!(fs::read(&local_open).unwrap(), bytes);
    assert_eq!(fs::read(&remote_open).unwrap(), bytes);

    let blocked = dir.0.join("blocked.e2ed");
    let incompatible = cli(
        &alice,
        true,
        &[
            "seal-text",
            "alice",
            "outgoing-v1",
            draft.to_str().unwrap(),
            blocked.to_str().unwrap(),
        ],
    );
    assert_eq!(incompatible.status.code(), Some(2));
    assert!(!blocked.exists());
    let forbidden = cli(&alice, true, &["identity"]);
    assert_eq!(forbidden.status.code(), Some(2));
    let also_forbidden = cli(
        &alice,
        true,
        &[
            "open-note",
            "outgoing-v1",
            my_copy.to_str().unwrap(),
            blocked.to_str().unwrap(),
        ],
    );
    assert_eq!(also_forbidden.status.code(), Some(2));
    assert!(!blocked.exists());
}
