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

struct Sandbox(PathBuf);
impl Sandbox {
    fn new() -> Self {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let serial = WORKSPACE_SERIAL.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!(
                "e2ee-delivery-{}-{seed}-{serial}",
                std::process::id()
            ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

const SECRET: &[u8] = b"strong delivery test password\n";
fn cli(state: &Path, args: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_e2ee"))
        .args(["--state"])
        .arg(state)
        .args(["--software-vault", "--password-only", "--password-stdin"])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(SECRET).unwrap();
    child.wait_with_output().unwrap()
}
fn ok(output: &Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
fn init(state: &Path, id: &str) {
    ok(&cli(state, &["init", id]));
}
fn trust(one: &Path, other: &Path, id: &str) {
    let card = cli(other, &["card"]);
    ok(&card);
    let uri = String::from_utf8(card.stdout).unwrap();
    ok(&cli(one, &["import", uri.trim()]));
    let identity = cli(other, &["identity"]);
    ok(&identity);
    let fingerprint = String::from_utf8(identity.stdout)
        .unwrap()
        .lines()
        .find_map(|x| x.strip_prefix("Fingerprint: "))
        .unwrap()
        .to_owned();
    ok(&cli(one, &["verify", id, &fingerprint]));
}

fn send(alice: &Path, input: &Path, output: &Path) -> Output {
    cli(
        alice,
        &[
            "seal-text",
            "bob",
            "personal-mail-v1",
            input.to_str().unwrap(),
            output.to_str().unwrap(),
        ],
    )
}
fn open(bob: &Path, context: &str, encrypted: &Path, output: &Path) -> Output {
    cli(
        bob,
        &[
            "open-text",
            "alice",
            context,
            encrypted.to_str().unwrap(),
            output.to_str().unwrap(),
        ],
    )
}

#[test]
fn signed_text_roundtrip_tampering_wrong_context_and_existing_destination() {
    let root = Sandbox::new();
    let alice = root.0.join("alice");
    let bob = root.0.join("bob");
    init(&alice, "alice");
    init(&bob, "bob");
    trust(&alice, &bob, "bob");
    trust(&bob, &alice, "alice");
    let input = root.0.join("private.txt");
    let encrypted = root.0.join("message.e2ed");
    let output = root.0.join("opened.txt");
    fs::write(&input, "Private multi-line\nmessage.").unwrap();
    ok(&send(&alice, &input, &encrypted));
    let metadata = fs::metadata(&encrypted).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert!(!open(&bob, "different-context", &encrypted, &output)
        .status
        .success());
    assert!(!output.exists());
    ok(&open(&bob, "personal-mail-v1", &encrypted, &output));
    assert_eq!(
        fs::read_to_string(&output).unwrap(),
        "Private multi-line\nmessage."
    );
    assert_eq!(
        fs::metadata(&output).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(!open(&bob, "personal-mail-v1", &encrypted, &output)
        .status
        .success());
    let tampered = root.0.join("tampered.e2ed");
    let mut bytes = fs::read(&encrypted).unwrap();
    let index = bytes.len() / 2;
    bytes[index] ^= 1;
    fs::write(&tampered, bytes).unwrap();
    let rejected = root.0.join("reject.txt");
    assert!(!open(&bob, "personal-mail-v1", &tampered, &rejected)
        .status
        .success());
    assert!(!rejected.exists());
}

#[test]
fn unverified_revoked_and_oversize_input_fail_without_output() {
    let root = Sandbox::new();
    let alice = root.0.join("alice");
    let bob = root.0.join("bob");
    init(&alice, "alice");
    init(&bob, "bob");
    let input = root.0.join("message.txt");
    let encrypted = root.0.join("message.e2ed");
    fs::write(&input, "secret").unwrap();
    let card = cli(&bob, &["card"]);
    ok(&card);
    let uri = String::from_utf8(card.stdout).unwrap();
    ok(&cli(&alice, &["import", uri.trim()]));
    assert!(!send(&alice, &input, &encrypted).status.success());
    assert!(!encrypted.exists());
    trust(&alice, &bob, "bob");
    ok(&cli(&alice, &["revoke", "bob"]));
    assert!(!send(&alice, &input, &encrypted).status.success());
    assert!(!encrypted.exists());
    fs::write(&input, vec![b'x'; 4 * 1024 * 1024 + 1]).unwrap();
    assert!(!send(&alice, &input, &encrypted).status.success());
    assert!(!encrypted.exists());
}
