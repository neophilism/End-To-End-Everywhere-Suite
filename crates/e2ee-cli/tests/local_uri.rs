#![cfg(unix)]

use std::{
    fs,
    io::Write,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

use std::sync::atomic::{AtomicU64, Ordering};

static WORKSPACE_SERIAL: AtomicU64 = AtomicU64::new(0);

const PASSWORD: &[u8] = b"a long local uri test password\n";

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let serial = WORKSPACE_SERIAL.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("e2ee-uri-{}-{stamp}-{serial}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn invoke(state: &Path, format: Option<&str>, command: &[&str]) -> Output {
    let mut program = Command::new(env!("CARGO_BIN_EXE_e2ee"));
    program.arg("--state").arg(state).args([
        "--software-vault",
        "--password-only",
        "--password-stdin",
    ]);
    if let Some(flag) = format {
        program.arg(flag);
    }
    let mut child = program
        .args(command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let _ = child.stdin.take().unwrap().write_all(PASSWORD);
    child.wait_with_output().unwrap()
}

fn success(output: Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn pin(observer: &Path, peer: &Path, name: &str) {
    let card = success(invoke(peer, None, &["card"]));
    success(invoke(observer, None, &["import", card.trim()]));
    let identity = success(invoke(peer, None, &["identity"]));
    let fingerprint = identity
        .lines()
        .find_map(|line| line.strip_prefix("Fingerprint: "))
        .unwrap();
    success(invoke(observer, None, &["verify", name, fingerprint]));
}

#[test]
fn bounded_local_uri_text_and_binary_file_roundtrip() {
    let root = TestDirectory::new();
    let alice = root.0.join("alice");
    let bob = root.0.join("bob");
    success(invoke(&alice, None, &["init", "alice"]));
    success(invoke(&bob, None, &["init", "bob"]));
    pin(&alice, &bob, "bob");
    pin(&bob, &alice, "alice");

    let input = root.0.join("input.txt");
    let uri = root.0.join("message.txt");
    let result = root.0.join("result.txt");
    let plaintext = "This protected note has a distinct secret value.";
    fs::write(&input, plaintext).unwrap();
    success(invoke(
        &alice,
        Some("--uri"),
        &[
            "seal-text",
            "bob",
            "uri-share-v1",
            input.to_str().unwrap(),
            uri.to_str().unwrap(),
        ],
    ));
    let encoded = fs::read_to_string(&uri).unwrap();
    assert!(encoded.starts_with("e2ed:v1:"));
    assert!(encoded.len() <= 8192);
    assert!(!encoded.contains(plaintext));
    assert_eq!(
        fs::metadata(&uri).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let wrong = invoke(
        &bob,
        Some("--uri"),
        &[
            "open-text",
            "alice",
            "wrong-v1",
            uri.to_str().unwrap(),
            result.to_str().unwrap(),
        ],
    );
    assert!(!wrong.status.success());
    assert!(!result.exists());
    success(invoke(
        &bob,
        Some("--uri"),
        &[
            "open-text",
            "alice",
            "uri-share-v1",
            uri.to_str().unwrap(),
            result.to_str().unwrap(),
        ],
    ));
    assert_eq!(fs::read_to_string(&result).unwrap(), plaintext);

    let source = root.0.join("binary.bin");
    let capsule = root.0.join("binary-uri.txt");
    let recovered = root.0.join("binary-result.bin");
    let bytes = vec![0, 11, 0, 255, 212, 0, 1, 2, 3, 4];
    fs::write(&source, &bytes).unwrap();
    success(invoke(
        &alice,
        Some("--uri"),
        &[
            "seal-file",
            "bob",
            "short-file-v1",
            source.to_str().unwrap(),
            capsule.to_str().unwrap(),
        ],
    ));
    success(invoke(
        &bob,
        Some("--uri"),
        &[
            "open-file",
            "alice",
            "short-file-v1",
            capsule.to_str().unwrap(),
            recovered.to_str().unwrap(),
        ],
    ));
    assert_eq!(fs::read(&recovered).unwrap(), bytes);
}

#[test]
fn size_limit_and_invalid_delivery_encoding_never_publish_output() {
    let root = TestDirectory::new();
    let alice = root.0.join("alice");
    let bob = root.0.join("bob");
    success(invoke(&alice, None, &["init", "alice"]));
    success(invoke(&bob, None, &["init", "bob"]));
    pin(&alice, &bob, "bob");

    let input = root.0.join("large.txt");
    let delivery = root.0.join("too-large-uri.txt");
    fs::write(&input, vec![b'X'; 12_000]).unwrap();
    let size_error = invoke(
        &alice,
        Some("--uri"),
        &[
            "seal-text",
            "bob",
            "note-v1",
            input.to_str().unwrap(),
            delivery.to_str().unwrap(),
        ],
    );
    assert!(!size_error.status.success());
    assert!(!delivery.exists());

    let identity_rejected = invoke(&alice, Some("--uri"), &["identity"]);
    assert_eq!(identity_rejected.status.code(), Some(2));
    assert!(identity_rejected.stdout.is_empty());

    let malformed = root.0.join("not-a-uri.txt");
    fs::write(&malformed, "https://site.invalid/?e2ed=v1:abc").unwrap();
    let rejected = root.0.join("not-opened.txt");
    let opening = invoke(
        &bob,
        Some("--uri"),
        &[
            "open-text",
            "alice",
            "note-v1",
            malformed.to_str().unwrap(),
            rejected.to_str().unwrap(),
        ],
    );
    assert!(!opening.status.success());
    assert!(!rejected.exists());
}
