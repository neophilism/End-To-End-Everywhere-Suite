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

const SECRET: &[u8] = b"private file test password\n";

struct Working(PathBuf);
impl Working {
    fn new() -> Self {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let serial = WORKSPACE_SERIAL.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("e2ee-file-{}-{seed}-{serial}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for Working {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn call(state: &Path, command: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_e2ee"))
        .arg("--state")
        .arg(state)
        .args(["--software-vault", "--password-only", "--password-stdin"])
        .args(command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(SECRET).unwrap();
    child.wait_with_output().unwrap()
}

fn passed(output: Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn contact(source: &Path, target: &Path, id: &str) {
    let card = passed(call(target, &["card"]));
    passed(call(source, &["import", card.trim()]));
    let identity = passed(call(target, &["identity"]));
    let fingerprint = identity
        .lines()
        .find_map(|line| line.strip_prefix("Fingerprint: "))
        .unwrap();
    passed(call(source, &["verify", id, fingerprint]));
}

#[test]
fn file_delivery_roundtrip_and_authentication_fail_closed() {
    let root = Working::new();
    let alice = root.0.join("alice");
    let bob = root.0.join("bob");
    passed(call(&alice, &["init", "alice"]));
    passed(call(&bob, &["init", "bob"]));
    contact(&alice, &bob, "bob");
    contact(&bob, &alice, "alice");

    let original = root.0.join("picture.bin");
    let delivery = root.0.join("attachment.e2ed");
    let opened = root.0.join("recovered.bin");
    let bytes: Vec<u8> = (0..130_000).map(|i| (i % 251) as u8).collect();
    fs::write(&original, &bytes).unwrap();
    passed(call(
        &alice,
        &[
            "seal-file",
            "bob",
            "files-v1",
            original.to_str().unwrap(),
            delivery.to_str().unwrap(),
        ],
    ));
    assert_eq!(
        fs::metadata(&delivery).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let wrong = call(
        &bob,
        &[
            "open-file",
            "alice",
            "other-v1",
            delivery.to_str().unwrap(),
            opened.to_str().unwrap(),
        ],
    );
    assert!(!wrong.status.success());
    assert!(!opened.exists());
    passed(call(
        &bob,
        &[
            "open-file",
            "alice",
            "files-v1",
            delivery.to_str().unwrap(),
            opened.to_str().unwrap(),
        ],
    ));
    assert_eq!(fs::read(&opened).unwrap(), bytes);
    assert_eq!(
        fs::metadata(&opened).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let second = call(
        &bob,
        &[
            "open-file",
            "alice",
            "files-v1",
            delivery.to_str().unwrap(),
            opened.to_str().unwrap(),
        ],
    );
    assert!(!second.status.success());

    let mut corrupted = fs::read(&delivery).unwrap();
    let index = corrupted.len() / 2;
    corrupted[index] ^= 1;
    let tampered = root.0.join("tampered.e2ed");
    let denied = root.0.join("denied.bin");
    fs::write(&tampered, corrupted).unwrap();
    let result = call(
        &bob,
        &[
            "open-file",
            "alice",
            "files-v1",
            tampered.to_str().unwrap(),
            denied.to_str().unwrap(),
        ],
    );
    assert!(!result.status.success());
    assert!(!denied.exists());
}
