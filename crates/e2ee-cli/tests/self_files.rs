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

const PASSWORD: &[u8] = b"strong self file test password\n";

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let serial = WORKSPACE_SERIAL.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "e2ee-self-file-{}-{stamp}-{serial}",
            std::process::id()
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        Self(root)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run(state: &Path, mode: Option<&str>, command: &[&str]) -> Output {
    let mut process = Command::new(env!("CARGO_BIN_EXE_e2ee"));
    process.arg("--state").arg(state).args([
        "--software-vault",
        "--password-only",
        "--password-stdin",
    ]);
    if let Some(flag) = mode {
        process.arg(flag);
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

fn assert_ok(result: &Output) {
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

fn protect(state: &Path, mode: Option<&str>, source: &Path, target: &Path) -> Output {
    run(
        state,
        mode,
        &[
            "seal-self-file",
            "personal-file-v1",
            source.to_str().unwrap(),
            target.to_str().unwrap(),
        ],
    )
}
fn restore(state: &Path, mode: Option<&str>, context: &str, input: &Path, output: &Path) -> Output {
    run(
        state,
        mode,
        &[
            "open-self-file",
            context,
            input.to_str().unwrap(),
            output.to_str().unwrap(),
        ],
    )
}

#[test]
fn local_file_protection_authenticates_sender_context_and_destination() {
    let folder = Directory::new();
    let me = folder.0.join("local-key");
    let other = folder.0.join("different-key");
    assert_ok(&run(&me, None, &["init", "me"]));
    assert_ok(&run(&other, None, &["init", "other"]));

    let input = folder.0.join("personal.bin");
    let encrypted = folder.0.join("sealed.e2ed");
    let plaintext: Vec<u8> = (0..125_000).map(|i| (i % 251) as u8).collect();
    fs::write(&input, &plaintext).unwrap();
    assert_ok(&protect(&me, None, &input, &encrypted));
    assert_eq!(
        fs::metadata(&encrypted).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_ne!(fs::read(&encrypted).unwrap(), plaintext);

    let output = folder.0.join("restored.bin");
    let wrong_context = restore(&me, None, "wrong-purpose", &encrypted, &output);
    assert!(!wrong_context.status.success());
    assert!(!output.exists());
    let wrong_identity = restore(&other, None, "personal-file-v1", &encrypted, &output);
    assert!(!wrong_identity.status.success());
    assert!(!output.exists());

    assert_ok(&restore(&me, None, "personal-file-v1", &encrypted, &output));
    assert_eq!(fs::read(&output).unwrap(), plaintext);
    assert_eq!(
        fs::metadata(&output).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let duplicate = restore(&me, None, "personal-file-v1", &encrypted, &output);
    assert!(!duplicate.status.success());

    let mut altered = fs::read(&encrypted).unwrap();
    let index = altered.len() / 2;
    altered[index] ^= 1;
    let corrupted = folder.0.join("corrupt.e2ed");
    fs::write(&corrupted, altered).unwrap();
    let rejected = folder.0.join("rejected.bin");
    let tamper = restore(&me, None, "personal-file-v1", &corrupted, &rejected);
    assert!(!tamper.status.success());
    assert!(!rejected.exists());
}

#[test]
fn a_small_file_can_use_armor_and_local_uri_modes() {
    let folder = Directory::new();
    let me = folder.0.join("local");
    assert_ok(&run(&me, None, &["init", "local"]));
    let source = folder.0.join("source.bin");
    fs::write(&source, [0, 255, 32, 13, 10, 42]).unwrap();
    for (flag, extension) in [("--armor", "asc"), ("--uri", "txt")] {
        let encrypted = folder.0.join(format!("protected-{extension}"));
        let decrypted = folder.0.join(format!("recovered-{extension}"));
        assert_ok(&protect(&me, Some(flag), &source, &encrypted));
        assert_ok(&restore(
            &me,
            Some(flag),
            "personal-file-v1",
            &encrypted,
            &decrypted,
        ));
        assert_eq!(fs::read(&decrypted).unwrap(), fs::read(&source).unwrap());
    }
}
