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

const PASSPHRASE: &[u8] = b"file contact integration password\n";

struct Isolated(PathBuf);
impl Isolated {
    fn create() -> Self {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let serial = WORKSPACE_SERIAL.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "e2ee-card-{}-{stamp}-{serial}",
            std::process::id()
        ));
        fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        Self(dir)
    }
}
impl Drop for Isolated {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn cli(state: &Path, commands: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_e2ee"))
        .arg("--state")
        .arg(state)
        .args(["--software-vault", "--password-only", "--password-stdin"])
        .args(commands)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(PASSPHRASE).unwrap();
    child.wait_with_output().unwrap()
}
fn output(result: Output) -> String {
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap()
}
fn init(dir: &Path, id: &str) {
    output(cli(dir, &["init", id]));
}

#[test]
fn exported_card_is_public_private_file_and_import_never_grants_trust() {
    let temp = Isolated::create();
    let alice = temp.0.join("alice");
    let bob = temp.0.join("bob");
    init(&alice, "alice");
    init(&bob, "bob");
    let card = temp.0.join("alice.contact");
    output(cli(&alice, &["card-save", card.to_str().unwrap()]));
    let contents = fs::read_to_string(&card).unwrap();
    assert!(contents.starts_with("e2ec:v1:"));
    assert!(contents.ends_with('\n'));
    assert_eq!(
        fs::metadata(&card).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(!cli(&alice, &["card-save", card.to_str().unwrap()])
        .status
        .success());

    output(cli(&bob, &["import-card", card.to_str().unwrap()]));
    let listing = output(cli(&bob, &["contacts"]));
    assert!(listing.contains("alice\tunverified\t"));

    let full_identity = output(cli(&alice, &["identity"]));
    let fingerprint = full_identity
        .lines()
        .find_map(|line| line.strip_prefix("Fingerprint: "))
        .unwrap();
    output(cli(&bob, &["verify", "alice", fingerprint]));
    let verified = output(cli(&bob, &["contacts"]));
    assert!(verified.contains("alice\tverified\t"));
    output(cli(&bob, &["revoke", "alice"]));
    output(cli(&bob, &["import-card", card.to_str().unwrap()]));
    let revoked = output(cli(&bob, &["contacts"]));
    assert!(revoked.contains("alice\trevoked\t"));
}

#[test]
fn malformed_multiple_record_and_oversized_cards_fail_closed() {
    let temp = Isolated::create();
    let alice = temp.0.join("alice");
    let bob = temp.0.join("bob");
    init(&alice, "alice");
    init(&bob, "bob");
    let card = temp.0.join("card.contact");
    output(cli(&alice, &["card-save", card.to_str().unwrap()]));
    let contents = fs::read_to_string(&card).unwrap();

    for (name, material) in [
        ("extra-record", format!("{contents}{contents}")),
        ("extra-newline", format!("{contents}\n")),
        ("trailing-spaces", format!("{contents} ")),
    ] {
        let file = temp.0.join(name);
        fs::write(&file, material).unwrap();
        let bad = cli(&bob, &["import-card", file.to_str().unwrap()]);
        assert!(!bad.status.success(), "{name}");
    }

    let binary_card = temp.0.join("invalid-utf8");
    fs::write(&binary_card, [0xff, 0xfe, 0xfd]).unwrap();
    assert!(!cli(&bob, &["import-card", binary_card.to_str().unwrap()])
        .status
        .success());
    let oversize = temp.0.join("oversize");
    fs::write(&oversize, vec![b'A'; 4097]).unwrap();
    assert!(!cli(&bob, &["import-card", oversize.to_str().unwrap()])
        .status
        .success());
    let listing = output(cli(&bob, &["contacts"]));
    assert!(listing.is_empty());
}
