#![cfg(unix)]

use std::{
    fs,
    io::Write,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

const PASSWORD: &[u8] = b"group encryption integration password\n";

struct PrivateTest(PathBuf);
impl PrivateTest {
    fn create() -> Self {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let folder = std::env::temp_dir().join(format!("e2ee-group-{}-{stamp}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&folder).unwrap();
        Self(folder)
    }
}
impl Drop for PrivateTest {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn run(state: &Path, include_self: bool, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_e2ee"));
    command
        .arg("--state")
        .arg(state)
        .args(["--software-vault", "--password-only", "--password-stdin"]);
    if include_self {
        command.arg("--include-self");
    }
    let mut child = command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(PASSWORD).unwrap();
    child.wait_with_output().unwrap()
}
fn success(result: Output) -> String {
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap()
}
fn connect(observer: &Path, peer: &Path, id: &str) {
    let public = success(run(peer, false, &["card"]));
    success(run(observer, false, &["import", public.trim()]));
    let identity = success(run(peer, false, &["identity"]));
    let full = identity
        .lines()
        .find_map(|line| line.strip_prefix("Fingerprint: "))
        .unwrap();
    success(run(observer, false, &["verify", id, full]));
}

#[test]
fn group_list_delivers_to_all_verified_contacts_and_optional_self() {
    let root = PrivateTest::create();
    let alice = root.0.join("alice");
    let bob = root.0.join("bob");
    let carol = root.0.join("carol");
    success(run(&alice, false, &["init", "alice"]));
    success(run(&bob, false, &["init", "bob"]));
    success(run(&carol, false, &["init", "carol"]));
    connect(&alice, &bob, "bob");
    connect(&alice, &carol, "carol");
    connect(&bob, &alice, "alice");
    connect(&carol, &alice, "alice");

    let roster = root.0.join("recipients.txt");
    fs::write(&roster, "bob\r\ncarol\r\n").unwrap();
    let original = root.0.join("memo.txt");
    fs::write(&original, "This memo is for both verified recipients").unwrap();
    let delivery = root.0.join("message.e2ed");
    success(run(
        &alice,
        true,
        &[
            "seal-text-list",
            roster.to_str().unwrap(),
            "group-v1",
            original.to_str().unwrap(),
            delivery.to_str().unwrap(),
        ],
    ));
    let retained = root.0.join("retained.txt");
    success(run(
        &alice,
        false,
        &[
            "open-note",
            "group-v1",
            delivery.to_str().unwrap(),
            retained.to_str().unwrap(),
        ],
    ));
    for (name, recipient) in [("bob", &bob), ("carol", &carol)] {
        let output = root.0.join(format!("opened-{name}.txt"));
        success(run(
            recipient,
            false,
            &[
                "open-text",
                "alice",
                "group-v1",
                delivery.to_str().unwrap(),
                output.to_str().unwrap(),
            ],
        ));
        assert_eq!(fs::read(&output).unwrap(), fs::read(&retained).unwrap());
    }

    let raw = root.0.join("data.bin");
    let sealed = root.0.join("file.e2ed");
    fs::write(&raw, [0, 255, 2, 3, 0, 5, 8]).unwrap();
    success(run(
        &alice,
        false,
        &[
            "seal-file-list",
            roster.to_str().unwrap(),
            "group-files-v1",
            raw.to_str().unwrap(),
            sealed.to_str().unwrap(),
        ],
    ));
    let opened = root.0.join("bob-data.bin");
    success(run(
        &bob,
        false,
        &[
            "open-file",
            "alice",
            "group-files-v1",
            sealed.to_str().unwrap(),
            opened.to_str().unwrap(),
        ],
    ));
    assert_eq!(fs::read(&opened).unwrap(), fs::read(&raw).unwrap());
}

#[test]
fn invalid_or_untrusted_group_lists_fail_before_creating_delivery() {
    let root = PrivateTest::create();
    let alice = root.0.join("alice");
    let bob = root.0.join("bob");
    success(run(&alice, false, &["init", "alice"]));
    success(run(&bob, false, &["init", "bob"]));
    connect(&alice, &bob, "bob");
    let input = root.0.join("memo.txt");
    fs::write(&input, "Some message").unwrap();
    for (label, roster) in [
        ("duplicate", b"bob\nbob\n".to_vec()),
        ("unknown", b"bob\nuntrusted\n".to_vec()),
        ("empty", b"bob\n\n".to_vec()),
        ("leading-space", b" bob\n".to_vec()),
        ("bare-cr", b"bob\r".to_vec()),
        ("invalid-utf8", vec![0xff, 0xfe]),
        ("oversized", vec![b'b'; 132_097]),
    ] {
        let list = root.0.join(format!("{label}.txt"));
        let output = root.0.join(format!("{label}.e2ed"));
        fs::write(&list, roster).unwrap();
        let result = run(
            &alice,
            false,
            &[
                "seal-text-list",
                list.to_str().unwrap(),
                "group-v1",
                input.to_str().unwrap(),
                output.to_str().unwrap(),
            ],
        );
        assert!(!result.status.success(), "{label}");
        assert!(!output.exists(), "{label}");
    }
}
