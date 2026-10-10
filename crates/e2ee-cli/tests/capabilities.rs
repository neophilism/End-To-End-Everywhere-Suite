use std::process::Command;

fn invoke(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_e2ee"))
        .args(arguments)
        .output()
        .expect("execute local CLI")
}

#[test]
fn capabilities_are_available_without_identity_or_password() {
    let result = invoke(&["--capabilities-json"]);
    assert!(result.status.success());
    assert!(result.stderr.is_empty());
    let output = String::from_utf8(result.stdout).expect("UTF-8 JSON");
    assert!(output.contains("\"schema_version\": 1"));
    assert!(output.contains("\"security_certified\": false"));
    assert!(output.contains("\"production_ready\": false"));
    assert!(output.contains("\"network_delivery\": false"));
    assert!(output.contains("\"forward_secret_sessions\": false"));
    assert!(output.contains("\"verified_contact_pinning\": true"));
    assert!(output.ends_with(char::from(10u8)));
}

#[test]
fn capabilities_flag_rejects_trailing_arguments() {
    let result = invoke(&["--capabilities-json", "unexpected"]);
    assert_eq!(result.status.code(), Some(2));
    assert!(result.stdout.is_empty());
}

#[test]
fn capabilities_do_not_expose_local_secret_material() {
    let result = invoke(&["--capabilities-json"]);
    let output = String::from_utf8(result.stdout).expect("UTF-8 JSON");
    assert!(!output.contains("passphrase_value"));
    assert!(!output.contains("private_key"));
    assert!(!output.contains("credential_value"));
}
