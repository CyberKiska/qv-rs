use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

fn qvault_cli() -> &'static str {
    env!("CARGO_BIN_EXE_qvault-cli")
}

fn unique_temp_path(name: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/qvault-cli-tests");
    std::fs::create_dir_all(&dir).expect("create test temp dir");
    dir.join(format!("{name}-{nonce}"))
}

fn core_fixture(relative: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../qvault-core/tests/data")
        .join(relative)
}

#[test]
fn version_json_envelope_is_schema_v1() {
    let output = Command::new(qvault_cli())
        .args(["--json", "version"])
        .output()
        .expect("run qvault-cli version");
    assert!(output.status.success(), "status: {:?}", output.status);
    let value: Value = serde_json::from_slice(&output.stdout).expect("version JSON");
    assert_eq!(value["command"], "version");
    assert_eq!(value["ok"], true);
    assert_eq!(value["cliSchemaVersion"], 1);
    assert_eq!(value["format"]["qcont"], "QVqcont-7");
}

#[test]
fn selftest_json_envelope_is_schema_v1() {
    let output = Command::new(qvault_cli())
        .args(["--json", "--quiet", "selftest"])
        .output()
        .expect("run qvault-cli selftest");
    assert!(output.status.success(), "status: {:?}", output.status);
    let value: Value = serde_json::from_slice(&output.stdout).expect("selftest JSON");
    assert_eq!(value["command"], "selftest");
    assert_eq!(value["ok"], true);
    assert_eq!(value["cliSchemaVersion"], 1);
    assert!(value["checks"].as_array().is_some());
}

#[test]
fn usage_errors_emit_minimal_qvcode_json_envelope() {
    let output = Command::new(qvault_cli())
        .args(["--json", "restore"])
        .output()
        .expect("run qvault-cli restore usage error");
    assert!(!output.status.success(), "status should fail");
    let value: Value = serde_json::from_slice(&output.stdout).expect("error JSON");
    assert_eq!(value["command"], "restore");
    assert_eq!(value["ok"], false);
    assert_eq!(value["cliSchemaVersion"], 1);
    assert_eq!(value["qvCode"], "USAGE");
    assert!(value.get("error").and_then(Value::as_str).is_some());
    assert_eq!(value.as_object().expect("object").len(), 5);
}

#[test]
fn key_rejected_errors_emit_oracle_qvcode_and_exit_status() {
    let bad_key = unique_temp_path("bad-key.qkey");
    std::fs::write(&bad_key, b"not-a-ml-kem-secret-key").expect("write bad key");
    let output_path = unique_temp_path("decrypted.bin");

    let output = Command::new(qvault_cli())
        .args([
            "--json",
            "decrypt",
            core_fixture("qenc_interop/single-small/container.qenc")
                .to_str()
                .expect("utf8 fixture path"),
            "--private-key",
            bad_key.to_str().expect("utf8 temp path"),
            "--out",
            output_path.to_str().expect("utf8 temp path"),
        ])
        .output()
        .expect("run qvault-cli decrypt with rejected key");

    assert_eq!(output.status.code(), Some(5), "status: {:?}", output.status);
    let value: Value = serde_json::from_slice(&output.stdout).expect("error JSON");
    assert_eq!(value["command"], "decrypt");
    assert_eq!(value["ok"], false);
    assert_eq!(value["qvCode"], "KEY_REJECTED");
}

#[test]
fn aead_errors_emit_oracle_qvcode_and_exit_status() {
    let qenc_path = unique_temp_path("tampered.qenc");
    let mut qenc = std::fs::read(core_fixture("qenc_interop/single-small/container.qenc"))
        .expect("read qenc fixture");
    let last = qenc.last_mut().expect("non-empty qenc");
    *last ^= 0x01;
    std::fs::write(&qenc_path, qenc).expect("write tampered qenc");
    let output_path = unique_temp_path("decrypted.bin");

    let output = Command::new(qvault_cli())
        .args([
            "--json",
            "decrypt",
            qenc_path.to_str().expect("utf8 temp path"),
            "--private-key",
            core_fixture("qenc_interop/single-small/secret.qkey")
                .to_str()
                .expect("utf8 fixture path"),
            "--out",
            output_path.to_str().expect("utf8 temp path"),
        ])
        .output()
        .expect("run qvault-cli decrypt with tampered qenc");

    assert_eq!(output.status.code(), Some(6), "status: {:?}", output.status);
    let value: Value = serde_json::from_slice(&output.stdout).expect("error JSON");
    assert_eq!(value["command"], "decrypt");
    assert_eq!(value["ok"], false);
    assert_eq!(value["qvCode"], "AEAD_FAILED");
}
