use std::process::Command;

use serde_json::Value;

fn qvault_cli() -> &'static str {
    env!("CARGO_BIN_EXE_qvault-cli")
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
