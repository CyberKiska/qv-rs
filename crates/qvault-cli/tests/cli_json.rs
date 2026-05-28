use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use qvault_core::auth::{unpack_public_key_file, unpack_secret_key_file, PqSignatureSuite};
use qvault_core::hash::sha3_512_hex;
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

fn append_file_name_suffix(path: &std::path::Path, suffix: &str) -> std::path::PathBuf {
    let mut file_name = path.file_name().expect("file name").to_os_string();
    file_name.push(suffix);
    path.with_file_name(file_name)
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
fn signer_keygen_json_writes_pq_keys_without_secret_leakage() {
    let out_prefix = unique_temp_path("signer");
    let public_key_path = append_file_name_suffix(&out_prefix, ".pqpk");
    let secret_key_path = append_file_name_suffix(&out_prefix, ".pqsk");

    let output = Command::new(qvault_cli())
        .args([
            "--json",
            "signer-keygen",
            "--suite",
            "mldsa-44",
            "--out",
            out_prefix.to_str().expect("utf8 temp path"),
        ])
        .output()
        .expect("run qvault-cli signer-keygen");

    assert!(
        output.status.success(),
        "status: {:?}, stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let value: Value = serde_json::from_str(&stdout).expect("signer-keygen JSON");
    assert_eq!(value["command"], "signer-keygen");
    assert_eq!(value["ok"], true);
    assert_eq!(value["cliSchemaVersion"], 1);
    assert_eq!(value["suite"], "mldsa-44");
    assert_eq!(value["strongPq"], false);
    assert_eq!(
        value["publicKeyPath"],
        public_key_path.to_str().expect("utf8 public path")
    );
    assert_eq!(
        value["secretKeyPath"],
        secret_key_path.to_str().expect("utf8 secret path")
    );
    assert_eq!(value["signerFingerprintAlg"], "SHA3-256");
    assert_eq!(
        value["signerFingerprintHex"]
            .as_str()
            .expect("fingerprint hex")
            .len(),
        64
    );

    let public_key_file = std::fs::read(&public_key_path).expect("read public key");
    let secret_key_file = std::fs::read(&secret_key_path).expect("read secret key");
    let parsed_public = unpack_public_key_file(&public_key_file).expect("parse pqpk");
    let parsed_secret = unpack_secret_key_file(&secret_key_file).expect("parse pqsk");
    assert_eq!(parsed_public.suite, PqSignatureSuite::MlDsa44);
    assert_eq!(parsed_secret.suite, PqSignatureSuite::MlDsa44);
    assert_eq!(
        value["publicKeyDigestHex"],
        sha3_512_hex(&parsed_public.key_bytes)
    );

    for forbidden_field in [
        "privateKeyDigestHex",
        "secretKeyDigestHex",
        "privateKeyBase64",
        "secretKeyBase64",
        "secretKeyBytes",
        "seed",
    ] {
        assert!(
            value.get(forbidden_field).is_none(),
            "{forbidden_field} must not be emitted"
        );
    }
    assert!(!stdout.contains(&sha3_512_hex(&secret_key_file)));
    assert!(!stdout.contains(&sha3_512_hex(parsed_secret.key_bytes())));
    assert!(!stdout.contains(&BASE64_STANDARD.encode(&secret_key_file)));
    assert!(!stdout.contains(&BASE64_STANDARD.encode(parsed_secret.key_bytes())));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        assert_eq!(
            std::fs::metadata(&secret_key_path)
                .expect("secret key metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn signer_keygen_quiet_success_emits_no_stdout() {
    let out_prefix = unique_temp_path("signer-quiet");
    let public_key_path = append_file_name_suffix(&out_prefix, ".pqpk");
    let secret_key_path = append_file_name_suffix(&out_prefix, ".pqsk");

    let output = Command::new(qvault_cli())
        .args([
            "--quiet",
            "signer-keygen",
            "--suite",
            "mldsa-44",
            "--out",
            out_prefix.to_str().expect("utf8 temp path"),
        ])
        .output()
        .expect("run quiet signer-keygen");

    assert!(
        output.status.success(),
        "status: {:?}, stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    assert!(public_key_path.exists());
    assert!(secret_key_path.exists());
}

#[test]
fn signer_keygen_refuses_existing_output_without_secret_side_effect() {
    let out_prefix = unique_temp_path("signer-existing");
    let public_key_path = append_file_name_suffix(&out_prefix, ".pqpk");
    let secret_key_path = append_file_name_suffix(&out_prefix, ".pqsk");
    std::fs::write(&public_key_path, b"existing-pqpk").expect("write existing public key");

    let output = Command::new(qvault_cli())
        .args([
            "--json",
            "signer-keygen",
            "--suite",
            "mldsa-44",
            "--out",
            out_prefix.to_str().expect("utf8 temp path"),
        ])
        .output()
        .expect("run signer-keygen with existing output");

    assert!(!output.status.success(), "status should fail");
    assert_eq!(
        std::fs::read(&public_key_path).expect("read existing public key"),
        b"existing-pqpk"
    );
    assert!(
        !secret_key_path.exists(),
        "secret key must not be created after preflight failure"
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("error JSON");
    assert_eq!(value["command"], "signer-keygen");
    assert_eq!(value["ok"], false);
    assert_eq!(value["qvCode"], "USAGE");
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
