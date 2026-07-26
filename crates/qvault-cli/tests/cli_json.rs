use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use qvault_core::auth::{unpack_public_key_file, unpack_secret_key_file, PqSignatureSuite};
use qvault_core::hash::{sha256_hex, sha3_512_hex};
use qvault_core::lifecycle::parse_source_evidence_bytes;
use qvault_core::qcont::parse_qvqcont7_shard;
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

fn generate_test_signer(name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let out_prefix = unique_temp_path(name);
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
        .expect("run signer-keygen");
    assert!(
        output.status.success(),
        "status: {:?}, stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    (public_key_path, secret_key_path)
}

fn generate_test_encryption_keys(name: &str) -> std::path::PathBuf {
    let key_dir = unique_temp_path(name);
    let output = Command::new(qvault_cli())
        .args([
            "--quiet",
            "keygen",
            "--out",
            key_dir.to_str().expect("utf8 key dir"),
        ])
        .output()
        .expect("run keygen");
    assert!(
        output.status.success(),
        "status: {:?}, stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    key_dir
}

fn assert_no_secret_material(stdout: &str, secret_key_file: &[u8], secret_key_bytes: &[u8]) {
    assert!(!stdout.contains(&sha3_512_hex(secret_key_file)));
    assert!(!stdout.contains(&sha3_512_hex(secret_key_bytes)));
    assert!(!stdout.contains(&BASE64_STANDARD.encode(secret_key_file)));
    assert!(!stdout.contains(&BASE64_STANDARD.encode(secret_key_bytes)));
}

fn create_encrypted_payload_fixture(name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let root = unique_temp_path(name);
    std::fs::create_dir_all(&root).expect("create fixture root");
    let payload_path = root.join("payload.txt");
    let key_dir = root.join("keys");
    let qenc_path = root.join("payload.qenc");
    std::fs::write(&payload_path, b"split archive approval payload").expect("write payload");

    let keygen = Command::new(qvault_cli())
        .args([
            "--quiet",
            "keygen",
            "--out",
            key_dir.to_str().expect("utf8 key dir"),
        ])
        .output()
        .expect("run keygen");
    assert!(
        keygen.status.success(),
        "status: {:?}, stderr: {}",
        keygen.status,
        String::from_utf8_lossy(&keygen.stderr)
    );

    let encrypt = Command::new(qvault_cli())
        .args([
            "--quiet",
            "encrypt",
            payload_path.to_str().expect("utf8 payload path"),
            "--public-key",
            key_dir
                .join("publicKey.qkey")
                .to_str()
                .expect("utf8 public key path"),
            "--out",
            qenc_path.to_str().expect("utf8 qenc path"),
            "--filename",
            "payload.txt",
        ])
        .output()
        .expect("run encrypt");
    assert!(
        encrypt.status.success(),
        "status: {:?}, stderr: {}",
        encrypt.status,
        String::from_utf8_lossy(&encrypt.stderr)
    );

    (qenc_path, key_dir.join("privateKey.qkey"))
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
    assert_no_secret_material(&stdout, &secret_key_file, parsed_secret.key_bytes());

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
fn sign_and_sig_verify_roundtrip_json_with_pinned_and_embedded_modes() {
    let (public_key_path, secret_key_path) = generate_test_signer("signer-sign");
    let payload_path = unique_temp_path("signed-payload.txt");
    let signature_path = unique_temp_path("signed-payload.qsig");
    std::fs::write(&payload_path, b"detached qsig payload").expect("write payload");

    let sign_output = Command::new(qvault_cli())
        .args([
            "--json",
            "sign",
            payload_path.to_str().expect("utf8 payload path"),
            "--secret-key",
            secret_key_path.to_str().expect("utf8 secret key path"),
            "--out",
            signature_path.to_str().expect("utf8 signature path"),
            "--target",
            "bytes",
            "--filename",
            "payload.txt",
            "--created-at",
            "2026-05-28T12:34:56+02:00",
        ])
        .output()
        .expect("run qvault-cli sign");

    assert!(
        sign_output.status.success(),
        "status: {:?}, stderr: {}",
        sign_output.status,
        String::from_utf8_lossy(&sign_output.stderr)
    );
    let sign_stdout = String::from_utf8(sign_output.stdout).expect("utf8 sign stdout");
    let sign_json: Value = serde_json::from_str(&sign_stdout).expect("sign JSON");
    assert_eq!(sign_json["command"], "sign");
    assert_eq!(sign_json["ok"], true);
    assert_eq!(sign_json["suite"], "mldsa-44");
    assert_eq!(sign_json["target"]["type"], "bytes");
    assert_eq!(sign_json["displayMetadata"]["filename"], "payload.txt");
    assert_eq!(sign_json["displayMetadata"]["filesize"], 21);
    assert_eq!(
        sign_json["displayMetadata"]["createdAt"],
        "2026-05-28T10:34:56.000Z"
    );
    assert_eq!(
        sign_json["signerFingerprintHex"]
            .as_str()
            .expect("fingerprint hex")
            .len(),
        64
    );
    let secret_key_file = std::fs::read(&secret_key_path).expect("read secret key");
    let parsed_secret = unpack_secret_key_file(&secret_key_file).expect("parse pqsk");
    assert_no_secret_material(&sign_stdout, &secret_key_file, parsed_secret.key_bytes());
    for forbidden_field in [
        "privateKeyDigestHex",
        "secretKeyDigestHex",
        "privateKeyBase64",
        "secretKeyBase64",
        "secretKeyBytes",
        "seed",
    ] {
        assert!(
            sign_json.get(forbidden_field).is_none(),
            "{forbidden_field} must not be emitted"
        );
    }
    assert!(signature_path.exists());

    let pinned_verify = Command::new(qvault_cli())
        .args([
            "--json",
            "sig-verify",
            payload_path.to_str().expect("utf8 payload path"),
            "--sig",
            signature_path.to_str().expect("utf8 signature path"),
            "--pqpk",
            public_key_path.to_str().expect("utf8 public key path"),
        ])
        .output()
        .expect("run qvault-cli sig-verify pinned");
    assert!(
        pinned_verify.status.success(),
        "status: {:?}, stderr: {}",
        pinned_verify.status,
        String::from_utf8_lossy(&pinned_verify.stderr)
    );
    let pinned_json: Value =
        serde_json::from_slice(&pinned_verify.stdout).expect("pinned verify JSON");
    assert_eq!(pinned_json["command"], "sig-verify");
    assert_eq!(pinned_json["ok"], true);
    assert_eq!(pinned_json["cryptographicOk"], true);
    assert_eq!(pinned_json["trusted"], true);
    assert_eq!(pinned_json["trustSource"], "loaded-pqpk");
    assert_eq!(pinned_json["reasonCode"], "VERIFIED_WITH_PQPK");
    assert_eq!(pinned_json["verification"]["userPinned"], true);
    assert_eq!(pinned_json["verification"]["bundlePinned"], false);
    assert_eq!(pinned_json["verification"]["keySource"], "user-pqpk");
    assert_eq!(pinned_json["lifecyclePolicyEvaluated"], false);
    assert_eq!(pinned_json["countedForLifecyclePolicy"], false);

    let embedded_verify = Command::new(qvault_cli())
        .args([
            "--json",
            "sig-verify",
            payload_path.to_str().expect("utf8 payload path"),
            "--sig",
            signature_path.to_str().expect("utf8 signature path"),
        ])
        .output()
        .expect("run qvault-cli sig-verify embedded");
    assert!(
        embedded_verify.status.success(),
        "status: {:?}, stderr: {}",
        embedded_verify.status,
        String::from_utf8_lossy(&embedded_verify.stderr)
    );
    let embedded_json: Value =
        serde_json::from_slice(&embedded_verify.stdout).expect("embedded verify JSON");
    assert_eq!(embedded_json["ok"], true);
    assert_eq!(embedded_json["cryptographicOk"], true);
    assert_eq!(embedded_json["trusted"], false);
    assert_eq!(embedded_json["trustSource"], "embedded-only");
    assert_eq!(
        embedded_json["reasonCode"],
        "VERIFIED_EMBEDDED_KEY_UNPINNED"
    );
}

#[test]
fn sig_verify_rejects_target_digest_mismatch_and_wrong_pqpk_distinctly() {
    let (public_key_path, secret_key_path) = generate_test_signer("signer-good");
    let (wrong_public_key_path, _) = generate_test_signer("signer-wrong");
    let payload_path = unique_temp_path("verify-payload.txt");
    let tampered_payload_path = unique_temp_path("verify-payload-tampered.txt");
    let signature_path = unique_temp_path("verify-payload.qsig");
    std::fs::write(&payload_path, b"payload before tamper").expect("write payload");
    std::fs::write(&tampered_payload_path, b"payload after tamper").expect("write tampered");

    let sign_output = Command::new(qvault_cli())
        .args([
            "--quiet",
            "sign",
            payload_path.to_str().expect("utf8 payload path"),
            "--secret-key",
            secret_key_path.to_str().expect("utf8 secret key path"),
            "--out",
            signature_path.to_str().expect("utf8 signature path"),
        ])
        .output()
        .expect("run qvault-cli sign");
    assert!(
        sign_output.status.success(),
        "status: {:?}, stderr: {}",
        sign_output.status,
        String::from_utf8_lossy(&sign_output.stderr)
    );

    let tampered_verify = Command::new(qvault_cli())
        .args([
            "--json",
            "sig-verify",
            tampered_payload_path.to_str().expect("utf8 tampered path"),
            "--sig",
            signature_path.to_str().expect("utf8 signature path"),
            "--pqpk",
            public_key_path.to_str().expect("utf8 public key path"),
        ])
        .output()
        .expect("run tampered sig-verify");
    assert!(!tampered_verify.status.success(), "tamper should fail");
    let tampered_json: Value =
        serde_json::from_slice(&tampered_verify.stdout).expect("tampered verify JSON");
    assert_eq!(tampered_json["ok"], false);
    assert_eq!(tampered_json["cryptographicOk"], false);
    assert_eq!(tampered_json["reasonCode"], "TARGET_DIGEST_MISMATCH");

    let wrong_key_verify = Command::new(qvault_cli())
        .args([
            "--json",
            "sig-verify",
            payload_path.to_str().expect("utf8 payload path"),
            "--sig",
            signature_path.to_str().expect("utf8 signature path"),
            "--pqpk",
            wrong_public_key_path
                .to_str()
                .expect("utf8 wrong public key path"),
        ])
        .output()
        .expect("run wrong-key sig-verify");
    assert!(!wrong_key_verify.status.success(), "wrong pqpk should fail");
    let wrong_key_json: Value =
        serde_json::from_slice(&wrong_key_verify.stdout).expect("wrong-key verify JSON");
    assert_eq!(wrong_key_json["ok"], false);
    assert_eq!(wrong_key_json["cryptographicOk"], false);
    assert_eq!(wrong_key_json["reasonCode"], "PQPK_VERIFICATION_FAILED");
    assert_eq!(wrong_key_json["trustSource"], "loaded-pqpk-failed");
}

#[test]
fn sign_lifecycle_target_rejects_noncanonical_archive_state_without_output() {
    let (_, secret_key_path) = generate_test_signer("signer-lifecycle");
    let canonical = std::fs::read(core_fixture(
        "schema/fixtures/qv-archive-state-descriptor-v1.valid.json",
    ))
    .expect("read archive-state fixture");
    let noncanonical_path = unique_temp_path("archive-state-pretty.json");
    let signature_path = unique_temp_path("archive-state.qsig");
    let mut noncanonical = canonical;
    noncanonical.push(b'\n');
    std::fs::write(&noncanonical_path, noncanonical).expect("write noncanonical archive state");

    let output = Command::new(qvault_cli())
        .args([
            "--json",
            "sign",
            noncanonical_path.to_str().expect("utf8 archive path"),
            "--secret-key",
            secret_key_path.to_str().expect("utf8 secret key path"),
            "--out",
            signature_path.to_str().expect("utf8 signature path"),
            "--target",
            "archive-state",
        ])
        .output()
        .expect("run noncanonical lifecycle sign");

    assert!(!output.status.success(), "noncanonical target should fail");
    assert!(
        !signature_path.exists(),
        "signature must not be created for noncanonical lifecycle target"
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("error JSON");
    assert_eq!(value["command"], "sign");
    assert_eq!(value["ok"], false);
    assert_eq!(value["qvCode"], "FORMAT_POLICY_REJECT");
    assert!(value["error"]
        .as_str()
        .expect("error text")
        .contains("archive-state signing target must be canonical"));
}

#[test]
fn encrypt_source_evidence_key_writes_signed_canonical_artifacts_and_attaches() {
    let root = unique_temp_path("encrypt-source-evidence");
    std::fs::create_dir_all(&root).expect("create test root");
    let payload_path = root.join("source.pdf");
    let qenc_path = root.join("source.pdf.qenc");
    let source_evidence_path = append_file_name_suffix(&qenc_path, ".source-evidence.json");
    let source_evidence_sig_path =
        append_file_name_suffix(&qenc_path, ".source-evidence.json.qsig");
    let source_evidence_pqpk_path = append_file_name_suffix(&qenc_path, ".source-evidence.pqpk");
    let plaintext = b"source evidence plaintext bytes\nwith stable digest coverage";
    std::fs::write(&payload_path, plaintext).expect("write source payload");
    let key_dir = generate_test_encryption_keys("encrypt-source-evidence-keys");
    let (signer_public_key_path, signer_secret_key_path) =
        generate_test_signer("encrypt-source-evidence-signer");
    assert!(signer_public_key_path.exists());

    let output = Command::new(qvault_cli())
        .args([
            "--json",
            "encrypt",
            payload_path.to_str().expect("utf8 payload path"),
            "--public-key",
            key_dir
                .join("publicKey.qkey")
                .to_str()
                .expect("utf8 public key path"),
            "--out",
            qenc_path.to_str().expect("utf8 qenc path"),
            "--filename",
            "source.pdf",
            "--source-evidence-key",
            signer_secret_key_path
                .to_str()
                .expect("utf8 signer secret path"),
        ])
        .output()
        .expect("run encrypt with source evidence");

    assert!(
        output.status.success(),
        "status: {:?}, stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 encrypt stdout");
    let encrypt_json: Value = serde_json::from_str(&stdout).expect("encrypt JSON");
    assert_eq!(encrypt_json["command"], "encrypt");
    assert_eq!(encrypt_json["ok"], true);
    assert_eq!(
        encrypt_json["sourceEvidence"]["sourceEvidencePath"],
        source_evidence_path
            .to_str()
            .expect("utf8 source evidence path")
    );
    assert_eq!(
        encrypt_json["sourceEvidence"]["signaturePath"],
        source_evidence_sig_path
            .to_str()
            .expect("utf8 source evidence signature path")
    );
    assert_eq!(
        encrypt_json["sourceEvidence"]["publicKeyPath"],
        source_evidence_pqpk_path
            .to_str()
            .expect("utf8 source evidence pqpk path")
    );
    assert_eq!(encrypt_json["sourceEvidence"]["suite"], "mldsa-44");
    assert_eq!(
        encrypt_json["sourceEvidence"]["relationType"],
        "encrypted-source"
    );
    assert_eq!(encrypt_json["sourceEvidence"]["sourceObjectType"], "file");
    assert_eq!(
        encrypt_json["sourceEvidence"]["canonicalization"],
        "QV-JSON-RFC8785-v1"
    );

    let secret_key_file = std::fs::read(&signer_secret_key_path).expect("read pqsk");
    let parsed_secret = unpack_secret_key_file(&secret_key_file).expect("parse pqsk");
    assert_no_secret_material(&stdout, &secret_key_file, parsed_secret.key_bytes());
    for forbidden_field in [
        "sourceEvidenceKeyPath",
        "privateKeyDigestHex",
        "secretKeyDigestHex",
        "privateKeyBase64",
        "secretKeyBase64",
        "secretKeyBytes",
        "seed",
    ] {
        assert!(
            encrypt_json.get(forbidden_field).is_none(),
            "{forbidden_field} must not be emitted"
        );
        assert!(
            encrypt_json["sourceEvidence"]
                .get(forbidden_field)
                .is_none(),
            "sourceEvidence.{forbidden_field} must not be emitted"
        );
    }

    assert!(qenc_path.exists());
    assert!(source_evidence_path.exists());
    assert!(source_evidence_sig_path.exists());
    assert!(source_evidence_pqpk_path.exists());

    let source_evidence_bytes = std::fs::read(&source_evidence_path).expect("read source evidence");
    let canonical =
        parse_source_evidence_bytes(&source_evidence_bytes).expect("parse source evidence");
    assert_eq!(canonical.bytes, source_evidence_bytes);
    let source_digests = canonical
        .source_evidence
        .value
        .get("sourceDigests")
        .and_then(Value::as_array)
        .expect("source digests");
    assert_eq!(source_digests.len(), 2);
    assert_eq!(source_digests[0]["alg"], "SHA3-512");
    assert_eq!(source_digests[0]["value"], sha3_512_hex(plaintext));
    assert_eq!(source_digests[1]["alg"], "SHA-256");
    assert_eq!(source_digests[1]["value"], sha256_hex(plaintext));
    assert_eq!(
        encrypt_json["sourceEvidence"]["sourceDigests"],
        Value::Array(source_digests.clone())
    );

    let sig_verify = Command::new(qvault_cli())
        .args([
            "--json",
            "sig-verify",
            source_evidence_path
                .to_str()
                .expect("utf8 source evidence path"),
            "--sig",
            source_evidence_sig_path
                .to_str()
                .expect("utf8 source evidence signature path"),
            "--pqpk",
            source_evidence_pqpk_path
                .to_str()
                .expect("utf8 source evidence pqpk path"),
        ])
        .output()
        .expect("run sig-verify for source evidence");
    assert!(
        sig_verify.status.success(),
        "status: {:?}, stderr: {}",
        sig_verify.status,
        String::from_utf8_lossy(&sig_verify.stderr)
    );
    let sig_verify_json: Value =
        serde_json::from_slice(&sig_verify.stdout).expect("source evidence sig-verify JSON");
    assert_eq!(sig_verify_json["ok"], true);
    assert_eq!(sig_verify_json["trusted"], true);

    let split_dir = root.join("split");
    let split = Command::new(qvault_cli())
        .args([
            "--json",
            "split",
            qenc_path.to_str().expect("utf8 qenc path"),
            "--private-key",
            key_dir
                .join("privateKey.qkey")
                .to_str()
                .expect("utf8 private key path"),
            "--n",
            "5",
            "--k",
            "3",
            "--out",
            split_dir.to_str().expect("utf8 split dir"),
            "--auth-policy-level",
            "strong-pq-signature",
            "--min-valid-signatures",
            "1",
        ])
        .output()
        .expect("run split for source evidence attach");
    assert!(
        split.status.success(),
        "status: {:?}, stderr: {}",
        split.status,
        String::from_utf8_lossy(&split.stderr)
    );

    let lifecycle_bundle_path = split_dir.join("source.pdf.lifecycle-bundle.json");
    let attached_bundle_path = root.join("source-approved.lifecycle-bundle.json");
    let attached_shards_dir = root.join("source-approved-shards");
    let shard_paths = (1..=5)
        .map(|index| split_dir.join(format!("source.pdf.part{index}-of-5.qcont")))
        .collect::<Vec<_>>();
    let mut attach_args = vec![
        "--json".to_string(),
        "attach".to_string(),
        "--shards".to_string(),
    ];
    attach_args.extend(
        shard_paths
            .iter()
            .map(|path| path.to_str().expect("utf8 shard path").to_string()),
    );
    attach_args.extend([
        "--bundle".to_string(),
        lifecycle_bundle_path
            .to_str()
            .expect("utf8 lifecycle bundle path")
            .to_string(),
        "--source-evidence".to_string(),
        source_evidence_path
            .to_str()
            .expect("utf8 source evidence path")
            .to_string(),
        "--source-evidence-sig".to_string(),
        source_evidence_sig_path
            .to_str()
            .expect("utf8 source evidence signature path")
            .to_string(),
        "--pqpk".to_string(),
        source_evidence_pqpk_path
            .to_str()
            .expect("utf8 source evidence pqpk path")
            .to_string(),
        "--out-bundle".to_string(),
        attached_bundle_path
            .to_str()
            .expect("utf8 attached bundle path")
            .to_string(),
        "--out-shards".to_string(),
        attached_shards_dir
            .to_str()
            .expect("utf8 attached shards dir")
            .to_string(),
    ]);
    let attach = Command::new(qvault_cli())
        .args(&attach_args)
        .output()
        .expect("run attach source evidence");
    assert!(
        attach.status.success(),
        "status: {:?}, stderr: {}",
        attach.status,
        String::from_utf8_lossy(&attach.stderr)
    );

    let verify = Command::new(qvault_cli())
        .args([
            "--json",
            "verify",
            split_dir
                .join("source.pdf.archive-state.json")
                .to_str()
                .expect("utf8 archive state path"),
            "--bundle",
            attached_bundle_path
                .to_str()
                .expect("utf8 attached bundle path"),
        ])
        .output()
        .expect("run verify attached source evidence");
    assert!(
        !verify.status.success(),
        "source-evidence signatures must not satisfy strong archive approval policy"
    );
    let verify_json: Value = serde_json::from_slice(&verify.stdout).expect("verify JSON");
    assert_eq!(verify_json["ok"], false);
    assert_eq!(verify_json["policy"]["satisfied"], false);
    assert_eq!(
        verify_json["verification"]["counts"]["validArchiveApproval"],
        0
    );
    assert_eq!(
        verify_json["verification"]["counts"]["validSourceEvidence"],
        1
    );
    assert_eq!(verify_json["status"]["sourceEvidencePresent"], true);
    assert_eq!(
        verify_json["status"]["sourceEvidenceSignatureVerified"],
        true
    );
    assert_eq!(
        verify_json["sourceEvidenceReport"]["verifiedSourceEvidenceSignatureCount"],
        1
    );
}

#[test]
fn encrypt_source_evidence_invalid_pqsk_fails_before_outputs() {
    let root = unique_temp_path("encrypt-source-evidence-bad-pqsk");
    std::fs::create_dir_all(&root).expect("create test root");
    let payload_path = root.join("source.txt");
    let qenc_path = root.join("source.qenc");
    let bad_pqsk_path = root.join("bad.pqsk");
    std::fs::write(&payload_path, b"plaintext").expect("write payload");
    std::fs::write(&bad_pqsk_path, b"not-a-pqsk").expect("write bad pqsk");
    let key_dir = generate_test_encryption_keys("encrypt-source-evidence-bad-pqsk-keys");

    let output = Command::new(qvault_cli())
        .args([
            "--json",
            "encrypt",
            payload_path.to_str().expect("utf8 payload path"),
            "--public-key",
            key_dir
                .join("publicKey.qkey")
                .to_str()
                .expect("utf8 public key path"),
            "--out",
            qenc_path.to_str().expect("utf8 qenc path"),
            "--source-evidence-key",
            bad_pqsk_path.to_str().expect("utf8 bad pqsk path"),
        ])
        .output()
        .expect("run encrypt with bad source-evidence key");

    assert!(!output.status.success(), "bad pqsk should fail");
    let value: Value = serde_json::from_slice(&output.stdout).expect("error JSON");
    assert_eq!(value["command"], "encrypt");
    assert_eq!(value["ok"], false);
    assert_eq!(value["qvCode"], "FORMAT_POLICY_REJECT");
    assert!(!qenc_path.exists());
    assert!(!append_file_name_suffix(&qenc_path, ".source-evidence.json").exists());
    assert!(!append_file_name_suffix(&qenc_path, ".source-evidence.json.qsig").exists());
    assert!(!append_file_name_suffix(&qenc_path, ".source-evidence.pqpk").exists());
}

#[test]
fn encrypt_source_evidence_preflight_rejects_existing_output_before_qenc_write() {
    let root = unique_temp_path("encrypt-source-evidence-existing");
    std::fs::create_dir_all(&root).expect("create test root");
    let payload_path = root.join("source.txt");
    let qenc_path = root.join("source.qenc");
    let existing_source_evidence_path = root.join("existing-source-evidence.json");
    std::fs::write(&payload_path, b"plaintext").expect("write payload");
    std::fs::write(&existing_source_evidence_path, b"existing").expect("write existing output");
    let key_dir = generate_test_encryption_keys("encrypt-source-evidence-existing-keys");
    let (_, signer_secret_key_path) =
        generate_test_signer("encrypt-source-evidence-existing-signer");

    let output = Command::new(qvault_cli())
        .args([
            "--json",
            "encrypt",
            payload_path.to_str().expect("utf8 payload path"),
            "--public-key",
            key_dir
                .join("publicKey.qkey")
                .to_str()
                .expect("utf8 public key path"),
            "--out",
            qenc_path.to_str().expect("utf8 qenc path"),
            "--source-evidence-key",
            signer_secret_key_path
                .to_str()
                .expect("utf8 signer secret path"),
            "--source-evidence-out",
            existing_source_evidence_path
                .to_str()
                .expect("utf8 existing evidence path"),
        ])
        .output()
        .expect("run encrypt with existing source evidence output");

    assert!(!output.status.success(), "existing output should fail");
    let value: Value = serde_json::from_slice(&output.stdout).expect("error JSON");
    assert_eq!(value["command"], "encrypt");
    assert_eq!(value["ok"], false);
    assert_eq!(value["qvCode"], "USAGE");
    assert_eq!(
        std::fs::read(&existing_source_evidence_path).expect("read existing output"),
        b"existing"
    );
    assert!(!qenc_path.exists());
    assert!(!append_file_name_suffix(&qenc_path, ".source-evidence.json.qsig").exists());
    assert!(!append_file_name_suffix(&qenc_path, ".source-evidence.pqpk").exists());
}

#[test]
fn encrypt_source_evidence_output_flags_require_key_before_input_reads() {
    let root = unique_temp_path("encrypt-source-evidence-no-key");
    std::fs::create_dir_all(&root).expect("create test root");
    let qenc_path = root.join("source.qenc");
    let evidence_path = root.join("source-evidence.json");

    let output = Command::new(qvault_cli())
        .args([
            "--json",
            "encrypt",
            root.join("missing-source.txt")
                .to_str()
                .expect("utf8 missing source path"),
            "--public-key",
            root.join("missing-public.qkey")
                .to_str()
                .expect("utf8 missing public key path"),
            "--out",
            qenc_path.to_str().expect("utf8 qenc path"),
            "--source-evidence-out",
            evidence_path.to_str().expect("utf8 evidence path"),
        ])
        .output()
        .expect("run encrypt with source-evidence output flag but no key");

    assert!(
        !output.status.success(),
        "missing source-evidence key should fail"
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("error JSON");
    assert_eq!(value["command"], "encrypt");
    assert_eq!(value["ok"], false);
    assert_eq!(value["qvCode"], "USAGE");
    assert!(value["error"]
        .as_str()
        .expect("error text")
        .contains("requires --source-evidence-key"));
    assert!(!qenc_path.exists());
    assert!(!evidence_path.exists());
}

#[test]
fn split_archive_approval_key_embeds_qsig_and_satisfies_verify_restore() {
    let (qenc_path, private_key_path) = create_encrypted_payload_fixture("signed-split");
    let (signer_public_key_path, signer_secret_key_path) = {
        let out_prefix = qenc_path.parent().expect("fixture parent").join("signer");
        let public_key_path = append_file_name_suffix(&out_prefix, ".pqpk");
        let secret_key_path = append_file_name_suffix(&out_prefix, ".pqsk");
        let output = Command::new(qvault_cli())
            .args([
                "--quiet",
                "signer-keygen",
                "--suite",
                "mldsa-87",
                "--out",
                out_prefix.to_str().expect("utf8 signer prefix"),
            ])
            .output()
            .expect("run signer-keygen");
        assert!(
            output.status.success(),
            "status: {:?}, stderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        (public_key_path, secret_key_path)
    };
    assert!(signer_public_key_path.exists());

    let out_dir = qenc_path
        .parent()
        .expect("fixture parent")
        .join("signed-shards");
    let split = Command::new(qvault_cli())
        .args([
            "--json",
            "split",
            qenc_path.to_str().expect("utf8 qenc path"),
            "--private-key",
            private_key_path.to_str().expect("utf8 private key path"),
            "--n",
            "5",
            "--k",
            "3",
            "--out",
            out_dir.to_str().expect("utf8 out dir"),
            "--auth-policy-level",
            "strong-pq-signature",
            "--min-valid-signatures",
            "1",
            "--archive-approval-key",
            signer_secret_key_path
                .to_str()
                .expect("utf8 signer secret path"),
        ])
        .output()
        .expect("run signed split");
    assert!(
        split.status.success(),
        "status: {:?}, stderr: {}",
        split.status,
        String::from_utf8_lossy(&split.stderr)
    );
    let split_json: Value = serde_json::from_slice(&split.stdout).expect("split JSON");
    assert_eq!(split_json["command"], "split");
    assert_eq!(split_json["ok"], true);
    assert_eq!(split_json["archiveApproval"]["signed"], true);
    assert_eq!(split_json["archiveApproval"]["suite"], "mldsa-87");
    assert_eq!(split_json["archiveApproval"]["strongPq"], true);
    assert_eq!(split_json["archiveApproval"]["signatureEmbedded"], true);
    assert_eq!(split_json["archiveApproval"]["publicKeyFileEmbedded"], true);
    assert_ne!(
        split_json["lifecycleBundleDigestHex"],
        split_json["unsignedLifecycleBundleDigestHex"]
    );

    let archive_state_path = out_dir.join("payload.archive-state.json");
    let lifecycle_bundle_path = out_dir.join("payload.lifecycle-bundle.json");
    let lifecycle_bundle: Value = serde_json::from_slice(
        &std::fs::read(&lifecycle_bundle_path).expect("read lifecycle bundle"),
    )
    .expect("lifecycle bundle JSON");
    assert!(!lifecycle_bundle["attachments"]["publicKeys"]
        .as_array()
        .expect("public keys")
        .is_empty());
    assert!(
        !lifecycle_bundle["attachments"]["archiveApprovalSignatures"]
            .as_array()
            .expect("archive approval signatures")
            .is_empty()
    );

    let shard_paths = (1..=5)
        .map(|index| out_dir.join(format!("payload.part{index}-of-5.qcont")))
        .collect::<Vec<_>>();
    let first_shard =
        parse_qvqcont7_shard(&std::fs::read(&shard_paths[0]).expect("read first signed shard"))
            .expect("parse signed shard");
    assert_eq!(
        first_shard.lifecycle_bundle_digest_hex,
        split_json["lifecycleBundleDigestHex"]
            .as_str()
            .expect("lifecycle digest")
    );

    // Without an external signer pin the bundle-embedded key is not a trust
    // anchor: cryptographically verified, but archive policy must NOT be
    // satisfied (oracle parity; see F2 fix in successor_policy.rs).
    let verify_unpinned = Command::new(qvault_cli())
        .args([
            "--json",
            "verify",
            archive_state_path
                .to_str()
                .expect("utf8 archive state path"),
            "--bundle",
            lifecycle_bundle_path
                .to_str()
                .expect("utf8 lifecycle bundle path"),
        ])
        .output()
        .expect("run unpinned verify for signed split");
    let verify_unpinned_json: Value =
        serde_json::from_slice(&verify_unpinned.stdout).expect("unpinned verify JSON");
    assert_eq!(
        verify_unpinned_json["policy"]["satisfied"], false,
        "bundle-embedded key alone must not satisfy archive policy"
    );

    // Supplying the signer public key as an external pin authorizes policy.
    let verify = Command::new(qvault_cli())
        .args([
            "--json",
            "verify",
            archive_state_path
                .to_str()
                .expect("utf8 archive state path"),
            "--bundle",
            lifecycle_bundle_path
                .to_str()
                .expect("utf8 lifecycle bundle path"),
            "--pqpk",
            signer_public_key_path
                .to_str()
                .expect("utf8 signer public key path"),
            "--required-policy-level",
            "strong-pq-signature",
        ])
        .output()
        .expect("run verify for signed split");
    assert!(
        verify.status.success(),
        "status: {:?}, stderr: {}",
        verify.status,
        String::from_utf8_lossy(&verify.stderr)
    );
    let verify_json: Value = serde_json::from_slice(&verify.stdout).expect("verify JSON");
    assert_eq!(verify_json["ok"], true);
    assert_eq!(verify_json["policy"]["satisfied"], true);
    assert_eq!(verify_json["status"]["strongPqSignatureVerified"], true);

    let mut restore_args = vec![
        "--json".to_string(),
        "restore".to_string(),
        "--bundle".to_string(),
        lifecycle_bundle_path
            .to_str()
            .expect("utf8 lifecycle bundle path")
            .to_string(),
        "--pqpk".to_string(),
        signer_public_key_path
            .to_str()
            .expect("utf8 signer public key path")
            .to_string(),
        "--dry-run".to_string(),
    ];
    restore_args.extend(
        shard_paths
            .iter()
            .map(|path| path.to_str().expect("utf8 shard path").to_string()),
    );
    let restore = Command::new(qvault_cli())
        .args(&restore_args)
        .output()
        .expect("run restore dry-run for signed split");
    assert!(
        restore.status.success(),
        "status: {:?}, stderr: {}",
        restore.status,
        String::from_utf8_lossy(&restore.stderr)
    );
    let restore_json: Value = serde_json::from_slice(&restore.stdout).expect("restore JSON");
    assert_eq!(restore_json["ok"], true);
    assert_eq!(restore_json["dryRun"], true);
    assert_eq!(restore_json["authenticity"]["policy"]["satisfied"], true);
}

#[test]
fn split_archive_approval_key_failure_writes_no_split_outputs() {
    let (qenc_path, private_key_path) = create_encrypted_payload_fixture("signed-split-bad-key");
    let bad_signer_key_path = qenc_path.parent().expect("fixture parent").join("bad.pqsk");
    let out_dir = qenc_path
        .parent()
        .expect("fixture parent")
        .join("bad-signed-shards");
    std::fs::write(&bad_signer_key_path, b"not-a-pqsk").expect("write bad pqsk");

    let output = Command::new(qvault_cli())
        .args([
            "--json",
            "split",
            qenc_path.to_str().expect("utf8 qenc path"),
            "--private-key",
            private_key_path.to_str().expect("utf8 private key path"),
            "--n",
            "5",
            "--k",
            "3",
            "--out",
            out_dir.to_str().expect("utf8 out dir"),
            "--auth-policy-level",
            "strong-pq-signature",
            "--min-valid-signatures",
            "1",
            "--archive-approval-key",
            bad_signer_key_path
                .to_str()
                .expect("utf8 bad signer key path"),
        ])
        .output()
        .expect("run signed split with bad key");

    assert!(!output.status.success(), "bad signing key should fail");
    assert!(
        !out_dir.exists(),
        "split output directory must not be created after signing-key failure"
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("error JSON");
    assert_eq!(value["command"], "split");
    assert_eq!(value["ok"], false);
    assert_eq!(value["qvCode"], "FORMAT_POLICY_REJECT");
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

#[test]
fn malformed_qenc_geometry_emits_format_policy_exit_status() {
    let qenc_path = unique_temp_path("truncated.qenc");
    let mut qenc = std::fs::read(core_fixture("qenc_interop/single-small/container.qenc"))
        .expect("read qenc fixture");
    qenc.pop();
    std::fs::write(&qenc_path, qenc).expect("write malformed qenc");
    let output_path = unique_temp_path("must-not-exist.bin");

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
        .expect("run qvault-cli decrypt with malformed geometry");

    assert_eq!(output.status.code(), Some(4), "status: {:?}", output.status);
    let value: Value = serde_json::from_slice(&output.stdout).expect("error JSON");
    assert_eq!(value["qvCode"], "FORMAT_POLICY_REJECT");
    assert!(value["error"]
        .as_str()
        .expect("error string")
        .contains("authenticated geometry"));
    assert!(!output_path.exists());
}

#[test]
fn restore_rejects_identical_secret_and_container_outputs_before_input_io() {
    let output_path = unique_temp_path("same-restore-output");
    let missing_shard = unique_temp_path("missing.qcont");
    let output = Command::new(qvault_cli())
        .args([
            "--json",
            "restore",
            "--output-qenc",
            output_path.to_str().expect("utf8 output path"),
            "--output-secret-key",
            output_path.to_str().expect("utf8 output path"),
            missing_shard.to_str().expect("utf8 missing shard path"),
        ])
        .output()
        .expect("run restore with colliding outputs");

    assert_eq!(output.status.code(), Some(2), "status: {:?}", output.status);
    let value: Value = serde_json::from_slice(&output.stdout).expect("error JSON");
    assert_eq!(value["qvCode"], "USAGE");
    assert!(value["error"]
        .as_str()
        .expect("error string")
        .contains("must be distinct"));
    assert!(!output_path.exists());
}

#[test]
fn selector_arguments_require_exact_lowercase_hex() {
    let output = Command::new(qvault_cli())
        .args([
            "--json",
            "restore",
            "--archive-id",
            &"AA".repeat(32),
            "missing.qcont",
        ])
        .output()
        .expect("run restore with uppercase selector");
    assert_eq!(output.status.code(), Some(2));
    let value: Value = serde_json::from_slice(&output.stdout).expect("error JSON");
    assert_eq!(value["qvCode"], "USAGE");
    assert!(value["error"]
        .as_str()
        .expect("error string")
        .contains("lowercase hex"));
}

#[test]
fn selftest_rejects_filters_that_match_no_checks() {
    let output = Command::new(qvault_cli())
        .args(["--json", "selftest", "--filter", "definitely-unknown"])
        .output()
        .expect("run filtered selftest");
    assert_eq!(output.status.code(), Some(2));
    let value: Value = serde_json::from_slice(&output.stdout).expect("error JSON");
    assert_eq!(value["ok"], false);
    assert_eq!(value["qvCode"], "USAGE");
}

#[cfg(unix)]
#[test]
fn decrypted_plaintext_is_written_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let (qenc_path, private_key_path) = create_encrypted_payload_fixture("secret-plaintext-mode");
    let plaintext_path = qenc_path
        .parent()
        .expect("fixture parent")
        .join("restored-plaintext.txt");
    let output = Command::new(qvault_cli())
        .args([
            "--quiet",
            "decrypt",
            qenc_path.to_str().expect("utf8 qenc path"),
            "--private-key",
            private_key_path.to_str().expect("utf8 private key path"),
            "--out",
            plaintext_path.to_str().expect("utf8 plaintext path"),
        ])
        .output()
        .expect("decrypt fixture");
    assert!(
        output.status.success(),
        "status: {:?}, stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::metadata(&plaintext_path)
            .expect("plaintext metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[cfg(unix)]
#[test]
fn json_error_reporting_is_panic_free_for_non_utf8_paths() {
    use std::os::unix::ffi::OsStringExt;

    let invalid_path =
        std::path::PathBuf::from(std::ffi::OsString::from_vec(b"missing-qenc-\xff".to_vec()));
    let output = Command::new(qvault_cli())
        .arg("--json")
        .arg("decrypt")
        .arg(&invalid_path)
        .arg("--private-key")
        .arg(core_fixture("qenc_interop/single-small/secret.qkey"))
        .arg("--out")
        .arg(unique_temp_path("non-utf8-output"))
        .output()
        .expect("run decrypt with non-UTF8 input path");

    assert!(!output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).expect("error JSON");
    assert_eq!(value["command"], "decrypt");
    assert_eq!(value["ok"], false);
}
