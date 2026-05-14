use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use qvault_core::auth::{
    parse_open_timestamp_proof, resolve_open_timestamp_target, unpack_pqpk, unpack_qsig,
    verify_qsig_against_bytes, SignatureArtifact,
};
use qvault_core::hash::{sha256_hex, sha3_512_hex};
use serde_json::Value;

fn data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/corpus")
}

fn read_fixture(path: &Path) -> Result<Value> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn fixture_bytes(fixture: &Value) -> Result<Vec<u8>> {
    let encoding = fixture["encoding"].as_str().context("encoding")?;
    if encoding != "base64" {
        anyhow::bail!("unsupported fixture encoding {encoding}");
    }
    Ok(BASE64_STANDARD.decode(fixture["bytes"].as_str().context("bytes")?)?)
}

fn assert_fixture_digest(name: &str, fixture: &Value, bytes: &[u8]) -> Result<()> {
    assert_eq!(
        fixture["expectedDigestAlg"].as_str().unwrap_or("SHA3-512"),
        "SHA3-512",
        "{name}: expected digest algorithm"
    );
    assert_eq!(
        sha3_512_hex(bytes),
        fixture["expectedDigest"]
            .as_str()
            .context("expectedDigest")?,
        "{name}: SHA3-512 digest"
    );
    Ok(())
}

fn suite_name(suite_id: u8) -> &'static str {
    match suite_id {
        1 => "mldsa-44",
        2 => "mldsa-65",
        3 => "mldsa-87",
        0x11 => "slhdsa-shake-128s",
        0x12 => "slhdsa-shake-192s",
        0x13 => "slhdsa-shake-256s",
        0x14 => "slhdsa-shake-256f",
        _ => "unknown",
    }
}

#[test]
fn qsig_corpus_parses_and_verifies_like_oracle() -> Result<()> {
    let mut entries =
        fs::read_dir(data_dir().join("qsig"))?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        let name = entry.file_name().to_string_lossy().to_string();
        let fixture = read_fixture(&entry.path())?;
        let bytes = fixture_bytes(&fixture)?;
        assert_fixture_digest(&name, &fixture, &bytes)?;

        if fixture["valid"].as_bool().unwrap_or(false) {
            let parsed = unpack_qsig(&bytes).with_context(|| format!("{name}: unpack qsig"))?;
            assert_eq!(
                suite_name(parsed.suite_id),
                fixture["runtime"]["expectedSuite"]
                    .as_str()
                    .context("expectedSuite")?,
                "{name}: suite"
            );
            let message = BASE64_STANDARD.decode(
                fixture["runtime"]["messageBytes"]
                    .as_str()
                    .context("messageBytes")?,
            )?;
            let result = verify_qsig_against_bytes(&message, &bytes, None, None)
                .with_context(|| format!("{name}: verify qsig"))?;
            assert!(
                result.ok,
                "{name}: expected valid signature, got {:?}",
                result.error
            );
        } else if let Some(message) = fixture["runtime"]["messageBytes"].as_str() {
            let message = BASE64_STANDARD.decode(message)?;
            let result = verify_qsig_against_bytes(&message, &bytes, None, None)
                .with_context(|| format!("{name}: verify negative qsig"))?;
            assert!(
                !result.ok,
                "{name}: expected signature verification failure"
            );
        } else {
            let error = unpack_qsig(&bytes).expect_err(&format!("{name}: expected unpack failure"));
            if let Some(reason) = fixture["rejectionReason"].as_str() {
                assert!(
                    error.to_string().contains(reason),
                    "{name}: expected error containing {reason:?}, got {error}"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn pqpk_corpus_parses_or_rejects_like_oracle() -> Result<()> {
    let mut entries =
        fs::read_dir(data_dir().join("pqpk"))?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        let name = entry.file_name().to_string_lossy().to_string();
        let fixture = read_fixture(&entry.path())?;
        let bytes = fixture_bytes(&fixture)?;
        assert_fixture_digest(&name, &fixture, &bytes)?;

        if fixture["valid"].as_bool().unwrap_or(false) {
            let parsed = unpack_pqpk(&bytes).with_context(|| format!("{name}: unpack pqpk"))?;
            assert_eq!(
                parsed.suite_id,
                fixture["runtime"]["expectedSuiteId"]
                    .as_u64()
                    .context("expectedSuiteId")? as u8,
                "{name}: suiteId"
            );
            assert!(!parsed.key_bytes.is_empty(), "{name}: key bytes");
        } else {
            let error = unpack_pqpk(&bytes).expect_err(&format!("{name}: expected pqpk failure"));
            if let Some(reason) = fixture["rejectionReason"].as_str() {
                assert!(
                    error.to_string().contains(reason),
                    "{name}: expected error containing {reason:?}, got {error}"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn ots_corpus_links_only_to_exact_signature_digest() -> Result<()> {
    let mut entries = fs::read_dir(data_dir().join("ots"))?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        let name = entry.file_name().to_string_lossy().to_string();
        let fixture = read_fixture(&entry.path())?;
        let bytes = fixture_bytes(&fixture)?;
        assert_fixture_digest(&name, &fixture, &bytes)?;

        let parsed = parse_open_timestamp_proof(&bytes, Some(&name));
        if !fixture["valid"].as_bool().unwrap_or(false) && fixture["runtime"].is_null() {
            let error = parsed.expect_err(&format!("{name}: expected OTS parse failure"));
            if let Some(reason) = fixture["rejectionReason"].as_str() {
                assert!(
                    error.to_string().contains(reason),
                    "{name}: expected error containing {reason:?}, got {error}"
                );
            }
            continue;
        }

        let parsed = parsed.with_context(|| format!("{name}: parse OTS"))?;
        let signatures = fixture["runtime"]["signatures"]
            .as_array()
            .context("runtime.signatures")?
            .iter()
            .map(signature_artifact)
            .collect::<Result<Vec<_>>>()?;
        let linked = resolve_open_timestamp_target(&bytes, Some(&name), &signatures);
        if fixture["valid"].as_bool().unwrap_or(false) {
            let linked = linked.with_context(|| format!("{name}: resolve OTS"))?;
            assert_eq!(linked.stamped_digest_hex, parsed.stamped_digest_hex);
            assert!(linked.linked, "{name}: linked");
        } else {
            let error = linked.expect_err(&format!("{name}: expected OTS linkage failure"));
            if let Some(reason) = fixture["rejectionReason"].as_str() {
                assert!(
                    error.to_string().contains(reason),
                    "{name}: expected error containing {reason:?}, got {error}"
                );
            }
        }
    }
    Ok(())
}

fn signature_artifact(value: &Value) -> Result<SignatureArtifact> {
    let bytes = BASE64_STANDARD.decode(value["bytes"].as_str().context("signature bytes")?)?;
    Ok(SignatureArtifact {
        id: value["id"].as_str().unwrap_or("signature").to_string(),
        name: value["name"]
            .as_str()
            .unwrap_or("signature.qsig")
            .to_string(),
        source: "corpus".to_string(),
        format: "qsig".to_string(),
        signature_content_digest_hex: value["signatureContentDigestHex"]
            .as_str()
            .map(str::to_string),
        ots_stamped_digest_hex: Some(sha256_hex(&bytes)),
        bytes,
        ok: true,
    })
}
