use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use qvault_core::hash::sha3_512_hex;
use qvault_core::qcont::{
    build_qvqcont7_shard, parse_qvqcont7_shard, LIFECYCLE_ARTIFACT_FAMILY,
    LIFECYCLE_QCONT_FORMAT_VERSION, LIFECYCLE_QCONT_MAGIC, LIFECYCLE_QCONT_MIN_HEADER_BYTES,
};
use serde_json::Value;

fn corpus_qcont_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/corpus/qcont")
}

fn fixture_bytes(fixture: &Value) -> Result<Vec<u8>> {
    let encoding = fixture["encoding"].as_str().context("encoding")?;
    if encoding != "base64" {
        anyhow::bail!("unsupported fixture encoding {encoding}");
    }
    let encoded = fixture["bytes"].as_str().context("bytes")?;
    Ok(BASE64_STANDARD.decode(encoded)?)
}

#[test]
fn qcont_v7_schema_corpus_matches_oracle_expectations() -> Result<()> {
    let mut entries = fs::read_dir(corpus_qcont_dir())?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".json") {
            continue;
        }
        let raw = fs::read(entry.path()).with_context(|| format!("read {name}"))?;
        let fixture: Value = serde_json::from_slice(&raw).with_context(|| format!("{name}: JSON"))?;
        let bytes = fixture_bytes(&fixture).with_context(|| format!("{name}: bytes"))?;
        assert_eq!(
            sha3_512_hex(&bytes),
            fixture["expectedDigest"]
                .as_str()
                .with_context(|| format!("{name}: expectedDigest"))?,
            "{name}: expected SHA3-512 digest"
        );

        let parsed = parse_qvqcont7_shard(&bytes);
        if fixture["valid"].as_bool().unwrap_or(false) {
            let shard = parsed.with_context(|| format!("{name}: expected parse success"))?;
            let expected = &fixture["runtime"]["expectedMetaJSON"];
            assert_eq!(
                shard.meta_json["archiveId"], expected["archiveId"],
                "{name}: archiveId"
            );
            assert_eq!(
                shard.meta_json["stateId"], expected["stateId"],
                "{name}: stateId"
            );
            assert_eq!(
                shard.meta_json["cohortId"], expected["cohortId"],
                "{name}: cohortId"
            );
            assert_eq!(
                shard.meta_json["shardIndex"], expected["shardIndex"],
                "{name}: shardIndex"
            );
            assert_eq!(
                shard.archive_state_digest_hex, shard.state_id,
                "{name}: stateId"
            );
            assert_eq!(
                shard.cohort_id,
                expected["cohortId"].as_str().context("cohortId")?,
                "{name}: derived cohortId"
            );
            assert_eq!(
                build_qvqcont7_shard(&shard)?,
                bytes,
                "{name}: writer roundtrip"
            );
        } else {
            let error = parsed.expect_err(&format!("{name}: expected parse failure"));
            let reason = fixture["rejectionReason"].as_str().unwrap_or_else(|| {
                panic!("{name}: invalid corpus fixture must include rejectionReason")
            });
            assert!(
                error.to_string().contains(reason),
                "{name}: expected error containing {reason:?}, got {error}"
            );
        }
    }
    Ok(())
}

#[test]
fn qcont_v7_rejects_predecessor_qvqcont6_format_identifier() -> Result<()> {
    let meta = serde_json::json!({
        "artifactFamily": LIFECYCLE_ARTIFACT_FAMILY,
        "alg": { "fmt": "QVqcont-6" }
    });
    let meta_bytes = serde_json::to_vec(&meta)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(LIFECYCLE_QCONT_MAGIC);
    bytes.extend_from_slice(&(meta_bytes.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&meta_bytes);
    bytes.resize(LIFECYCLE_QCONT_MIN_HEADER_BYTES, 0);

    let error = parse_qvqcont7_shard(&bytes).unwrap_err();
    assert!(
        error.to_string().contains(&format!(
            "Unsupported shard format: expected {LIFECYCLE_QCONT_FORMAT_VERSION}"
        )),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn qcont_v7_rejects_unknown_artifact_family() -> Result<()> {
    let meta = serde_json::json!({
        "artifactFamily": "legacy-manifest-v2",
        "alg": { "fmt": LIFECYCLE_QCONT_FORMAT_VERSION }
    });
    let meta_bytes = serde_json::to_vec(&meta)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(LIFECYCLE_QCONT_MAGIC);
    bytes.extend_from_slice(&(meta_bytes.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&meta_bytes);
    bytes.resize(LIFECYCLE_QCONT_MIN_HEADER_BYTES, 0);

    let error = parse_qvqcont7_shard(&bytes).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("Unsupported shard artifactFamily"),
        "unexpected error: {error}"
    );
    Ok(())
}
