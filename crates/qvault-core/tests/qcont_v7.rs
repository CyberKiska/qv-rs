use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use qvault_core::hash::sha3_512_hex;
use qvault_core::qcont::{
    build_qvqcont7_shard, parse_qvqcont7_shard, LIFECYCLE_ARTIFACT_FAMILY,
    LIFECYCLE_QCONT_FORMAT_VERSION, LIFECYCLE_QCONT_MAGIC, LIFECYCLE_QCONT_MIN_HEADER_BYTES,
};
use serde_json::Value;

const CORPUS: &[(&str, &str)] = &[
    (
        "valid-roundtrip-shard.json",
        include_str!("data/qcont/valid-roundtrip-shard.json"),
    ),
    (
        "invalid-archive-state-digest-mismatch.json",
        include_str!("data/qcont/invalid-archive-state-digest-mismatch.json"),
    ),
    (
        "invalid-lifecycle-bundle-digest-mismatch.json",
        include_str!("data/qcont/invalid-lifecycle-bundle-digest-mismatch.json"),
    ),
    (
        "invalid-shardindex-mismatch.json",
        include_str!("data/qcont/invalid-shardindex-mismatch.json"),
    ),
    (
        "invalid-truncated-archive-state.json",
        include_str!("data/qcont/invalid-truncated-archive-state.json"),
    ),
    (
        "invalid-wrong-magic.json",
        include_str!("data/qcont/invalid-wrong-magic.json"),
    ),
];

#[test]
fn qcont_v7_schema_corpus_matches_oracle_expectations() -> Result<()> {
    for (name, raw_json) in CORPUS {
        let fixture: Value =
            serde_json::from_str(raw_json).with_context(|| format!("{name}: fixture JSON"))?;
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
            assert_expected_error(name, &error.to_string());
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

fn fixture_bytes(fixture: &Value) -> Result<Vec<u8>> {
    let encoding = fixture["encoding"].as_str().context("encoding")?;
    if encoding != "base64" {
        anyhow::bail!("unsupported fixture encoding {encoding}");
    }
    let encoded = fixture["bytes"].as_str().context("bytes")?;
    Ok(BASE64_STANDARD.decode(encoded)?)
}

fn assert_expected_error(name: &str, actual: &str) {
    let expected = match name {
        "invalid-archive-state-digest-mismatch.json" => "Embedded archive-state digest mismatch",
        "invalid-lifecycle-bundle-digest-mismatch.json" => {
            "Embedded lifecycle-bundle digest mismatch"
        }
        "invalid-shardindex-mismatch.json" => "Shard metadata shardIndex mismatch",
        "invalid-truncated-archive-state.json" => "Shard is truncated",
        "invalid-wrong-magic.json" => "Invalid .qcont magic",
        other => panic!("missing expected error assertion for {other}"),
    };
    assert!(
        actual.contains(expected),
        "{name}: expected error containing {expected:?}, got {actual}"
    );
}
