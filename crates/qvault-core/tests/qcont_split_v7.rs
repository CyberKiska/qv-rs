use anyhow::{Context, Result};
use qvault_core::auth::AuthPolicyLevel;
use qvault_core::lifecycle::{
    parse_archive_state_descriptor_bytes, parse_cohort_binding_bytes, parse_lifecycle_bundle_bytes,
};
use qvault_core::qcont::{
    build_qvqcont7_shards, parse_qvqcont7_shard, Qvqcont7BuildOptions, Qvqcont7BuildParams,
    LIFECYCLE_ARTIFACT_FAMILY, LIFECYCLE_QCONT_FORMAT_VERSION,
};
use serde_json::Value;

const QENC_BYTES: &[u8] = include_bytes!("data/split_v7/single-small.qenc");
const SECRET_KEY_BYTES: &[u8] = include_bytes!("data/split_v7/single-small.secret.qkey");

#[test]
fn split_v7_builds_successor_artifacts_and_parseable_shards() -> Result<()> {
    let built = build_fixture_split()?;
    assert_eq!(built.format_version, LIFECYCLE_QCONT_FORMAT_VERSION);
    assert_eq!(built.shards.len(), 5);

    parse_archive_state_descriptor_bytes(&built.archive_state_bytes)?;
    parse_cohort_binding_bytes(&built.cohort_binding_bytes)?;
    let bundle = parse_lifecycle_bundle_bytes(&built.lifecycle_bundle_bytes)?;
    assert_eq!(
        bundle.lifecycle_bundle.value["archiveStateDigest"]["value"],
        built.archive_state_digest_hex
    );
    assert_eq!(
        bundle.lifecycle_bundle.value["currentCohortBindingDigest"]["value"],
        built.cohort_binding_digest_hex
    );

    for (index, shard) in built.shards.iter().enumerate() {
        let parsed = parse_qvqcont7_shard(&shard.bytes)?;
        assert_eq!(parsed.shard_index, index as u16);
        assert_eq!(
            parsed.meta_json["artifactFamily"],
            LIFECYCLE_ARTIFACT_FAMILY
        );
        assert_eq!(
            parsed.meta_json["alg"]["fmt"],
            LIFECYCLE_QCONT_FORMAT_VERSION
        );
        assert_eq!(parsed.meta_json["archiveId"], built.archive_id);
        assert_eq!(parsed.meta_json["stateId"], built.state_id);
        assert_eq!(parsed.meta_json["cohortId"], built.cohort_id);
        assert!(parsed.meta_json.get("manifestDigest").is_none());
        assert!(parsed.meta_json.get("bundleDigest").is_none());
        assert_eq!(parsed.archive_state_bytes, built.archive_state_bytes);
        assert_eq!(parsed.cohort_binding_bytes, built.cohort_binding_bytes);
        assert_eq!(parsed.lifecycle_bundle_bytes, built.lifecycle_bundle_bytes);
    }
    Ok(())
}

#[test]
fn split_v7_archive_state_matches_js_successor_fixture() -> Result<()> {
    let built = build_fixture_split()?;
    let expected: Value = serde_json::from_str(include_str!(
        "data/split_v7/js-archive-state-single-small.json"
    ))?;
    let expected_bytes = expected["bytesUtf8"]
        .as_str()
        .context("bytesUtf8")?
        .as_bytes()
        .to_vec();
    assert_eq!(built.archive_id, expected["archiveId"].as_str().unwrap());
    assert_eq!(built.state_id, expected["stateId"].as_str().unwrap());
    assert_eq!(
        built.archive_state_digest_hex,
        expected["digest"].as_str().unwrap()
    );
    assert_eq!(built.archive_state_bytes, expected_bytes);
    Ok(())
}

#[test]
fn split_v7_rejects_unsupported_odd_parity_tuple() {
    let error = build_qvqcont7_shards(
        QENC_BYTES,
        SECRET_KEY_BYTES,
        Qvqcont7BuildParams { n: 4, k: 3 },
        &Qvqcont7BuildOptions::default(),
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("parity must be even"),
        "unexpected error: {error}"
    );
}

fn build_fixture_split() -> Result<qvault_core::qcont::BuiltQvqcont7Shards> {
    build_qvqcont7_shards(
        QENC_BYTES,
        SECRET_KEY_BYTES,
        Qvqcont7BuildParams { n: 5, k: 3 },
        &Qvqcont7BuildOptions {
            archive_id: Some("31".repeat(32)),
            sss_random_bytes: Some(vec![0x42; 10_000]),
            auth_policy_level: Some(AuthPolicyLevel::IntegrityOnly),
            min_valid_signatures: Some(1),
            ..Qvqcont7BuildOptions::default()
        },
    )
    .map_err(Into::into)
}
