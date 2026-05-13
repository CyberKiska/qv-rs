use anyhow::Result;
use qvault_core::auth::AuthPolicyLevel;
use qvault_core::lifecycle::{
    attach_lifecycle_bundle, parse_lifecycle_bundle_bytes, AttachLifecycleOptions,
    LifecycleSourceEvidenceImport,
};
use qvault_core::qcont::{
    build_qvqcont7_shards, parse_qvqcont7_shard, restore_qvqcont7_from_shards,
    Qvqcont7BuildOptions, Qvqcont7BuildParams, RestoreQvqcont7Options,
};
use serde_json::Value;

const QENC_BYTES: &[u8] = include_bytes!("data/split_v7/single-small.qenc");
const SECRET_KEY_BYTES: &[u8] = include_bytes!("data/split_v7/single-small.secret.qkey");
const SOURCE_EVIDENCE_JSON: &str =
    include_str!("data/schema/fixtures/qv-source-evidence-v1.valid.json");

#[test]
fn attach_lifecycle_source_evidence_without_mutating_identity_bytes() -> Result<()> {
    let built = build_fixture_split()?;
    let shards = parse_built_shards(&built)?;
    let source_evidence: Value = serde_json::from_str(SOURCE_EVIDENCE_JSON)?;

    let attached = attach_lifecycle_bundle(
        &shards,
        &AttachLifecycleOptions {
            source_evidence: vec![LifecycleSourceEvidenceImport {
                bytes: None,
                value: Some(source_evidence),
            }],
            embed_into_shards: false,
            ..AttachLifecycleOptions::default()
        },
    )?;

    assert!(attached.shards.is_empty());
    assert_eq!(attached.archive_state_bytes, built.archive_state_bytes);
    assert_eq!(attached.cohort_binding_bytes, built.cohort_binding_bytes);
    assert_ne!(
        attached.lifecycle_bundle_bytes,
        built.lifecycle_bundle_bytes
    );
    assert_eq!(
        attached.lifecycle_bundle["sourceEvidence"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    parse_lifecycle_bundle_bytes(&attached.lifecycle_bundle_bytes)?;
    Ok(())
}

#[test]
fn attach_lifecycle_can_rewrite_embedded_qvqcont7_bundles() -> Result<()> {
    let built = build_fixture_split()?;
    let shards = parse_built_shards(&built)?;
    let source_evidence: Value = serde_json::from_str(SOURCE_EVIDENCE_JSON)?;

    let attached = attach_lifecycle_bundle(
        &shards,
        &AttachLifecycleOptions {
            source_evidence: vec![LifecycleSourceEvidenceImport {
                bytes: None,
                value: Some(source_evidence),
            }],
            embed_into_shards: true,
            ..AttachLifecycleOptions::default()
        },
    )?;

    assert_eq!(attached.shards.len(), shards.len());
    let rewritten = attached
        .shards
        .iter()
        .map(|shard| parse_qvqcont7_shard(&shard.bytes).map_err(Into::into))
        .collect::<Result<Vec<_>>>()?;
    for shard in &rewritten {
        assert_eq!(shard.archive_state_bytes, built.archive_state_bytes);
        assert_eq!(shard.cohort_binding_bytes, built.cohort_binding_bytes);
        assert_eq!(
            shard.lifecycle_bundle_bytes,
            attached.lifecycle_bundle_bytes
        );
        assert_eq!(
            shard.lifecycle_bundle_digest_hex,
            attached.lifecycle_bundle_digest_hex
        );
    }

    let restored = restore_qvqcont7_from_shards(&rewritten, &RestoreQvqcont7Options::default())?;
    assert_eq!(restored.qenc_bytes, QENC_BYTES);
    assert_eq!(restored.priv_key, SECRET_KEY_BYTES);
    Ok(())
}

#[test]
fn attach_lifecycle_requires_explicit_bundle_for_mixed_embedded_variants() -> Result<()> {
    let built = build_fixture_split()?;
    let shards = parse_built_shards(&built)?;
    let source_evidence: Value = serde_json::from_str(SOURCE_EVIDENCE_JSON)?;
    let attached = attach_lifecycle_bundle(
        &shards,
        &AttachLifecycleOptions {
            source_evidence: vec![LifecycleSourceEvidenceImport {
                bytes: None,
                value: Some(source_evidence),
            }],
            embed_into_shards: true,
            ..AttachLifecycleOptions::default()
        },
    )?;
    let mut mixed = vec![shards[0].clone()];
    mixed.extend(
        attached
            .shards
            .iter()
            .skip(1)
            .map(|shard| parse_qvqcont7_shard(&shard.bytes))
            .collect::<qvault_core::Result<Vec<_>>>()?,
    );

    let error = attach_lifecycle_bundle(&mixed, &AttachLifecycleOptions::default())
        .expect_err("mixed embedded bundle variants must fail closed");
    assert!(
        error
            .to_string()
            .contains("multiple embedded lifecycle-bundle digests"),
        "unexpected error: {error}"
    );

    let selected = attach_lifecycle_bundle(
        &mixed,
        &AttachLifecycleOptions {
            lifecycle_bundle_bytes: Some(attached.lifecycle_bundle_bytes),
            embed_into_shards: false,
            ..AttachLifecycleOptions::default()
        },
    )?;
    assert!(selected.mixed_embedded_lifecycle_bundle_digests);
    Ok(())
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

fn parse_built_shards(
    built: &qvault_core::qcont::BuiltQvqcont7Shards,
) -> Result<Vec<qvault_core::qcont::Qvqcont7Shard>> {
    built
        .shards
        .iter()
        .map(|shard| parse_qvqcont7_shard(&shard.bytes).map_err(Into::into))
        .collect()
}
