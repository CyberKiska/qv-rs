use anyhow::Result;
use qvault_core::auth::AuthPolicyLevel;
use qvault_core::error::QvCode;
use qvault_core::qcont::{
    build_qvqcont7_shards, parse_qvqcont7_shard, restore_qvqcont7_from_shards,
    Qvqcont7BuildOptions, Qvqcont7BuildParams, RestoreQvqcont7Options, RestoreQvqcont7Selection,
};

const QENC_BYTES: &[u8] = include_bytes!("data/split_v7/single-small.qenc");
const SECRET_KEY_BYTES: &[u8] = include_bytes!("data/split_v7/single-small.secret.qkey");

#[test]
fn restore_v7_reconstructs_successor_qenc_and_private_key() -> Result<()> {
    let built = build_fixture_split(vec![0x42; 10_000])?;
    let shards = parse_built_shards(&built)?;
    let restored = restore_qvqcont7_from_shards(&shards, &RestoreQvqcont7Options::default())?;

    assert_eq!(restored.qenc_bytes, QENC_BYTES);
    assert_eq!(restored.priv_key, SECRET_KEY_BYTES);
    assert_eq!(restored.archive_id, built.archive_id);
    assert_eq!(restored.state_id, built.state_id);
    assert_eq!(restored.cohort_id, built.cohort_id);
    assert_eq!(restored.archive_state_bytes, built.archive_state_bytes);
    assert_eq!(restored.cohort_binding_bytes, built.cohort_binding_bytes);
    assert_eq!(
        restored.lifecycle_bundle_bytes,
        built.lifecycle_bundle_bytes
    );
    assert!(restored.qenc_ok);
    assert!(restored.qkey_ok);
    assert!(restored.authenticity.policy.satisfied);
    Ok(())
}

#[test]
fn restore_v7_fails_closed_on_ambiguous_same_state_cohorts() -> Result<()> {
    let first = build_fixture_split(vec![0x42; 10_000])?;
    let second = build_fixture_split(vec![0x24; 10_000])?;
    assert_eq!(first.archive_id, second.archive_id);
    assert_eq!(first.state_id, second.state_id);
    assert_ne!(first.cohort_id, second.cohort_id);

    let mut shards = parse_built_shards(&first)?;
    shards.extend(parse_built_shards(&second)?);

    let error = restore_qvqcont7_from_shards(&shards, &RestoreQvqcont7Options::default())
        .expect_err("ambiguous cohorts must fail closed");
    assert_eq!(error.qv_code(), Some(QvCode::AmbiguousInputs));

    let restored = restore_qvqcont7_from_shards(
        &shards,
        &RestoreQvqcont7Options {
            selection: RestoreQvqcont7Selection {
                selected_cohort_id: Some(second.cohort_id.clone()),
                ..RestoreQvqcont7Selection::default()
            },
            ..RestoreQvqcont7Options::default()
        },
    )?;
    assert_eq!(restored.cohort_id, second.cohort_id);
    Ok(())
}

#[test]
fn restore_v7_enforces_archive_policy() -> Result<()> {
    let built = build_qvqcont7_shards(
        QENC_BYTES,
        SECRET_KEY_BYTES,
        Qvqcont7BuildParams { n: 5, k: 3 },
        &Qvqcont7BuildOptions {
            archive_id: Some("31".repeat(32)),
            sss_random_bytes: Some(vec![0x55; 10_000]),
            auth_policy_level: Some(AuthPolicyLevel::StrongPqSignature),
            min_valid_signatures: Some(1),
            ..Qvqcont7BuildOptions::default()
        },
    )?;
    let shards = parse_built_shards(&built)?;
    let error = restore_qvqcont7_from_shards(&shards, &RestoreQvqcont7Options::default())
        .expect_err("unsigned strong-PQ archive must fail policy");
    assert_eq!(error.qv_code(), Some(QvCode::PolicyNotSatisfied));
    Ok(())
}

#[test]
fn restore_v7_tolerates_one_corrupted_shard_under_rs_policy() -> Result<()> {
    let built = build_fixture_split(vec![0x42; 10_000])?;
    let mut shards = parse_built_shards(&built)?;
    shards[0].share[0] ^= 0x80;

    let restored = restore_qvqcont7_from_shards(&shards, &RestoreQvqcont7Options::default())?;
    assert_eq!(restored.qenc_bytes, QENC_BYTES);
    assert_eq!(restored.priv_key, SECRET_KEY_BYTES);
    assert_eq!(restored.rejected_shard_indices, vec![0]);
    Ok(())
}

fn build_fixture_split(
    sss_random_bytes: Vec<u8>,
) -> Result<qvault_core::qcont::BuiltQvqcont7Shards> {
    build_qvqcont7_shards(
        QENC_BYTES,
        SECRET_KEY_BYTES,
        Qvqcont7BuildParams { n: 5, k: 3 },
        &Qvqcont7BuildOptions {
            archive_id: Some("31".repeat(32)),
            sss_random_bytes: Some(sss_random_bytes),
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
