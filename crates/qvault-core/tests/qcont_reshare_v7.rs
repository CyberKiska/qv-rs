use anyhow::Result;
use qvault_core::auth::AuthPolicyLevel;
use qvault_core::error::QvCode;
use qvault_core::lifecycle::{parse_lifecycle_bundle_bytes, parse_transition_record_bytes};
use qvault_core::qcont::{
    build_qvqcont7_shards, parse_qvqcont7_shard, reshare_same_state, restore_qvqcont7_from_shards,
    Qvqcont7BuildOptions, Qvqcont7BuildParams, ReshareSameStateOptions, ReshareSameStateParams,
    ReshareTransitionOptions, RestoreQvqcont7Options,
};
use serde_json::json;

const QENC_BYTES: &[u8] = include_bytes!("data/split_v7/single-small.qenc");
const SECRET_KEY_BYTES: &[u8] = include_bytes!("data/split_v7/single-small.secret.qkey");

#[test]
fn reshare_v7_preserves_archive_state_and_emits_transition_chain() -> Result<()> {
    let predecessor = build_predecessor_split()?;
    let predecessor_shards = parse_built_shards(&predecessor)?;
    let reshared = reshare_same_state(
        &predecessor_shards,
        ReshareSameStateParams { n: 7, k: 5 },
        &reshare_options(),
    )?;

    assert_eq!(reshared.archive_id, predecessor.archive_id);
    assert_eq!(reshared.state_id, predecessor.state_id);
    assert_eq!(
        reshared.archive_state_bytes,
        predecessor.archive_state_bytes
    );
    assert_eq!(
        reshared.archive_state_digest_hex,
        predecessor.archive_state_digest_hex
    );
    assert_eq!(reshared.predecessor_cohort_id, predecessor.cohort_id);
    assert_ne!(reshared.cohort_id, predecessor.cohort_id);
    assert_eq!(reshared.shards.len(), 7);

    let transition = parse_transition_record_bytes(&reshared.transition_record_bytes)?;
    assert_eq!(
        transition.transition_record.value["transitionType"],
        "same-state-resharing"
    );
    assert_eq!(
        transition.transition_record.value["fromCohortId"],
        predecessor.cohort_id
    );
    assert_eq!(
        transition.transition_record.value["toCohortId"],
        reshared.cohort_id
    );

    let bundle = parse_lifecycle_bundle_bytes(&reshared.lifecycle_bundle_bytes)?;
    assert_eq!(
        bundle.lifecycle_bundle.value["archiveStateDigest"]["value"],
        predecessor.archive_state_digest_hex
    );
    assert_eq!(
        bundle.lifecycle_bundle.value["currentCohortBindingDigest"]["value"],
        reshared.cohort_binding_digest_hex
    );
    assert_eq!(
        bundle.lifecycle_bundle.value["transitions"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    let successor_shards = reshared
        .shards
        .iter()
        .map(|shard| parse_qvqcont7_shard(&shard.bytes).map_err(Into::into))
        .collect::<Result<Vec<_>>>()?;
    for shard in &successor_shards {
        assert_eq!(shard.archive_state_bytes, predecessor.archive_state_bytes);
        assert_eq!(
            shard.lifecycle_bundle_bytes,
            reshared.lifecycle_bundle_bytes
        );
        assert_eq!(shard.cohort_id, reshared.cohort_id);
    }
    let restored =
        restore_qvqcont7_from_shards(&successor_shards, &RestoreQvqcont7Options::default())?;
    assert_eq!(restored.qenc_bytes, QENC_BYTES);
    assert_eq!(restored.priv_key, SECRET_KEY_BYTES);
    Ok(())
}

#[test]
fn reshare_v7_rejects_forbidden_archive_state_overrides() -> Result<()> {
    let predecessor = build_predecessor_split()?;
    let predecessor_shards = parse_built_shards(&predecessor)?;
    let mut options = reshare_options();
    options.forbidden_overrides = vec!["archiveId".to_string()];

    let error = reshare_same_state(
        &predecessor_shards,
        ReshareSameStateParams { n: 7, k: 5 },
        &options,
    )
    .expect_err("forbidden archive-state override must fail");
    assert_eq!(error.qv_code(), Some(QvCode::ReshareContractViolation));
    Ok(())
}

fn build_predecessor_split() -> Result<qvault_core::qcont::BuiltQvqcont7Shards> {
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

fn reshare_options() -> ReshareSameStateOptions {
    ReshareSameStateOptions {
        selection: Default::default(),
        lifecycle_bundle_bytes: None,
        transition: ReshareTransitionOptions {
            reason_code: "cohort-rotation".to_string(),
            performed_at: "2026-05-14T12:00:00.000Z".to_string(),
            operator_role: "operator".to_string(),
            actor_hints: json!({ "surface": "rust-test" }),
            notes: Some("routine rotation".to_string()),
        },
        sss_random_bytes: Some(vec![0x24; 30_000]),
        maintenance_artifacts: Vec::new(),
        forbidden_overrides: Vec::new(),
    }
}
