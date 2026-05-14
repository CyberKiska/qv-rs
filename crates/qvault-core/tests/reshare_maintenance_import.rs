//! Same-run maintenance import rules (oracle: `quantum-vault` `reshare.js` CLI guards).

use anyhow::Result;
use qvault_core::auth::AuthPolicyLevel;
use qvault_core::lifecycle::{
    import_maintenance_evidence_for_new_transition, parse_transition_record_bytes,
};
use qvault_core::qcont::{
    build_qvqcont7_shards, parse_qvqcont7_shard, reshare_same_state, Qvqcont7BuildOptions,
    Qvqcont7BuildParams, ReshareSameStateOptions, ReshareSameStateParams, ReshareTransitionOptions,
};

const QENC_BYTES: &[u8] = include_bytes!("data/split_v7/single-small.qenc");
const SECRET_KEY_BYTES: &[u8] = include_bytes!("data/split_v7/single-small.secret.qkey");

#[test]
fn maintenance_import_rejects_pqpk_without_signature_imports() -> Result<()> {
    let predecessor = build_predecessor_split()?;
    let predecessor_shards = parse_built_shards(&predecessor)?;
    let reshared = reshare_same_state(
        &predecessor_shards,
        ReshareSameStateParams { n: 7, k: 5 },
        &reshare_options(),
    )?;
    let transition = parse_transition_record_bytes(&reshared.transition_record_bytes)?;
    let err = import_maintenance_evidence_for_new_transition(
        &transition,
        &[],
        &[vec![1u8, 2, 3]],
        &[],
        None,
    )
    .expect_err("pqpk without maintenance signatures must fail");
    assert!(
        err.to_string().contains("maintenance signer keys require"),
        "unexpected error: {err}"
    );
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
            ..Default::default()
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
            actor_hints: serde_json::json!({}),
            notes: Some("routine rotation".to_string()),
        },
        sss_random_bytes: Some(vec![0x24; 30_000]),
        maintenance_artifacts: Vec::new(),
        maintenance_signature_imports: Vec::new(),
        maintenance_pq_public_key_file_bytes_list: Vec::new(),
        maintenance_timestamps: Vec::new(),
        maintenance_expected_ed25519_signer: None,
        forbidden_overrides: Vec::new(),
    }
}
