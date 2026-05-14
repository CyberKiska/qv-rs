use serde_json::Value;
use zeroize::Zeroize;

use super::attach::{
    import_maintenance_evidence_for_new_transition, LifecycleSignatureImport,
};
use crate::auth::{AuthPolicyLevel, NamedBinaryArtifact};
use crate::error::{coded, err, QvCode, Result};
use crate::lifecycle::{
    canonicalize_cohort_binding, canonicalize_lifecycle_bundle, canonicalize_transition_record,
    parse_lifecycle_bundle_bytes, CanonicalLifecycleBundle, TRANSITION_RECORD_CANONICALIZATION,
    TRANSITION_RECORD_SCHEMA, TRANSITION_RECORD_VERSION, TRANSITION_TYPE_DEFAULT,
};
use crate::qcont::{
    build_qvqcont7_shard, build_qvqcont7_shards, parse_qvqcont7_shard,
    restore_qvqcont7_from_shards, BuiltQvqcont7Shard, Qvqcont7BuildOptions, Qvqcont7BuildParams,
    Qvqcont7Shard, RestoreQvqcont7Options, RestoreQvqcont7Selection,
};

const RESHARE_OPERATIONAL_WARNINGS: &[&str] = &[
    "Predecessor shard destruction cannot be proven by Quantum Vault; operators must handle custodial destruction outside the system.",
    "Same-state resharing does not revoke leaked predecessor quorum material or repair prior compromise; suspected old-quorum leakage requires a new archive state.",
];

const FORBIDDEN_RESHARE_FIELDS: &[&str] = &[
    "archiveId",
    "stateId",
    "archiveState",
    "archiveStateBytes",
    "archiveStateDigest",
    "archiveStateDigestHex",
    "qencHash",
    "containerId",
    "cryptoProfileId",
    "kdfTreeId",
    "noncePolicyId",
    "nonceMode",
    "counterBits",
    "maxChunkCount",
    "aadPolicyId",
    "authPolicy",
    "authPolicyCommitment",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReshareSameStateParams {
    pub n: u16,
    pub k: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReshareTransitionOptions {
    pub reason_code: String,
    pub performed_at: String,
    pub operator_role: String,
    pub actor_hints: Value,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReshareMaintenanceArtifacts {
    pub public_keys: Vec<Value>,
    pub maintenance_signatures: Vec<Value>,
    pub timestamps: Vec<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReshareSameStateOptions {
    pub selection: RestoreQvqcont7Selection,
    pub lifecycle_bundle_bytes: Option<Vec<u8>>,
    pub transition: ReshareTransitionOptions,
    pub sss_random_bytes: Option<Vec<u8>>,
    pub maintenance_artifacts: Vec<ReshareMaintenanceArtifacts>,
    /// Detached maintenance signatures over the **new** transition (same semantics as attach
    /// `--maintenance-sig` after resharing; `targetRef` / `targetDigestHex` may be omitted).
    pub maintenance_signature_imports: Vec<LifecycleSignatureImport>,
    pub maintenance_pq_public_key_file_bytes_list: Vec<Vec<u8>>,
    pub maintenance_timestamps: Vec<NamedBinaryArtifact>,
    pub maintenance_expected_ed25519_signer: Option<String>,
    pub forbidden_overrides: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReshareVerificationReport {
    pub rejected_shard_indices: Vec<u16>,
    pub private_key_hash_matches_metadata: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResharedSameState {
    pub shards: Vec<BuiltQvqcont7Shard>,
    pub archive_id: String,
    pub state_id: String,
    pub predecessor_cohort_id: String,
    pub predecessor_cohort_binding_digest_hex: String,
    pub predecessor_lifecycle_bundle_bytes: Vec<u8>,
    pub predecessor_lifecycle_bundle_digest_hex: String,
    pub archive_state: Value,
    pub archive_state_bytes: Vec<u8>,
    pub archive_state_digest_hex: String,
    pub cohort_binding: Value,
    pub cohort_binding_bytes: Vec<u8>,
    pub cohort_binding_digest_hex: String,
    pub cohort_id: String,
    pub lifecycle_bundle: Value,
    pub lifecycle_bundle_bytes: Vec<u8>,
    pub lifecycle_bundle_digest_hex: String,
    pub transition_record: Value,
    pub transition_record_bytes: Vec<u8>,
    pub transition_record_digest_hex: String,
    pub verification_report: ReshareVerificationReport,
    pub maintenance_signature_count_added: usize,
    pub operational_warnings: Vec<String>,
}

pub fn reshare_same_state(
    predecessor_shards: &[Qvqcont7Shard],
    params: ReshareSameStateParams,
    options: &ReshareSameStateOptions,
) -> Result<ResharedSameState> {
    assert_no_forbidden_reshare_overrides(&options.forbidden_overrides)?;
    validate_reshare_params(params)?;

    let mut selection = options.selection.clone();
    if let Some(bytes) = &options.lifecycle_bundle_bytes {
        selection.lifecycle_bundle_bytes = Some(bytes.clone());
    }
    let mut restored = restore_qvqcont7_from_shards(
        predecessor_shards,
        &RestoreQvqcont7Options {
            selection,
            enforce_policy: false,
            ..RestoreQvqcont7Options::default()
        },
    )?;
    let predecessor_bundle = parse_lifecycle_bundle_bytes(&restored.lifecycle_bundle_bytes)?;
    let (policy_level, min_valid) = parse_auth_policy(&predecessor_bundle)?;

    let successor_base = build_qvqcont7_shards(
        &restored.qenc_bytes,
        &restored.priv_key,
        Qvqcont7BuildParams {
            n: params.n,
            k: params.k,
        },
        &Qvqcont7BuildOptions {
            preserved_archive_state_bytes: Some(restored.archive_state_bytes.clone()),
            auth_policy_level: Some(policy_level),
            min_valid_signatures: Some(min_valid),
            sss_random_bytes: options.sss_random_bytes.clone(),
            ..Qvqcont7BuildOptions::default()
        },
    )?;
    restored.priv_key.zeroize();
    assert_same_state_preserved(&restored, &successor_base)?;

    let transition_record =
        build_transition_record(&restored, &successor_base, &options.transition)?;
    let canonical_transition = canonicalize_transition_record(&transition_record)?;
    let mut maintenance_sources = options.maintenance_artifacts.clone();
    if !options.maintenance_signature_imports.is_empty()
        || !options.maintenance_pq_public_key_file_bytes_list.is_empty()
        || !options.maintenance_timestamps.is_empty()
    {
        let imported = import_maintenance_evidence_for_new_transition(
            &canonical_transition,
            &options.maintenance_signature_imports,
            &options.maintenance_pq_public_key_file_bytes_list,
            &options.maintenance_timestamps,
            options
                .maintenance_expected_ed25519_signer
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty()),
        )?;
        maintenance_sources.push(ReshareMaintenanceArtifacts {
            public_keys: imported.public_keys,
            maintenance_signatures: imported.maintenance_signatures,
            timestamps: imported.timestamps,
        });
    }
    let maintenance_artifacts =
        collect_new_maintenance_artifacts(&maintenance_sources, &canonical_transition)?;
    let final_bundle = build_reshared_lifecycle_bundle(
        &predecessor_bundle,
        &successor_base,
        &canonical_transition.transition_record.value,
        &maintenance_artifacts,
    )?;
    let rewritten_shards = rewrite_successor_shards(&successor_base.shards, &final_bundle.bytes)?;

    Ok(ResharedSameState {
        shards: rewritten_shards,
        archive_id: restored.archive_id,
        state_id: restored.state_id,
        predecessor_cohort_id: restored.cohort_id,
        predecessor_cohort_binding_digest_hex: restored.cohort_binding_digest_hex,
        predecessor_lifecycle_bundle_bytes: restored.lifecycle_bundle_bytes,
        predecessor_lifecycle_bundle_digest_hex: restored.lifecycle_bundle_digest_hex,
        archive_state: successor_base.archive_state.value,
        archive_state_bytes: successor_base.archive_state_bytes,
        archive_state_digest_hex: successor_base.archive_state_digest_hex,
        cohort_binding: successor_base.cohort_binding.value,
        cohort_binding_bytes: successor_base.cohort_binding_bytes,
        cohort_binding_digest_hex: successor_base.cohort_binding_digest_hex,
        cohort_id: successor_base.cohort_id,
        lifecycle_bundle: final_bundle.lifecycle_bundle.value,
        lifecycle_bundle_bytes: final_bundle.bytes,
        lifecycle_bundle_digest_hex: final_bundle.digest.value,
        transition_record: canonical_transition.transition_record.value,
        transition_record_bytes: canonical_transition.bytes,
        transition_record_digest_hex: canonical_transition.digest.value,
        verification_report: ReshareVerificationReport {
            rejected_shard_indices: restored.rejected_shard_indices,
            private_key_hash_matches_metadata: restored.qkey_ok,
        },
        maintenance_signature_count_added: maintenance_artifacts.maintenance_signatures.len(),
        operational_warnings: RESHARE_OPERATIONAL_WARNINGS
            .iter()
            .map(|value| (*value).to_string())
            .collect(),
    })
}

fn assert_no_forbidden_reshare_overrides(overrides: &[String]) -> Result<()> {
    let rejected = overrides
        .iter()
        .filter(|field| FORBIDDEN_RESHARE_FIELDS.contains(&field.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if !rejected.is_empty() {
        return Err(coded(
            QvCode::ReshareContractViolation,
            format!(
                "Same-state resharing forbids overriding {}",
                rejected.join(", ")
            ),
        ));
    }
    Ok(())
}

fn validate_reshare_params(params: ReshareSameStateParams) -> Result<()> {
    if params.k < 2 || params.n <= params.k {
        return Err(coded(
            QvCode::ReshareContractViolation,
            "Invalid reshare parameters: require 2 <= k < n",
        ));
    }
    let parity = params.n - params.k;
    if parity % 2 != 0 {
        return Err(coded(
            QvCode::ReshareContractViolation,
            "Invalid reshare parameters: parity must be even",
        ));
    }
    Ok(())
}

fn parse_auth_policy(bundle: &CanonicalLifecycleBundle) -> Result<(AuthPolicyLevel, u64)> {
    let policy = bundle
        .lifecycle_bundle
        .value
        .get("authPolicy")
        .and_then(Value::as_object)
        .ok_or_else(|| err("Missing lifecycleBundle.authPolicy"))?;
    let level = match policy
        .get("level")
        .and_then(Value::as_str)
        .unwrap_or_default()
    {
        "integrity-only" => AuthPolicyLevel::IntegrityOnly,
        "any-signature" => AuthPolicyLevel::AnySignature,
        "strong-pq-signature" => AuthPolicyLevel::StrongPqSignature,
        other => return Err(err(format!("Unsupported authPolicy.level: {other}"))),
    };
    Ok((
        level,
        policy
            .get("minValidSignatures")
            .and_then(Value::as_u64)
            .unwrap_or(1)
            .max(1),
    ))
}

fn assert_same_state_preserved(
    predecessor: &crate::qcont::RestoredQvqcont7,
    successor: &crate::qcont::BuiltQvqcont7Shards,
) -> Result<()> {
    if successor.archive_state_bytes != predecessor.archive_state_bytes
        || successor.archive_state_digest_hex != predecessor.archive_state_digest_hex
        || successor.archive_id != predecessor.archive_id
        || successor.state_id != predecessor.state_id
    {
        return Err(coded(
            QvCode::ReshareContractViolation,
            "Same-state resharing must preserve exact archive-state descriptor bytes",
        ));
    }
    Ok(())
}

fn build_transition_record(
    predecessor: &crate::qcont::RestoredQvqcont7,
    successor: &crate::qcont::BuiltQvqcont7Shards,
    transition: &ReshareTransitionOptions,
) -> Result<Value> {
    if transition.reason_code.trim().is_empty()
        || transition.operator_role.trim().is_empty()
        || transition.performed_at.trim().is_empty()
    {
        return Err(coded(
            QvCode::ReshareContractViolation,
            "same-state resharing requires reasonCode, operatorRole, and performedAt",
        ));
    }
    Ok(serde_json::json!({
        "schema": TRANSITION_RECORD_SCHEMA,
        "version": TRANSITION_RECORD_VERSION,
        "canonicalization": TRANSITION_RECORD_CANONICALIZATION,
        "transitionType": TRANSITION_TYPE_DEFAULT,
        "archiveId": predecessor.archive_id,
        "fromStateId": predecessor.state_id,
        "toStateId": successor.state_id,
        "fromCohortId": predecessor.cohort_id,
        "toCohortId": successor.cohort_id,
        "fromCohortBindingDigest": { "alg": "SHA3-512", "value": predecessor.cohort_binding_digest_hex },
        "toCohortBindingDigest": { "alg": "SHA3-512", "value": successor.cohort_binding_digest_hex },
        "reasonCode": transition.reason_code,
        "performedAt": transition.performed_at,
        "operatorRole": transition.operator_role,
        "actorHints": transition.actor_hints,
        "notes": transition.notes,
    }))
}

fn collect_new_maintenance_artifacts(
    sources: &[ReshareMaintenanceArtifacts],
    transition: &crate::lifecycle::CanonicalTransitionRecord,
) -> Result<ReshareMaintenanceArtifacts> {
    let mut combined = ReshareMaintenanceArtifacts::default();
    for source in sources {
        combined
            .public_keys
            .extend(source.public_keys.iter().cloned());
        combined
            .maintenance_signatures
            .extend(source.maintenance_signatures.iter().cloned());
        combined
            .timestamps
            .extend(source.timestamps.iter().cloned());
    }
    validate_new_maintenance_artifacts(&combined, transition)?;
    Ok(combined)
}

fn validate_new_maintenance_artifacts(
    artifacts: &ReshareMaintenanceArtifacts,
    transition: &crate::lifecycle::CanonicalTransitionRecord,
) -> Result<()> {
    let target_ref = format!("transition:sha3-512:{}", transition.digest.value);
    let mut new_signature_ids = std::collections::HashSet::new();
    for signature in &artifacts.maintenance_signatures {
        let object = signature
            .as_object()
            .ok_or_else(|| err("Invalid maintenance signature artifact"))?;
        if object.get("signatureFamily").and_then(Value::as_str) != Some("maintenance") {
            return Err(coded(
                QvCode::ReshareContractViolation,
                "Same-state resharing accepts only maintenance detached signatures for new transition artifacts",
            ));
        }
        if object.get("targetType").and_then(Value::as_str) != Some("transition-record") {
            return Err(coded(
                QvCode::ReshareContractViolation,
                "New maintenance signatures must target transition-record bytes",
            ));
        }
        if object.get("targetRef").and_then(Value::as_str) != Some(target_ref.as_str()) {
            return Err(coded(
                QvCode::ReshareContractViolation,
                "New maintenance signatures must target the newly emitted transition record",
            ));
        }
        if object
            .get("targetDigest")
            .and_then(|digest| digest.get("value"))
            .and_then(Value::as_str)
            != Some(transition.digest.value.as_str())
        {
            return Err(coded(
                QvCode::ReshareContractViolation,
                "New maintenance signatures must carry the newly emitted transition-record digest",
            ));
        }
        if let Some(id) = object.get("id").and_then(Value::as_str) {
            new_signature_ids.insert(id.to_string());
        }
    }
    for timestamp in &artifacts.timestamps {
        let target = timestamp
            .get("targetRef")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !new_signature_ids.contains(target) {
            return Err(coded(
                QvCode::ReshareContractViolation,
                "New maintenance timestamps must reference one of the new maintenance signatures for this resharing event",
            ));
        }
    }
    Ok(())
}

fn build_reshared_lifecycle_bundle(
    predecessor_bundle: &CanonicalLifecycleBundle,
    successor: &crate::qcont::BuiltQvqcont7Shards,
    transition_record: &Value,
    maintenance: &ReshareMaintenanceArtifacts,
) -> Result<CanonicalLifecycleBundle> {
    let mut bundle = predecessor_bundle.lifecycle_bundle.value.clone();
    set_field(
        &mut bundle,
        "currentCohortBinding",
        successor.cohort_binding.value.clone(),
    )?;
    set_field(
        &mut bundle,
        "currentCohortBindingDigest",
        serde_json::json!({"alg": "SHA3-512", "value": successor.cohort_binding_digest_hex}),
    )?;
    let mut transitions = bundle
        .get("transitions")
        .and_then(Value::as_array)
        .ok_or_else(|| err("Invalid lifecycleBundle.transitions"))?
        .clone();
    transitions.push(transition_record.clone());
    set_field(&mut bundle, "transitions", Value::Array(transitions))?;

    let mut attachments = bundle
        .get("attachments")
        .cloned()
        .ok_or_else(|| err("Missing lifecycleBundle.attachments"))?;
    append_array_field(&mut attachments, "publicKeys", &maintenance.public_keys)?;
    append_array_field(
        &mut attachments,
        "maintenanceSignatures",
        &maintenance.maintenance_signatures,
    )?;
    append_array_field(&mut attachments, "timestamps", &maintenance.timestamps)?;
    set_field(&mut bundle, "attachments", attachments)?;

    let canonical = canonicalize_lifecycle_bundle(&bundle)?;
    let cohort =
        canonicalize_cohort_binding(&canonical.lifecycle_bundle.value["currentCohortBinding"])?;
    if cohort.bytes != successor.cohort_binding_bytes {
        return Err(coded(
            QvCode::ReshareContractViolation,
            "Same-state resharing changed successor cohort-binding bytes",
        ));
    }
    Ok(canonical)
}

fn rewrite_successor_shards(
    base_shards: &[BuiltQvqcont7Shard],
    lifecycle_bundle_bytes: &[u8],
) -> Result<Vec<BuiltQvqcont7Shard>> {
    let lifecycle_bundle = parse_lifecycle_bundle_bytes(lifecycle_bundle_bytes)?;
    base_shards
        .iter()
        .map(|built| {
            let mut shard = parse_qvqcont7_shard(&built.bytes)?;
            shard.lifecycle_bundle_bytes = lifecycle_bundle.bytes.clone();
            shard.lifecycle_bundle_digest_hex = lifecycle_bundle.digest.value.clone();
            shard.lifecycle_bundle = lifecycle_bundle.clone();
            Ok(BuiltQvqcont7Shard {
                index: built.index,
                bytes: build_qvqcont7_shard(&shard)?,
            })
        })
        .collect()
}

fn set_field(value: &mut Value, field: &str, next: Value) -> Result<()> {
    let object = value
        .as_object_mut()
        .ok_or_else(|| err("Expected lifecycle bundle object"))?;
    object.insert(field.to_string(), next);
    Ok(())
}

fn append_array_field(value: &mut Value, field: &str, next: &[Value]) -> Result<()> {
    let object = value
        .as_object_mut()
        .ok_or_else(|| err("Expected lifecycle attachments object"))?;
    let mut array = object
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| err(format!("Invalid lifecycleBundle.attachments.{field}")))?
        .clone();
    array.extend(next.iter().cloned());
    object.insert(field.to_string(), Value::Array(array));
    Ok(())
}
