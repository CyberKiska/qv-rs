use std::collections::{HashMap, HashSet};

use serde_json::Value;

use crate::error::{err, Result};
use crate::manifest::jcs::{
    canonicalize_json, canonicalize_json_to_bytes, BUNDLE_CANONICALIZATION_LABEL,
};
use crate::manifest::strict_json::{assert_canonical_bytes, parse_json_bytes_strict};

use super::archive_state::{
    canonicalize_archive_state_descriptor, validate_archive_state_descriptor_value,
    ARCHIVE_STATE_CANONICALIZATION,
};
use super::attachments::validate_lifecycle_attachments_value;
use super::cohort_binding::{canonicalize_cohort_binding, validate_cohort_binding_value};
use super::digests::{
    compute_auth_policy_commitment, normalize_auth_policy, normalize_digest_object,
    sha3_512_digest, DigestObject, SHA3_512_ALG,
};
use super::identity::derive_cohort_id;
use super::source_evidence::{canonicalize_source_evidence, validate_source_evidence_value};
use super::transition::{
    canonicalize_transition_record, validate_transition_record_value, TRANSITION_TYPE_DEFAULT,
};
use super::validation::{
    array, exact_keys, exact_string, number, object_from_pairs, string, value_object,
};

pub const LIFECYCLE_BUNDLE_TYPE: &str = "QV-Lifecycle-Bundle";
pub const LIFECYCLE_BUNDLE_VERSION: u64 = 1;
pub const LIFECYCLE_BUNDLE_CANONICALIZATION: &str = BUNDLE_CANONICALIZATION_LABEL;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleBundle {
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalLifecycleBundle {
    pub lifecycle_bundle: LifecycleBundle,
    pub canonical: String,
    pub bytes: Vec<u8>,
    pub digest: DigestObject,
    pub canonicalization_label: String,
}

pub fn validate_lifecycle_bundle_value(value: &Value) -> Result<LifecycleBundle> {
    let source = value_object(value, "lifecycleBundle")?;
    exact_keys(
        source,
        &[
            "type",
            "version",
            "bundleCanonicalization",
            "archiveStateCanonicalization",
            "archiveState",
            "archiveStateDigest",
            "currentCohortBinding",
            "currentCohortBindingDigest",
            "authPolicy",
            "sourceEvidence",
            "transitions",
            "attachments",
        ],
        &[],
        "lifecycleBundle",
    )?;
    let version = super::validation::integer(
        source.get("version"),
        "lifecycleBundle.version",
        1,
        u64::MAX,
    )?;
    if version != LIFECYCLE_BUNDLE_VERSION {
        return Err(err("Unsupported lifecycleBundle.version"));
    }
    let archive_state = validate_archive_state_descriptor_value(
        source
            .get("archiveState")
            .ok_or_else(|| err("Missing lifecycleBundle.archiveState"))?,
    )?;
    let canonical_archive_state = canonicalize_archive_state_descriptor(&archive_state.value)?;
    let archive_state_digest = normalize_digest_object(
        source
            .get("archiveStateDigest")
            .ok_or_else(|| err("Missing lifecycleBundle.archiveStateDigest"))?,
        "lifecycleBundle.archiveStateDigest",
        Some(SHA3_512_ALG),
        Some(128),
    )?;
    if archive_state_digest.value != canonical_archive_state.digest.value {
        return Err(err("lifecycleBundle.archiveStateDigest mismatch"));
    }

    let current_cohort_binding = validate_cohort_binding_value(
        source
            .get("currentCohortBinding")
            .ok_or_else(|| err("Missing lifecycleBundle.currentCohortBinding"))?,
    )?;
    let canonical_current_cohort = canonicalize_cohort_binding(&current_cohort_binding.value)?;
    let current_cohort_binding_digest = normalize_digest_object(
        source
            .get("currentCohortBindingDigest")
            .ok_or_else(|| err("Missing lifecycleBundle.currentCohortBindingDigest"))?,
        "lifecycleBundle.currentCohortBindingDigest",
        Some(SHA3_512_ALG),
        Some(128),
    )?;
    if current_cohort_binding_digest.value != canonical_current_cohort.digest.value {
        return Err(err("lifecycleBundle.currentCohortBindingDigest mismatch"));
    }

    let archive_state_object = value_object(&archive_state.value, "lifecycleBundle.archiveState")?;
    let cohort_object = value_object(
        &current_cohort_binding.value,
        "lifecycleBundle.currentCohortBinding",
    )?;
    let archive_id = string(
        archive_state_object.get("archiveId"),
        "lifecycleBundle.archiveState.archiveId",
    )?;
    if string(
        cohort_object.get("archiveId"),
        "lifecycleBundle.currentCohortBinding.archiveId",
    )? != archive_id
    {
        return Err(err("lifecycleBundle archiveId mismatch"));
    }
    if string(
        cohort_object.get("stateId"),
        "lifecycleBundle.currentCohortBinding.stateId",
    )? != canonical_archive_state.state_id
    {
        return Err(err("lifecycleBundle currentCohortBinding.stateId mismatch"));
    }

    let auth_policy = normalize_auth_policy(
        source
            .get("authPolicy")
            .ok_or_else(|| err("Missing lifecycleBundle.authPolicy"))?,
    )?;
    let expected_commitment = compute_auth_policy_commitment(&auth_policy)?;
    let commitment_object = value_object(
        archive_state_object
            .get("authPolicyCommitment")
            .ok_or_else(|| err("Missing lifecycleBundle.archiveState.authPolicyCommitment"))?,
        "authPolicyCommitment",
    )?;
    let actual_commitment_value =
        string(commitment_object.get("value"), "authPolicyCommitment.value")?;
    if actual_commitment_value != expected_commitment.value {
        return Err(err("authPolicyCommitment mismatch"));
    }

    let source_evidence = array(
        source.get("sourceEvidence"),
        "lifecycleBundle.sourceEvidence",
    )?
    .iter()
    .map(|entry| validate_source_evidence_value(entry).map(|validated| validated.value))
    .collect::<Result<Vec<_>>>()?;
    let transitions = array(source.get("transitions"), "lifecycleBundle.transitions")?
        .iter()
        .map(|entry| validate_transition_record_value(entry).map(|validated| validated.value))
        .collect::<Result<Vec<_>>>()?;
    let attachments = validate_lifecycle_attachments_value(
        source
            .get("attachments")
            .ok_or_else(|| err("Missing lifecycleBundle.attachments"))?,
    )?;

    inspect_lifecycle_transitions(
        &archive_id,
        &canonical_archive_state.state_id,
        &canonical_current_cohort.digest,
        &current_cohort_binding_digest,
        &transitions,
    )?;
    validate_signature_targets(
        &canonical_archive_state.digest,
        &source_evidence,
        &transitions,
        &attachments.value,
    )?;

    Ok(LifecycleBundle {
        value: object_from_pairs(vec![
            (
                "type",
                Value::String(exact_string(
                    source.get("type"),
                    "lifecycleBundle.type",
                    LIFECYCLE_BUNDLE_TYPE,
                )?),
            ),
            ("version", number(version)),
            (
                "bundleCanonicalization",
                Value::String(exact_string(
                    source.get("bundleCanonicalization"),
                    "lifecycleBundle.bundleCanonicalization",
                    LIFECYCLE_BUNDLE_CANONICALIZATION,
                )?),
            ),
            (
                "archiveStateCanonicalization",
                Value::String(exact_string(
                    source.get("archiveStateCanonicalization"),
                    "lifecycleBundle.archiveStateCanonicalization",
                    ARCHIVE_STATE_CANONICALIZATION,
                )?),
            ),
            ("archiveState", archive_state.value),
            (
                "archiveStateDigest",
                serde_json::to_value(archive_state_digest)?,
            ),
            ("currentCohortBinding", current_cohort_binding.value),
            (
                "currentCohortBindingDigest",
                serde_json::to_value(current_cohort_binding_digest)?,
            ),
            ("authPolicy", auth_policy),
            ("sourceEvidence", Value::Array(source_evidence)),
            ("transitions", Value::Array(transitions)),
            ("attachments", attachments.value),
        ]),
    })
}

fn inspect_lifecycle_transitions(
    archive_id: &str,
    state_id: &str,
    current_cohort_digest: &DigestObject,
    current_cohort_digest_declared: &DigestObject,
    transitions: &[Value],
) -> Result<()> {
    let current_cohort_id = derive_cohort_id(archive_id, state_id, current_cohort_digest)?;
    let mut prior_to_cohort_id: Option<String> = None;
    let mut prior_to_digest: Option<String> = None;
    let mut seen_digests = HashSet::new();
    for (index, transition) in transitions.iter().enumerate() {
        let canonical = canonicalize_transition_record(transition)?;
        if !seen_digests.insert(canonical.digest.value.clone()) {
            return Err(err(format!(
                "lifecycleBundle.transitions[{index}] duplicate transition-record digest"
            )));
        }
        let field = format!("lifecycleBundle.transitions[{index}]");
        let source = value_object(transition, &field)?;
        if string(source.get("archiveId"), &format!("{field}.archiveId"))? != archive_id {
            return Err(err(format!("{field}.archiveId mismatch")));
        }
        if string(
            source.get("transitionType"),
            &format!("{field}.transitionType"),
        )? != TRANSITION_TYPE_DEFAULT
        {
            return Err(err(format!(
                "{field}.transitionType is not supported in Phase 5"
            )));
        }
        let from_state_id = string(source.get("fromStateId"), &format!("{field}.fromStateId"))?;
        let to_state_id = string(source.get("toStateId"), &format!("{field}.toStateId"))?;
        if from_state_id != to_state_id {
            return Err(err(format!(
                "{field} changes stateId, which is not supported in Phase 5"
            )));
        }
        if from_state_id != state_id {
            return Err(err(format!(
                "{field} does not reference the current lifecycle bundle stateId"
            )));
        }
        let from_digest = super::digests::normalize_digest_object(
            source
                .get("fromCohortBindingDigest")
                .ok_or_else(|| err(format!("Missing {field}.fromCohortBindingDigest")))?,
            &format!("{field}.fromCohortBindingDigest"),
            Some(SHA3_512_ALG),
            Some(128),
        )?;
        let to_digest = super::digests::normalize_digest_object(
            source
                .get("toCohortBindingDigest")
                .ok_or_else(|| err(format!("Missing {field}.toCohortBindingDigest")))?,
            &format!("{field}.toCohortBindingDigest"),
            Some(SHA3_512_ALG),
            Some(128),
        )?;
        let expected_from = derive_cohort_id(archive_id, &from_state_id, &from_digest)?;
        if string(source.get("fromCohortId"), &format!("{field}.fromCohortId"))? != expected_from {
            return Err(err(format!("{field}.fromCohortId mismatch")));
        }
        let expected_to = derive_cohort_id(archive_id, &to_state_id, &to_digest)?;
        if string(source.get("toCohortId"), &format!("{field}.toCohortId"))? != expected_to {
            return Err(err(format!("{field}.toCohortId mismatch")));
        }
        if expected_from == expected_to {
            return Err(err(format!("{field} does not change cohortId")));
        }
        if let Some(prior) = &prior_to_cohort_id {
            if prior != &expected_from {
                return Err(err(format!(
                    "{field}.fromCohortId does not continue the prior transition chain"
                )));
            }
        }
        if let Some(prior) = &prior_to_digest {
            if prior != &from_digest.value {
                return Err(err(format!(
                    "{field}.fromCohortBindingDigest does not continue the prior transition chain"
                )));
            }
        }
        prior_to_cohort_id = Some(expected_to);
        prior_to_digest = Some(to_digest.value);
    }
    if !transitions.is_empty() {
        if prior_to_cohort_id.as_deref() != Some(current_cohort_id.as_str()) {
            return Err(err(
                "lifecycleBundle.transitions final toCohortId does not match lifecycleBundle.currentCohortBinding",
            ));
        }
        if prior_to_digest.as_deref() != Some(current_cohort_digest_declared.value.as_str()) {
            return Err(err(
                "lifecycleBundle.transitions final toCohortBindingDigest does not match lifecycleBundle.currentCohortBindingDigest",
            ));
        }
    }
    Ok(())
}

fn validate_signature_targets(
    archive_state_digest: &DigestObject,
    source_evidence: &[Value],
    transitions: &[Value],
    attachments: &Value,
) -> Result<()> {
    let mut transition_targets = HashMap::new();
    for transition in transitions {
        let canonical = canonicalize_transition_record(transition)?;
        transition_targets.insert(canonical.digest.value.clone(), canonical.digest);
    }
    let mut source_targets = HashMap::new();
    for (index, evidence) in source_evidence.iter().enumerate() {
        let canonical = canonicalize_source_evidence(evidence)?;
        if source_targets
            .insert(canonical.digest.value.clone(), canonical.digest)
            .is_some()
        {
            return Err(err(format!(
                "lifecycleBundle.sourceEvidence[{index}] duplicate source-evidence digest"
            )));
        }
    }
    let object = value_object(attachments, "lifecycleBundle.attachments")?;
    check_signature_family(
        object.get("archiveApprovalSignatures"),
        "archive-approval",
        "archive-state",
        &format!("state:{}", archive_state_digest.value),
        archive_state_digest,
    )?;
    check_signature_map_family(
        object.get("maintenanceSignatures"),
        "maintenance",
        "transition-record",
        "transition:sha3-512:",
        &transition_targets,
    )?;
    check_signature_map_family(
        object.get("sourceEvidenceSignatures"),
        "source-evidence",
        "source-evidence",
        "source-evidence:sha3-512:",
        &source_targets,
    )?;
    Ok(())
}

fn check_signature_family(
    value: Option<&Value>,
    family: &str,
    target_type: &str,
    target_ref: &str,
    digest: &DigestObject,
) -> Result<()> {
    let Some(Value::Array(entries)) = value else {
        return Err(err("Invalid signature family"));
    };
    for entry in entries {
        let source = value_object(entry, "detachedSignature")?;
        if string(
            source.get("signatureFamily"),
            "detachedSignature.signatureFamily",
        )? != family
        {
            return Err(err("detachedSignature entry has wrong signatureFamily"));
        }
        if string(source.get("targetType"), "detachedSignature.targetType")? != target_type {
            return Err(err("detachedSignature entry has wrong targetType"));
        }
        if string(source.get("targetRef"), "detachedSignature.targetRef")? != target_ref {
            return Err(err("detachedSignature targetRef mismatch"));
        }
        let target_digest = super::digests::normalize_digest_object(
            source
                .get("targetDigest")
                .ok_or_else(|| err("Missing detachedSignature.targetDigest"))?,
            "detachedSignature.targetDigest",
            Some(SHA3_512_ALG),
            Some(128),
        )?;
        if target_digest.value != digest.value {
            return Err(err("detachedSignature targetDigest mismatch"));
        }
    }
    Ok(())
}

fn check_signature_map_family(
    value: Option<&Value>,
    family: &str,
    target_type: &str,
    target_ref_prefix: &str,
    targets: &HashMap<String, DigestObject>,
) -> Result<()> {
    let Some(Value::Array(entries)) = value else {
        return Err(err("Invalid signature family"));
    };
    for entry in entries {
        let source = value_object(entry, "detachedSignature")?;
        if string(
            source.get("signatureFamily"),
            "detachedSignature.signatureFamily",
        )? != family
        {
            return Err(err("detachedSignature entry has wrong signatureFamily"));
        }
        if string(source.get("targetType"), "detachedSignature.targetType")? != target_type {
            return Err(err("detachedSignature entry has wrong targetType"));
        }
        let target_digest = super::digests::normalize_digest_object(
            source
                .get("targetDigest")
                .ok_or_else(|| err("Missing detachedSignature.targetDigest"))?,
            "detachedSignature.targetDigest",
            Some(SHA3_512_ALG),
            Some(128),
        )?;
        let Some(expected_digest) = targets.get(&target_digest.value) else {
            return Err(err("detachedSignature targetDigest mismatch"));
        };
        let expected_ref = format!("{target_ref_prefix}{}", expected_digest.value);
        if string(source.get("targetRef"), "detachedSignature.targetRef")? != expected_ref {
            return Err(err("detachedSignature targetRef mismatch"));
        }
    }
    Ok(())
}

pub fn canonicalize_lifecycle_bundle(value: &Value) -> Result<CanonicalLifecycleBundle> {
    let lifecycle_bundle = validate_lifecycle_bundle_value(value)?;
    let canonical = canonicalize_json(&lifecycle_bundle.value)?;
    let bytes = canonicalize_json_to_bytes(&lifecycle_bundle.value)?;
    let digest = sha3_512_digest(&bytes);
    Ok(CanonicalLifecycleBundle {
        lifecycle_bundle,
        canonical,
        bytes,
        digest,
        canonicalization_label: LIFECYCLE_BUNDLE_CANONICALIZATION.to_string(),
    })
}

pub fn parse_lifecycle_bundle_bytes(bytes: &[u8]) -> Result<CanonicalLifecycleBundle> {
    let parsed = parse_json_bytes_strict(bytes)?;
    let canonicalized = canonicalize_lifecycle_bundle(&parsed)?;
    assert_canonical_bytes(bytes, &canonicalized.bytes, "Lifecycle bundle")?;
    Ok(canonicalized)
}
