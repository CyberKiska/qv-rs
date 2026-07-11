use anyhow::{bail, Result};
use qvault_core::auth::{AuthPolicyLevel, AuthenticityReport};
use qvault_core::error::{coded, QvCode};
use qvault_core::hash::sha3_512_hex;
use qvault_core::lifecycle::{
    parse_archive_state_descriptor_bytes, parse_cohort_binding_bytes, parse_lifecycle_bundle_bytes,
    parse_source_evidence_bytes, parse_transition_record_bytes,
};
use qvault_core::qcont::parse_qvqcont7_shard;
use qvault_core::qenc::parse_qenc_header;
use serde_json::Value;
use std::path::Path;

use super::AuthPolicyLevelArg;

#[derive(Clone)]
pub(crate) struct CanonicalizedArtifact {
    pub(crate) artifact_type: &'static str,
    pub(crate) artifact_version: String,
    pub(crate) value: Value,
    pub(crate) text: String,
    pub(crate) bytes: Vec<u8>,
    pub(crate) canonical_input: bool,
}

pub(crate) fn canonicalize_artifact(bytes: &[u8]) -> Result<CanonicalizedArtifact> {
    if let Ok(parsed) = parse_archive_state_descriptor_bytes(bytes) {
        return Ok(CanonicalizedArtifact {
            artifact_type: "archive-state",
            artifact_version: "1".to_string(),
            value: parsed.archive_state.value,
            text: parsed.canonical,
            canonical_input: parsed.bytes == bytes,
            bytes: parsed.bytes,
        });
    }
    if let Ok(parsed) = parse_cohort_binding_bytes(bytes) {
        return Ok(CanonicalizedArtifact {
            artifact_type: "cohort-binding",
            artifact_version: "1".to_string(),
            value: parsed.cohort_binding.value,
            text: parsed.canonical,
            canonical_input: parsed.bytes == bytes,
            bytes: parsed.bytes,
        });
    }
    if let Ok(parsed) = parse_lifecycle_bundle_bytes(bytes) {
        return Ok(CanonicalizedArtifact {
            artifact_type: "lifecycle-bundle",
            artifact_version: "1".to_string(),
            value: parsed.lifecycle_bundle.value,
            text: parsed.canonical,
            canonical_input: parsed.bytes == bytes,
            bytes: parsed.bytes,
        });
    }
    if let Ok(parsed) = parse_transition_record_bytes(bytes) {
        return Ok(CanonicalizedArtifact {
            artifact_type: "transition-record",
            artifact_version: "1".to_string(),
            value: parsed.transition_record.value,
            text: parsed.canonical,
            canonical_input: parsed.bytes == bytes,
            bytes: parsed.bytes,
        });
    }
    if let Ok(parsed) = parse_source_evidence_bytes(bytes) {
        return Ok(CanonicalizedArtifact {
            artifact_type: "source-evidence",
            artifact_version: "1".to_string(),
            value: parsed.source_evidence.value,
            text: parsed.canonical,
            canonical_input: parsed.bytes == bytes,
            bytes: parsed.bytes,
        });
    }
    bail!("artifact is not a canonicalizable lifecycle JSON artifact");
}

pub(crate) fn inspect_artifact(path: &Path, bytes: &[u8]) -> Result<Value> {
    if let Ok(canonical) = canonicalize_artifact(bytes) {
        return Ok(serde_json::json!({
            "command": "inspect",
            "ok": true,
            "cliSchemaVersion": 1,
            "file": path,
            "artifactType": canonical.artifact_type,
            "artifactVersion": canonical.artifact_version,
            "encoding": "json",
            "digestAlg": "SHA3-512",
            "digestHex": sha3_512_hex(&canonical.bytes),
            "inputDigestHex": sha3_512_hex(bytes),
            "canonicalInput": canonical.canonical_input,
            "canonicalJson": canonical.value,
            "canonicalJsonText": canonical.text,
            "parsedSummary": {}
        }));
    }
    let parsed_shard = parse_qvqcont7_shard(bytes);
    if let Ok(shard) = parsed_shard {
        return Ok(serde_json::json!({
            "command": "inspect",
            "ok": true,
            "cliSchemaVersion": 1,
            "file": path,
            "artifactType": "qcont",
            "artifactVersion": "QVqcont-7",
            "encoding": "binary",
            "digestAlg": "SHA3-512",
            "digestHex": sha3_512_hex(bytes),
            "canonicalJson": shard.meta_json,
            "canonicalJsonText": String::from_utf8_lossy(&shard.meta_bytes),
            "parsedSummary": {
                "stateId": shard.state_id,
                "cohortId": shard.cohort_id,
                "shardIndex": shard.shard_index,
                "archiveStateDigestHex": shard.archive_state_digest_hex,
                "cohortBindingDigestHex": shard.cohort_binding_digest_hex,
                "lifecycleBundleDigestHex": shard.lifecycle_bundle_digest_hex
            }
        }));
    }
    if path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("qcont"))
    {
        return Err(coded(QvCode::InvalidFormat, "Malformed QVqcont shard").into());
    }

    let parsed_qenc = parse_qenc_header(bytes);
    if let Ok(qenc) = parsed_qenc {
        return Ok(serde_json::json!({
            "command": "inspect",
            "ok": true,
            "cliSchemaVersion": 1,
            "file": path,
            "artifactType": "qenc",
            "artifactVersion": qenc.metadata.fmt,
            "encoding": "binary",
            "digestAlg": "SHA3-512",
            "digestHex": sha3_512_hex(bytes),
            "canonicalJson": qenc.metadata,
            "parsedSummary": {
                "containerId": sha3_512_hex(&qenc.header),
                "aeadMode": qenc.metadata.aead_mode,
                "payloadLength": qenc.metadata.payload_length,
                "chunkSize": qenc.metadata.chunk_size,
                "chunkCount": qenc.metadata.chunk_count,
                "ciphertextLength": bytes.len() - qenc.offset,
            }
        }));
    }
    if path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("qenc"))
    {
        return Err(coded(QvCode::InvalidFormat, "Malformed QENC container").into());
    }
    Ok(serde_json::json!({
        "command": "inspect",
        "ok": true,
        "cliSchemaVersion": 1,
        "file": path,
        "artifactType": "binary",
        "artifactVersion": "unknown",
        "encoding": "binary",
        "digestAlg": "SHA3-512",
        "digestHex": sha3_512_hex(bytes),
        "parsedSummary": {}
    }))
}

pub(crate) fn build_required_policy_report(
    authenticity: &AuthenticityReport,
    required_level: Option<AuthPolicyLevelArg>,
) -> Option<Value> {
    let required = required_level?;
    let declared_level = authenticity.policy.level.as_str();
    let declared_strength = policy_strength(declared_level);
    let required_strength = policy_strength(AuthPolicyLevel::from(required).as_str());
    let declared_at_least = declared_strength >= required_strength;
    let archive_policy_satisfied = authenticity.policy.satisfied;
    let satisfied = archive_policy_satisfied && declared_at_least;
    let required_level_str = AuthPolicyLevel::from(required).as_str();
    let reason = if satisfied {
        format!("Archive policy satisfies required policy level {required_level_str}.")
    } else if archive_policy_satisfied {
        format!(
            "Archive policy level {declared_level} is weaker than required policy level {required_level_str}."
        )
    } else {
        format!("Archive policy did not satisfy its declared level {declared_level}.")
    };
    Some(serde_json::json!({
        "level": required_level_str,
        "declaredPolicyLevel": declared_level,
        "declaredPolicySatisfiesRequired": declared_at_least,
        "archivePolicySatisfied": archive_policy_satisfied,
        "satisfied": satisfied,
        "reason": reason,
    }))
}

pub(crate) fn verify_cli_report_satisfied(
    authenticity: &AuthenticityReport,
    required_policy: Option<&Value>,
) -> bool {
    if !authenticity.policy.satisfied {
        return false;
    }
    let Some(req) = required_policy else {
        return true;
    };
    req.get("satisfied").and_then(Value::as_bool) == Some(true)
}

fn policy_strength(level: &str) -> u8 {
    match level {
        "integrity-only" => 1,
        "any-signature" => 2,
        "strong-pq-signature" => 3,
        _ => 0,
    }
}
