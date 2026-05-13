use serde_json::Value;

use crate::error::{err, Result};
use crate::manifest::jcs::{
    canonicalize_json, canonicalize_json_to_bytes, MANIFEST_CANONICALIZATION_LABEL,
};
use crate::manifest::strict_json::{assert_canonical_bytes, parse_json_bytes_strict};

use super::digests::{normalize_digest_object, sha3_512_digest, DigestObject, SHA3_512_ALG};
use super::validation::{
    exact_keys, exact_string, hex_string, ijson_value, normalize_iso8601, number,
    object_from_pairs, optional_string, string, value_object,
};

pub const TRANSITION_RECORD_SCHEMA: &str = "quantum-vault-transition-record/v1";
pub const TRANSITION_RECORD_VERSION: u64 = 1;
pub const TRANSITION_RECORD_CANONICALIZATION: &str = MANIFEST_CANONICALIZATION_LABEL;
pub const TRANSITION_TYPE_DEFAULT: &str = "same-state-resharing";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionRecord {
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalTransitionRecord {
    pub transition_record: TransitionRecord,
    pub canonical: String,
    pub bytes: Vec<u8>,
    pub digest: DigestObject,
    pub canonicalization_label: String,
}

pub fn validate_transition_record_value(value: &Value) -> Result<TransitionRecord> {
    let source = value_object(value, "transitionRecord")?;
    exact_keys(
        source,
        &[
            "schema",
            "version",
            "canonicalization",
            "transitionType",
            "archiveId",
            "fromStateId",
            "toStateId",
            "fromCohortId",
            "toCohortId",
            "fromCohortBindingDigest",
            "toCohortBindingDigest",
            "reasonCode",
            "performedAt",
            "operatorRole",
            "actorHints",
            "notes",
        ],
        &[],
        "transitionRecord",
    )?;
    let version = super::validation::integer(
        source.get("version"),
        "transitionRecord.version",
        1,
        u64::MAX,
    )?;
    if version != TRANSITION_RECORD_VERSION {
        return Err(err("Unsupported transitionRecord.version"));
    }
    let notes = match optional_string(source.get("notes"), "transitionRecord.notes")? {
        Some(text) => Value::String(text),
        None => Value::Null,
    };
    Ok(TransitionRecord {
        value: object_from_pairs(vec![
            (
                "schema",
                Value::String(exact_string(
                    source.get("schema"),
                    "transitionRecord.schema",
                    TRANSITION_RECORD_SCHEMA,
                )?),
            ),
            ("version", number(version)),
            (
                "canonicalization",
                Value::String(exact_string(
                    source.get("canonicalization"),
                    "transitionRecord.canonicalization",
                    TRANSITION_RECORD_CANONICALIZATION,
                )?),
            ),
            (
                "transitionType",
                Value::String(string(
                    source.get("transitionType"),
                    "transitionRecord.transitionType",
                )?),
            ),
            (
                "archiveId",
                Value::String(hex_string(
                    source.get("archiveId"),
                    "transitionRecord.archiveId",
                    Some(64),
                )?),
            ),
            (
                "fromStateId",
                Value::String(hex_string(
                    source.get("fromStateId"),
                    "transitionRecord.fromStateId",
                    Some(128),
                )?),
            ),
            (
                "toStateId",
                Value::String(hex_string(
                    source.get("toStateId"),
                    "transitionRecord.toStateId",
                    Some(128),
                )?),
            ),
            (
                "fromCohortId",
                Value::String(hex_string(
                    source.get("fromCohortId"),
                    "transitionRecord.fromCohortId",
                    Some(64),
                )?),
            ),
            (
                "toCohortId",
                Value::String(hex_string(
                    source.get("toCohortId"),
                    "transitionRecord.toCohortId",
                    Some(64),
                )?),
            ),
            (
                "fromCohortBindingDigest",
                serde_json::to_value(normalize_digest_object(
                    source
                        .get("fromCohortBindingDigest")
                        .ok_or_else(|| err("Missing transitionRecord.fromCohortBindingDigest"))?,
                    "transitionRecord.fromCohortBindingDigest",
                    Some(SHA3_512_ALG),
                    Some(128),
                )?)?,
            ),
            (
                "toCohortBindingDigest",
                serde_json::to_value(normalize_digest_object(
                    source
                        .get("toCohortBindingDigest")
                        .ok_or_else(|| err("Missing transitionRecord.toCohortBindingDigest"))?,
                    "transitionRecord.toCohortBindingDigest",
                    Some(SHA3_512_ALG),
                    Some(128),
                )?)?,
            ),
            (
                "reasonCode",
                Value::String(string(
                    source.get("reasonCode"),
                    "transitionRecord.reasonCode",
                )?),
            ),
            (
                "performedAt",
                Value::String(normalize_iso8601(
                    source.get("performedAt"),
                    "transitionRecord.performedAt",
                )?),
            ),
            (
                "operatorRole",
                Value::String(string(
                    source.get("operatorRole"),
                    "transitionRecord.operatorRole",
                )?),
            ),
            (
                "actorHints",
                ijson_value(
                    source
                        .get("actorHints")
                        .ok_or_else(|| err("Missing transitionRecord.actorHints"))?,
                    "transitionRecord.actorHints",
                )?,
            ),
            ("notes", notes),
        ]),
    })
}

pub fn canonicalize_transition_record(value: &Value) -> Result<CanonicalTransitionRecord> {
    let transition_record = validate_transition_record_value(value)?;
    let canonical = canonicalize_json(&transition_record.value)?;
    let bytes = canonicalize_json_to_bytes(&transition_record.value)?;
    let digest = sha3_512_digest(&bytes);
    Ok(CanonicalTransitionRecord {
        transition_record,
        canonical,
        bytes,
        digest,
        canonicalization_label: TRANSITION_RECORD_CANONICALIZATION.to_string(),
    })
}

pub fn parse_transition_record_bytes(bytes: &[u8]) -> Result<CanonicalTransitionRecord> {
    let parsed = parse_json_bytes_strict(bytes)?;
    let canonicalized = canonicalize_transition_record(&parsed)?;
    assert_canonical_bytes(bytes, &canonicalized.bytes, "Transition record")?;
    Ok(canonicalized)
}
