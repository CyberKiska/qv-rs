use std::collections::HashSet;

use serde_json::Value;

use crate::error::{err, Result};
use crate::manifest::jcs::{
    canonicalize_json, canonicalize_json_to_bytes, MANIFEST_CANONICALIZATION_LABEL,
};
use crate::manifest::strict_json::{assert_canonical_bytes, parse_json_bytes_strict};

use super::digests::{
    normalize_digest_object, sha3_512_digest, DigestObject, SHA256_ALG, SHA3_256_ALG, SHA3_512_ALG,
};
use super::validation::{
    array, exact_keys, exact_string, number, object_from_pairs, string, string_array, value_object,
};

pub const SOURCE_EVIDENCE_SCHEMA: &str = "quantum-vault-source-evidence/v1";
pub const SOURCE_EVIDENCE_VERSION: u64 = 1;
pub const SOURCE_EVIDENCE_CANONICALIZATION: &str = MANIFEST_CANONICALIZATION_LABEL;
pub const SOURCE_EVIDENCE_TYPE_DEFAULT: &str = "source-evidence";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceEvidence {
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalSourceEvidence {
    pub source_evidence: SourceEvidence,
    pub canonical: String,
    pub bytes: Vec<u8>,
    pub digest: DigestObject,
    pub canonicalization_label: String,
}

pub fn normalize_digest_array(value: Option<&Value>, field: &str) -> Result<Value> {
    let values = array(value, field)?;
    if values.is_empty() {
        return Err(err(format!("Invalid {field}")));
    }
    let mut out = Vec::with_capacity(values.len());
    let mut seen_entries = HashSet::new();
    let mut seen_algs = HashSet::new();
    for (index, item) in values.iter().enumerate() {
        let source = value_object(item, &format!("{field}[{index}]"))?;
        let alg = string(source.get("alg"), &format!("{field}[{index}].alg"))?;
        let expected_len = match alg.as_str() {
            SHA3_512_ALG => 128,
            SHA3_256_ALG | SHA256_ALG => 64,
            _ => return Err(err(format!("Invalid {field}[{index}].alg"))),
        };
        let digest = normalize_digest_object(
            item,
            &format!("{field}[{index}]"),
            Some(&alg),
            Some(expected_len),
        )?;
        let entry_key = format!("{}:{}", digest.alg, digest.value);
        if !seen_entries.insert(entry_key) {
            return Err(err(format!("Duplicate {field} entry")));
        }
        if !seen_algs.insert(digest.alg.clone()) {
            return Err(err(format!("Duplicate {field}.alg")));
        }
        out.push(serde_json::to_value(digest)?);
    }
    Ok(Value::Array(out))
}

pub fn validate_source_evidence_value(value: &Value) -> Result<SourceEvidence> {
    let source = value_object(value, "sourceEvidence")?;
    exact_keys(
        source,
        &[
            "schema",
            "version",
            "sourceEvidenceType",
            "canonicalization",
            "relationType",
            "sourceObjectType",
            "sourceDigests",
        ],
        &["externalSourceSignatureRefs", "mediaType"],
        "sourceEvidence",
    )?;
    let version =
        super::validation::integer(source.get("version"), "sourceEvidence.version", 1, u64::MAX)?;
    if version != SOURCE_EVIDENCE_VERSION {
        return Err(err("Unsupported sourceEvidence.version"));
    }
    let mut pairs = vec![
        (
            "schema",
            Value::String(exact_string(
                source.get("schema"),
                "sourceEvidence.schema",
                SOURCE_EVIDENCE_SCHEMA,
            )?),
        ),
        ("version", number(version)),
        (
            "sourceEvidenceType",
            Value::String(string(
                source.get("sourceEvidenceType"),
                "sourceEvidence.sourceEvidenceType",
            )?),
        ),
        (
            "canonicalization",
            Value::String(exact_string(
                source.get("canonicalization"),
                "sourceEvidence.canonicalization",
                SOURCE_EVIDENCE_CANONICALIZATION,
            )?),
        ),
        (
            "relationType",
            Value::String(string(
                source.get("relationType"),
                "sourceEvidence.relationType",
            )?),
        ),
        (
            "sourceObjectType",
            Value::String(string(
                source.get("sourceObjectType"),
                "sourceEvidence.sourceObjectType",
            )?),
        ),
        (
            "sourceDigests",
            normalize_digest_array(source.get("sourceDigests"), "sourceEvidence.sourceDigests")?,
        ),
    ];
    if source.contains_key("externalSourceSignatureRefs") {
        let refs = string_array(
            source.get("externalSourceSignatureRefs"),
            "sourceEvidence.externalSourceSignatureRefs",
            1,
        )?;
        let mut seen = HashSet::new();
        for value in &refs {
            if !seen.insert(value.clone()) {
                return Err(err(
                    "Duplicate sourceEvidence.externalSourceSignatureRefs value",
                ));
            }
        }
        pairs.push((
            "externalSourceSignatureRefs",
            Value::Array(refs.into_iter().map(Value::String).collect()),
        ));
    }
    if source.contains_key("mediaType") {
        pairs.push((
            "mediaType",
            Value::String(string(source.get("mediaType"), "sourceEvidence.mediaType")?),
        ));
    }
    Ok(SourceEvidence {
        value: object_from_pairs(pairs),
    })
}

pub fn canonicalize_source_evidence(value: &Value) -> Result<CanonicalSourceEvidence> {
    let source_evidence = validate_source_evidence_value(value)?;
    let canonical = canonicalize_json(&source_evidence.value)?;
    let bytes = canonicalize_json_to_bytes(&source_evidence.value)?;
    let digest = sha3_512_digest(&bytes);
    Ok(CanonicalSourceEvidence {
        source_evidence,
        canonical,
        bytes,
        digest,
        canonicalization_label: SOURCE_EVIDENCE_CANONICALIZATION.to_string(),
    })
}

pub fn parse_source_evidence_bytes(bytes: &[u8]) -> Result<CanonicalSourceEvidence> {
    let parsed = parse_json_bytes_strict(bytes)?;
    let canonicalized = canonicalize_source_evidence(&parsed)?;
    assert_canonical_bytes(bytes, &canonicalized.bytes, "Source evidence")?;
    Ok(canonicalized)
}
