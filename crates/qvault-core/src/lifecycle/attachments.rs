use std::collections::HashSet;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use serde_json::Value;

use crate::auth::{get_signature_suite_info, normalize_signature_suite};
use crate::error::{err, Result};

use super::digests::{normalize_digest_object, SHA256_ALG, SHA3_512_ALG};
use super::validation::{
    base64_string, exact_keys, exact_string, object_from_pairs, string, value_object,
};

const STELLAR_BASE32_ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const STRKEY_VERSION_ED25519_PUBLIC: u8 = 6 << 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyEntry {
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetachedSignatureEntry {
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimestampEntry {
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleAttachments {
    pub value: Value,
}

fn pq_public_key_len(suite: &str) -> Option<usize> {
    match suite {
        "mldsa-44" => Some(1312),
        "mldsa-65" => Some(1952),
        "mldsa-87" => Some(2592),
        "slhdsa-shake-128s" => Some(32),
        "slhdsa-shake-192s" => Some(48),
        "slhdsa-shake-256s" => Some(64),
        "slhdsa-shake-256f" => Some(64),
        _ => None,
    }
}

fn crc16_xmodem(bytes: &[u8]) -> u16 {
    let mut crc = 0u16;
    for byte in bytes {
        crc ^= u16::from(*byte) << 8;
        for _ in 0..8 {
            if (crc & 0x8000) != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

fn base32_decode(text: &str) -> Result<Vec<u8>> {
    let clean = text.trim().trim_end_matches('=');
    if clean.is_empty() {
        return Err(err("Invalid bundled public key"));
    }
    let mut bits = 0u32;
    let mut value = 0u32;
    let mut out = Vec::new();
    for ch in clean.chars() {
        let Some(index) = STELLAR_BASE32_ALPHABET.find(ch) else {
            return Err(err("Invalid bundled public key"));
        };
        value = (value << 5) | index as u32;
        bits += 5;
        if bits >= 8 {
            out.push(((value >> (bits - 8)) & 0xff) as u8);
            bits -= 8;
        }
    }
    Ok(out)
}

fn decode_stellar_address(value: &str) -> Result<[u8; 32]> {
    let text = value.trim();
    if text.len() != 56
        || !text.starts_with('G')
        || !text.chars().all(|ch| matches!(ch, 'A'..='Z' | '2'..='7'))
    {
        return Err(err("Invalid bundled public key"));
    }
    let decoded = base32_decode(text)?;
    if decoded.len() < 3 {
        return Err(err("Invalid bundled public key"));
    }
    let payload_end = decoded.len() - 2;
    let payload = &decoded[..payload_end];
    let checksum = &decoded[payload_end..];
    let expected = crc16_xmodem(payload);
    let actual = u16::from(checksum[0]) | (u16::from(checksum[1]) << 8);
    if expected != actual || payload.first().copied() != Some(STRKEY_VERSION_ED25519_PUBLIC) {
        return Err(err("Invalid bundled public key"));
    }
    let raw = &payload[1..];
    raw.try_into()
        .map_err(|_| err("Invalid bundled public key"))
}

fn decode_public_key(entry: &Value, field: &str) -> Result<()> {
    let source = value_object(entry, field)?;
    let encoding = string(source.get("encoding"), &format!("{field}.encoding"))?;
    let suite = string(source.get("suite"), &format!("{field}.suite"))?;
    let value = string(source.get("value"), &format!("{field}.value"))?;
    if encoding == "base64" {
        let bytes = BASE64_STANDARD
            .decode(value.as_bytes())
            .map_err(|_| err(format!("Invalid {field}.value")))?;
        let expected =
            pq_public_key_len(&suite).ok_or_else(|| err(format!("Invalid {field}.suite")))?;
        if bytes.len() != expected {
            return Err(err(format!("Invalid {field}.value")));
        }
    } else if encoding == "stellar-address" {
        decode_stellar_address(&value)?;
    } else {
        return Err(err(format!("Unsupported {field}.encoding")));
    }
    Ok(())
}

pub fn normalize_public_key_entry(value: &Value, index: usize) -> Result<PublicKeyEntry> {
    let field = format!("attachments.publicKeys[{index}]");
    let source = value_object(value, &field)?;
    exact_keys(
        source,
        &["id", "kty", "suite", "encoding", "value"],
        &[],
        &field,
    )?;
    let id = string(source.get("id"), &format!("{field}.id"))?;
    let kty = string(source.get("kty"), &format!("{field}.kty"))?;
    if !matches!(
        kty.as_str(),
        "ml-dsa-public-key" | "slh-dsa-public-key" | "ed25519-public-key"
    ) {
        return Err(err(format!("Unsupported {field}.kty")));
    }
    let suite =
        normalize_signature_suite(&string(source.get("suite"), &format!("{field}.suite"))?)?
            .to_string();
    let suite_info = get_signature_suite_info(&suite)?;
    if suite_info.public_key_type != kty {
        return Err(err(format!("Invalid {field}.kty")));
    }
    let encoding = string(source.get("encoding"), &format!("{field}.encoding"))?;
    if !matches!(encoding.as_str(), "base64" | "stellar-address") {
        return Err(err(format!("Unsupported {field}.encoding")));
    }
    if encoding == "base64" && suite == "ed25519" {
        return Err(err(format!("Invalid {field}.encoding")));
    }
    if encoding == "stellar-address" && suite != "ed25519" {
        return Err(err(format!("Invalid {field}.encoding")));
    }
    let value_text = if encoding == "base64" {
        base64_string(source.get("value"), &format!("{field}.value"))?
    } else {
        string(source.get("value"), &format!("{field}.value"))?
    };
    let normalized = object_from_pairs(vec![
        ("id", Value::String(id)),
        ("kty", Value::String(kty)),
        ("suite", Value::String(suite)),
        ("encoding", Value::String(encoding)),
        ("value", Value::String(value_text)),
    ]);
    decode_public_key(&normalized, &field)?;
    Ok(PublicKeyEntry { value: normalized })
}

pub fn normalize_detached_signature_entry(
    value: &Value,
    index: usize,
    family_field: &str,
) -> Result<DetachedSignatureEntry> {
    let field = format!("{family_field}[{index}]");
    let source = value_object(value, &field)?;
    exact_keys(
        source,
        &[
            "id",
            "signatureFamily",
            "format",
            "suite",
            "targetType",
            "targetRef",
            "targetDigest",
            "signatureEncoding",
            "signature",
        ],
        &["publicKeyRef"],
        &field,
    )?;
    let signature_family = string(
        source.get("signatureFamily"),
        &format!("{field}.signatureFamily"),
    )?;
    if !matches!(
        signature_family.as_str(),
        "archive-approval" | "maintenance" | "source-evidence"
    ) {
        return Err(err(format!("Unsupported {field}.signatureFamily")));
    }
    let format = string(source.get("format"), &format!("{field}.format"))?;
    if !matches!(format.as_str(), "qsig" | "stellar-sig") {
        return Err(err(format!("Unsupported {field}.format")));
    }
    let suite =
        normalize_signature_suite(&string(source.get("suite"), &format!("{field}.suite"))?)?
            .to_string();
    if format == "qsig" && suite == "ed25519" {
        return Err(err(format!("Invalid {field}.suite")));
    }
    if format == "stellar-sig" && suite != "ed25519" {
        return Err(err(format!("Invalid {field}.suite")));
    }
    let target_type = string(source.get("targetType"), &format!("{field}.targetType"))?;
    if !matches!(
        target_type.as_str(),
        "archive-state" | "transition-record" | "source-evidence"
    ) {
        return Err(err(format!("Unsupported {field}.targetType")));
    }
    let mut pairs = vec![
        (
            "id",
            Value::String(string(source.get("id"), &format!("{field}.id"))?),
        ),
        ("signatureFamily", Value::String(signature_family)),
        ("format", Value::String(format)),
        ("suite", Value::String(suite)),
        ("targetType", Value::String(target_type)),
        (
            "targetRef",
            Value::String(string(
                source.get("targetRef"),
                &format!("{field}.targetRef"),
            )?),
        ),
        (
            "targetDigest",
            serde_json::to_value(normalize_digest_object(
                source
                    .get("targetDigest")
                    .ok_or_else(|| err(format!("Missing {field}.targetDigest")))?,
                &format!("{field}.targetDigest"),
                Some(SHA3_512_ALG),
                Some(128),
            )?)?,
        ),
        (
            "signatureEncoding",
            Value::String(exact_string(
                source.get("signatureEncoding"),
                &format!("{field}.signatureEncoding"),
                "base64",
            )?),
        ),
        (
            "signature",
            Value::String(base64_string(
                source.get("signature"),
                &format!("{field}.signature"),
            )?),
        ),
    ];
    // Oracle `artifacts.js` normalizes with `ensureOptionalString`: the member is
    // always present in the canonical entry and serializes as `null` when no
    // signer key is pinned (the common "unpinned evidence" attach path).
    let public_key_ref = match source.get("publicKeyRef") {
        None | Some(Value::Null) => Value::Null,
        Some(value) => Value::String(string(Some(value), &format!("{field}.publicKeyRef"))?),
    };
    pairs.push(("publicKeyRef", public_key_ref));
    Ok(DetachedSignatureEntry {
        value: object_from_pairs(pairs),
    })
}

pub fn normalize_timestamp_entry(value: &Value, index: usize) -> Result<TimestampEntry> {
    let field = format!("attachments.timestamps[{index}]");
    let source = value_object(value, &field)?;
    exact_keys(
        source,
        &[
            "id",
            "type",
            "targetRef",
            "targetDigest",
            "proofEncoding",
            "proof",
        ],
        &[],
        &field,
    )?;
    Ok(TimestampEntry {
        value: object_from_pairs(vec![
            (
                "id",
                Value::String(string(source.get("id"), &format!("{field}.id"))?),
            ),
            (
                "type",
                Value::String(exact_string(
                    source.get("type"),
                    &format!("{field}.type"),
                    "opentimestamps",
                )?),
            ),
            (
                "targetRef",
                Value::String(string(
                    source.get("targetRef"),
                    &format!("{field}.targetRef"),
                )?),
            ),
            (
                "targetDigest",
                serde_json::to_value(normalize_digest_object(
                    source
                        .get("targetDigest")
                        .ok_or_else(|| err(format!("Missing {field}.targetDigest")))?,
                    &format!("{field}.targetDigest"),
                    Some(SHA256_ALG),
                    Some(64),
                )?)?,
            ),
            (
                "proofEncoding",
                Value::String(exact_string(
                    source.get("proofEncoding"),
                    &format!("{field}.proofEncoding"),
                    "base64",
                )?),
            ),
            (
                "proof",
                Value::String(base64_string(
                    source.get("proof"),
                    &format!("{field}.proof"),
                )?),
            ),
        ]),
    })
}

fn normalize_array<F>(value: Option<&Value>, field: &str, mut normalize: F) -> Result<Vec<Value>>
where
    F: FnMut(&Value, usize) -> Result<Value>,
{
    let Some(Value::Array(values)) = value else {
        return Err(err(format!("Invalid {field}")));
    };
    values
        .iter()
        .enumerate()
        .map(|(index, item)| normalize(item, index))
        .collect()
}

pub fn validate_lifecycle_attachments_value(value: &Value) -> Result<LifecycleAttachments> {
    let source = value_object(value, "lifecycleBundle.attachments")?;
    exact_keys(
        source,
        &[
            "publicKeys",
            "archiveApprovalSignatures",
            "maintenanceSignatures",
            "sourceEvidenceSignatures",
            "timestamps",
        ],
        &[],
        "lifecycleBundle.attachments",
    )?;
    let public_keys = normalize_array(
        source.get("publicKeys"),
        "lifecycleBundle.attachments.publicKeys",
        |item, index| normalize_public_key_entry(item, index).map(|entry| entry.value),
    )?;
    let archive_approval = normalize_array(
        source.get("archiveApprovalSignatures"),
        "lifecycleBundle.attachments.archiveApprovalSignatures",
        |item, index| {
            normalize_detached_signature_entry(item, index, "attachments.archiveApprovalSignatures")
                .map(|entry| entry.value)
        },
    )?;
    let maintenance = normalize_array(
        source.get("maintenanceSignatures"),
        "lifecycleBundle.attachments.maintenanceSignatures",
        |item, index| {
            normalize_detached_signature_entry(item, index, "attachments.maintenanceSignatures")
                .map(|entry| entry.value)
        },
    )?;
    let source_evidence = normalize_array(
        source.get("sourceEvidenceSignatures"),
        "lifecycleBundle.attachments.sourceEvidenceSignatures",
        |item, index| {
            normalize_detached_signature_entry(item, index, "attachments.sourceEvidenceSignatures")
                .map(|entry| entry.value)
        },
    )?;
    let timestamps = normalize_array(
        source.get("timestamps"),
        "lifecycleBundle.attachments.timestamps",
        |item, index| normalize_timestamp_entry(item, index).map(|entry| entry.value),
    )?;

    assert_unique_ids(&public_keys, "publicKey")?;
    assert_unique_ids(&timestamps, "timestamp")?;
    let mut all_signatures = Vec::new();
    all_signatures.extend(archive_approval.iter().cloned());
    all_signatures.extend(maintenance.iter().cloned());
    all_signatures.extend(source_evidence.iter().cloned());
    assert_unique_ids(&all_signatures, "detached signature")?;

    Ok(LifecycleAttachments {
        value: object_from_pairs(vec![
            ("publicKeys", Value::Array(public_keys)),
            ("archiveApprovalSignatures", Value::Array(archive_approval)),
            ("maintenanceSignatures", Value::Array(maintenance)),
            ("sourceEvidenceSignatures", Value::Array(source_evidence)),
            ("timestamps", Value::Array(timestamps)),
        ]),
    })
}

fn assert_unique_ids(entries: &[Value], field: &str) -> Result<()> {
    let mut seen = HashSet::new();
    for entry in entries {
        let source = value_object(entry, field)?;
        let id = string(source.get("id"), &format!("{field}.id"))?;
        if !seen.insert(id.clone()) {
            return Err(err(format!("Duplicate {field} id: {id}")));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::jcs::canonicalize_json;
    use serde_json::json;

    fn unpinned_signature_entry(public_key_ref: Option<Value>) -> Value {
        let mut entry = json!({
            "id": "sig-0011223344556677",
            "signatureFamily": "archive-approval",
            "format": "qsig",
            "suite": "mldsa-87",
            "targetType": "archive-state",
            "targetRef": format!("state:{}", "ab".repeat(64)),
            "targetDigest": { "alg": "SHA3-512", "value": "ab".repeat(64) },
            "signatureEncoding": "base64",
            "signature": "AAECAw==",
        });
        if let (Value::Object(map), Some(reference)) = (&mut entry, public_key_ref) {
            map.insert("publicKeyRef".to_string(), reference);
        }
        entry
    }

    #[test]
    fn unpinned_entry_canonicalizes_with_null_public_key_ref() {
        // Oracle parity: JS `normalizeDetachedSignatureEntry` always emits the
        // member; JCS serializes it as `"publicKeyRef":null`.
        let entry = unpinned_signature_entry(None);
        let normalized = normalize_detached_signature_entry(&entry, 0, "archiveApprovalSignatures")
            .expect("normalize entry without publicKeyRef");
        let canonical = canonicalize_json(&normalized.value).expect("canonicalize");
        assert!(
            canonical.contains("\"publicKeyRef\":null"),
            "canonical entry must carry the null member: {canonical}"
        );
    }

    #[test]
    fn explicit_null_public_key_ref_is_accepted_as_unpinned() {
        let entry = unpinned_signature_entry(Some(Value::Null));
        let normalized = normalize_detached_signature_entry(&entry, 0, "archiveApprovalSignatures")
            .expect("JS-produced bundles carry publicKeyRef:null and must parse");
        assert_eq!(normalized.value.get("publicKeyRef"), Some(&Value::Null));
    }

    #[test]
    fn empty_string_public_key_ref_is_rejected() {
        let entry = unpinned_signature_entry(Some(json!("")));
        assert!(
            normalize_detached_signature_entry(&entry, 0, "archiveApprovalSignatures").is_err(),
            "empty-string publicKeyRef must fail closed like the oracle"
        );
    }
}
