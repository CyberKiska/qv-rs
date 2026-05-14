//! External detached archive-approval signature classification.
//!
//! Matches the oracle (`quantum-vault` `detectExternalLifecycleSignatureType` /
//! `isSupportedStellarSignatureDocumentBytes`): PQSG-prefixed `.qsig`, or strict JSON
//! satisfying the supported `stellar-signature/v2` profiles. No filename heuristics;
//! unknown bytes are rejected before routing to a verifier.

use serde_json::{Map, Value};

use crate::error::{err, Result};
use crate::lifecycle::{exact_keys, value_object};
use crate::manifest::strict_json::parse_json_bytes_strict;

pub const MAGIC_QSIG: &[u8; 4] = b"PQSG";

const STELLAR_SIGNATURE_SCHEMA_V2: &str = "stellar-signature/v2";
const PROOF_TYPE_SEP53_MESSAGE: &str = "sep53-message-signature";
const PAYLOAD_TYPE_RAW_BYTES: &str = "raw-bytes";
const SIGNATURE_SCHEME_SEP53_SHA256_ED25519: &str = "sep53-sha256-ed25519";
const PROOF_TYPE_XDR_ENVELOPE: &str = "xdr-envelope-proof";
const PAYLOAD_TYPE_DETACHED_DIGESTS: &str = "detached-digests";
const SIGNATURE_SCHEME_TX_ENVELOPE_ED25519: &str = "tx-envelope-ed25519";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetachedArchiveApprovalKind {
    Qsig,
    StellarJson,
}

fn trim_nonempty_string(value: Option<&Value>, field: &str) -> Result<String> {
    let Some(Value::String(text)) = value else {
        return Err(err(format!("Invalid {field}")));
    };
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(err(format!("Invalid {field}")));
    }
    Ok(trimmed.to_string())
}

/// `true` when `bytes` are strict JSON describing a supported Stellar signature document,
/// per `quantum-vault` `validateSupportedStellarSignatureDocument` / `isSupportedStellarSignatureDocumentBytes`.
pub fn is_supported_stellar_signature_document_bytes(bytes: &[u8]) -> bool {
    let Ok(value) = parse_json_bytes_strict(bytes) else {
        return false;
    };
    try_validate_supported_stellar_signature_document(&value).is_ok()
}

/// Classify detached archive-approval bytes for external `--sig` style inputs.
pub fn classify_detached_archive_approval_bytes(bytes: &[u8]) -> Result<DetachedArchiveApprovalKind> {
    if bytes.is_empty() {
        return Err(err("Detached signature bytes are empty"));
    }
    if bytes.len() >= MAGIC_QSIG.len() && bytes[..MAGIC_QSIG.len()] == *MAGIC_QSIG {
        return Ok(DetachedArchiveApprovalKind::Qsig);
    }
    let value = parse_json_bytes_strict(bytes).map_err(|error| {
        err(format!(
            "Unsupported detached archive-approval signature: not PQSG-prefixed .qsig and not strict JSON ({error})"
        ))
    })?;
    if try_validate_supported_stellar_signature_document(&value).is_ok() {
        return Ok(DetachedArchiveApprovalKind::StellarJson);
    }
    Err(err(
        "Unsupported detached archive-approval signature: JSON is not a supported Stellar signature document",
    ))
}

/// Structural validation mirroring the oracle's `validateSupportedStellarSignatureDocument`
/// (keys + profile tuple + minimal field presence). Hash entry semantics are enforced in verify.
pub fn try_validate_supported_stellar_signature_document(doc: &Value) -> Result<()> {
    let obj = value_object(doc, "stellarSignature")?;
    let schema = trim_nonempty_string(obj.get("schema"), "stellarSignature.schema")?;
    if schema != STELLAR_SIGNATURE_SCHEMA_V2 {
        return Err(err(format!(
            "Unsupported Stellar signature profile: {schema}"
        )));
    }
    let proof_type = trim_nonempty_string(obj.get("proofType"), "stellarSignature.proofType")?;
    let payload_type =
        trim_nonempty_string(obj.get("payloadType"), "stellarSignature.payloadType")?;
    let signature_scheme =
        trim_nonempty_string(obj.get("signatureScheme"), "stellarSignature.signatureScheme")?;

    let (required, optional): (&[&str], &[&str]) = match (
        proof_type.as_str(),
        payload_type.as_str(),
        signature_scheme.as_str(),
    ) {
        (
            PROOF_TYPE_SEP53_MESSAGE,
            PAYLOAD_TYPE_RAW_BYTES,
            SIGNATURE_SCHEME_SEP53_SHA256_ED25519,
        ) => (
            &[
                "schema",
                "proofType",
                "payloadType",
                "signatureScheme",
                "signer",
                "hashes",
                "signatureB64",
            ],
            &["input"][..],
        ),
        (
            PROOF_TYPE_XDR_ENVELOPE,
            PAYLOAD_TYPE_DETACHED_DIGESTS,
            SIGNATURE_SCHEME_TX_ENVELOPE_ED25519,
        ) => (
            &[
                "schema",
                "proofType",
                "payloadType",
                "signatureScheme",
                "signer",
                "hashes",
                "manageData",
                "network",
                "signedXdr",
            ],
            &["input", "txSourceAccount"][..],
        ),
        _ => {
            return Err(err(format!(
                "Unsupported Stellar signature profile: {schema} / {proof_type} / {signature_scheme}"
            )));
        }
    };
    exact_keys(obj, required, optional, "stellarSignature")?;
    let _ = trim_nonempty_string(obj.get("signer"), "stellarSignature.signer")?;
    match (
        proof_type.as_str(),
        payload_type.as_str(),
        signature_scheme.as_str(),
    ) {
        (
            PROOF_TYPE_SEP53_MESSAGE,
            PAYLOAD_TYPE_RAW_BYTES,
            SIGNATURE_SCHEME_SEP53_SHA256_ED25519,
        ) => {
            let _ = trim_nonempty_string(obj.get("signatureB64"), "stellarSignature.signatureB64")?;
            let hashes = obj
                .get("hashes")
                .and_then(Value::as_array)
                .ok_or_else(|| err("Invalid stellarSignature.hashes"))?;
            if hashes.is_empty() {
                return Err(err("Signature has no hashes[] entries"));
            }
        }
        (
            PROOF_TYPE_XDR_ENVELOPE,
            PAYLOAD_TYPE_DETACHED_DIGESTS,
            SIGNATURE_SCHEME_TX_ENVELOPE_ED25519,
        ) => {
            let _ = trim_nonempty_string(obj.get("network"), "stellarSignature.network")?;
            let _ = trim_nonempty_string(obj.get("signedXdr"), "stellarSignature.signedXdr")?;
            let manage_data = obj
                .get("manageData")
                .and_then(Value::as_object)
                .ok_or_else(|| err("Invalid stellarSignature.manageData"))?;
            let entries = manage_data
                .get("entries")
                .and_then(Value::as_array)
                .ok_or_else(|| err("manageData.entries must be an array."))?;
            if entries.is_empty() {
                return Err(err("manageData.entries must not be empty."));
            }
            let hashes = obj
                .get("hashes")
                .and_then(Value::as_array)
                .ok_or_else(|| err("Invalid stellarSignature.hashes"))?;
            if hashes.is_empty() {
                return Err(err("Signature has no hashes[] entries"));
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}

/// Whether `value` is a strict JSON object for legacy `stellar-file-signature/v1` (verified separately).
pub fn is_stellar_file_signature_v1_document(value: &Value) -> bool {
    let Some(obj) = value.as_object() else {
        return false;
    };
    match trim_nonempty_string(obj.get("schema"), "schema") {
        Ok(schema) if schema == "stellar-file-signature/v1" => {}
        _ => return false,
    }
    match trim_nonempty_string(obj.get("mode"), "mode") {
        Ok(mode) if mode == "sep53" => true,
        _ => false,
    }
}

/// Proof kind after oracle-style v2 structural validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StellarV2ProofKind {
    Sep53Message,
    XdrEnvelope,
}

pub fn stellar_v2_proof_kind(doc: &Value) -> Result<StellarV2ProofKind> {
    try_validate_supported_stellar_signature_document(doc)?;
    let obj = value_object(doc, "stellarSignature")?;
    let proof_type = trim_nonempty_string(obj.get("proofType"), "stellarSignature.proofType")?;
    match proof_type.as_str() {
        PROOF_TYPE_SEP53_MESSAGE => Ok(StellarV2ProofKind::Sep53Message),
        PROOF_TYPE_XDR_ENVELOPE => Ok(StellarV2ProofKind::XdrEnvelope),
        _ => Err(err("Unsupported stellarSignature.proofType")),
    }
}

pub fn stellar_v2_input_descriptor(doc: &Value) -> Result<Option<Map<String, Value>>> {
    let obj = value_object(doc, "stellarSignature")?;
    match obj.get("input") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(map)) => Ok(Some(map.clone())),
        Some(_) => Err(err("Invalid stellarSignature.input")),
    }
}
