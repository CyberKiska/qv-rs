//! Detached signature proof identity (oracle: `signature-identity.js`).
//! Used for deduplicated archive-policy counting on successor restore.

use serde::Serialize;
use serde_json::Value;

use crate::hash::sha3_512;
use crate::manifest::jcs::canonicalize_json;
use crate::manifest::strict_json::parse_json_bytes_strict;

const STELLAR_V2_SCHEMA: &str = "stellar-signature/v2";
const SEP53_MESSAGE: &str = "sep53-message-signature";
const RAW_BYTES: &str = "raw-bytes";
const SEP53_SHA256_ED25519: &str = "sep53-sha256-ed25519";
const XDR_ENVELOPE: &str = "xdr-envelope-proof";
const DETACHED_DIGESTS: &str = "detached-digests";
const TX_ENVELOPE_ED25519: &str = "tx-envelope-ed25519";

#[derive(Debug, Clone, Serialize)]
struct StellarHashEntry {
    alg: String,
    hex: String,
}

#[derive(Debug, Clone, Serialize)]
struct ManageDataEntry {
    name: String,
    alg: String,
    #[serde(rename = "digestHex")]
    digest_hex: String,
}

#[derive(Debug, Clone, Serialize)]
struct StellarV2Sep53Identity {
    format: &'static str,
    schema: String,
    #[serde(rename = "proofType")]
    proof_type: String,
    #[serde(rename = "payloadType")]
    payload_type: String,
    #[serde(rename = "signatureScheme")]
    signature_scheme: String,
    signer: String,
    #[serde(rename = "signatureB64")]
    signature_b64: String,
    hashes: Vec<StellarHashEntry>,
}

#[derive(Debug, Clone, Serialize)]
struct StellarV2XdrIdentity {
    format: &'static str,
    schema: String,
    #[serde(rename = "proofType")]
    proof_type: String,
    #[serde(rename = "payloadType")]
    payload_type: String,
    #[serde(rename = "signatureScheme")]
    signature_scheme: String,
    signer: String,
    #[serde(rename = "networkPassphrase")]
    network_passphrase: String,
    #[serde(rename = "signedXdr")]
    signed_xdr: String,
    hashes: Vec<StellarHashEntry>,
    #[serde(rename = "manageDataEntries")]
    manage_data_entries: Vec<ManageDataEntry>,
}

fn normalize_hash_entries(value: &Value) -> Option<Vec<StellarHashEntry>> {
    let arr = value.as_array()?;
    let mut out = Vec::with_capacity(arr.len());
    for entry in arr {
        let obj = entry.as_object()?;
        let alg = obj.get("alg")?.as_str()?.trim().to_ascii_uppercase();
        let hex = obj.get("hex")?.as_str()?.trim().to_ascii_lowercase();
        if alg.is_empty() || hex.is_empty() {
            return None;
        }
        out.push(StellarHashEntry { alg, hex });
    }
    out.sort_by(|a, b| a.alg.cmp(&b.alg).then_with(|| a.hex.cmp(&b.hex)));
    Some(out)
}

fn normalize_manage_data_entries(value: Option<&Value>) -> Vec<ManageDataEntry> {
    let Some(Value::Array(entries)) = value else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries {
        let Some(obj) = entry.as_object() else {
            continue;
        };
        let name = obj.get("name").and_then(Value::as_str).unwrap_or("").trim();
        let alg = obj
            .get("alg")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_ascii_uppercase();
        let digest_hex = obj
            .get("digestHex")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if name.is_empty() || alg.is_empty() || digest_hex.is_empty() {
            continue;
        }
        out.push(ManageDataEntry {
            name: name.to_string(),
            alg,
            digest_hex,
        });
    }
    out.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then_with(|| a.alg.cmp(&b.alg))
            .then_with(|| a.digest_hex.cmp(&b.digest_hex))
    });
    out
}

fn stellar_v2_sep53_identity_payload_from_doc(doc: &Value) -> Option<Vec<u8>> {
    let schema = doc.get("schema")?.as_str()?.trim();
    if schema != STELLAR_V2_SCHEMA {
        return None;
    }
    let proof_type = doc.get("proofType")?.as_str()?.trim();
    let payload_type = doc.get("payloadType")?.as_str()?.trim();
    let signature_scheme = doc.get("signatureScheme")?.as_str()?.trim();
    let signer = doc.get("signer")?.as_str()?.trim();
    if proof_type != SEP53_MESSAGE
        || payload_type != RAW_BYTES
        || signature_scheme != SEP53_SHA256_ED25519
    {
        return None;
    }
    let signature_b64 = doc.get("signatureB64")?.as_str()?.trim();
    if signature_b64.is_empty() || signer.is_empty() {
        return None;
    }
    let hashes = normalize_hash_entries(doc.get("hashes")?)?;
    let identity = StellarV2Sep53Identity {
        format: "stellar-sig",
        schema: schema.to_string(),
        proof_type: proof_type.to_string(),
        payload_type: payload_type.to_string(),
        signature_scheme: signature_scheme.to_string(),
        signer: signer.to_string(),
        signature_b64: signature_b64.to_string(),
        hashes,
    };
    let canonical = canonicalize_json(&identity).ok()?;
    Some(canonical.into_bytes())
}

fn stellar_v2_xdr_identity_payload_from_doc(doc: &Value) -> Option<Vec<u8>> {
    let schema = doc.get("schema")?.as_str()?.trim();
    if schema != STELLAR_V2_SCHEMA {
        return None;
    }
    let proof_type = doc.get("proofType")?.as_str()?.trim();
    let payload_type = doc.get("payloadType")?.as_str()?.trim();
    let signature_scheme = doc.get("signatureScheme")?.as_str()?.trim();
    let signer = doc.get("signer")?.as_str()?.trim();
    if proof_type != XDR_ENVELOPE
        || payload_type != DETACHED_DIGESTS
        || signature_scheme != TX_ENVELOPE_ED25519
    {
        return None;
    }
    let signed_xdr = doc.get("signedXdr")?.as_str()?.trim();
    let network_passphrase = doc
        .get("network")?
        .as_object()?
        .get("passphrase")?
        .as_str()?
        .trim();
    if signed_xdr.is_empty() || network_passphrase.is_empty() || signer.is_empty() {
        return None;
    }
    let hashes = normalize_hash_entries(doc.get("hashes")?)?;
    let manage_data_entries = normalize_manage_data_entries(
        doc.get("manageData")
            .and_then(|md| md.as_object())
            .and_then(|m| m.get("entries")),
    );
    let identity = StellarV2XdrIdentity {
        format: "stellar-sig",
        schema: schema.to_string(),
        proof_type: proof_type.to_string(),
        payload_type: payload_type.to_string(),
        signature_scheme: signature_scheme.to_string(),
        signer: signer.to_string(),
        network_passphrase: network_passphrase.to_string(),
        signed_xdr: signed_xdr.to_string(),
        hashes,
        manage_data_entries,
    };
    let canonical = canonicalize_json(&identity).ok()?;
    Some(canonical.into_bytes())
}

fn stellar_proof_identity_canonical_bytes(signature_bytes: &[u8]) -> Option<Vec<u8>> {
    let doc = parse_json_bytes_strict(signature_bytes).ok()?;
    stellar_v2_sep53_identity_payload_from_doc(&doc)
        .or_else(|| stellar_v2_xdr_identity_payload_from_doc(&doc))
}

/// Oracle: `computeDetachedSignatureIdentityDigestHex` (`signature-identity.js`).
/// Returns `None` when the oracle would not assign a stable proof identity (for example
/// legacy `stellar-file-signature/v1` payloads).
pub fn compute_detached_signature_identity_digest_hex(
    format: &str,
    signature_bytes: &[u8],
) -> Option<String> {
    match format {
        "qsig" => Some(hex::encode(sha3_512(signature_bytes))),
        "stellar-sig" => stellar_proof_identity_canonical_bytes(signature_bytes)
            .map(|bytes| hex::encode(sha3_512(&bytes))),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;

    #[test]
    fn qsig_identity_is_sha3_512_over_full_bytes() {
        let fixture: Value = serde_json::from_slice(include_bytes!(
            "../../tests/data/corpus/qsig/mldsa-44.valid.json"
        ))
        .unwrap();
        let bytes = B64.decode(fixture["bytes"].as_str().unwrap()).unwrap();
        let id = compute_detached_signature_identity_digest_hex("qsig", &bytes).unwrap();
        assert_eq!(
            id,
            hex::encode(sha3_512(&bytes)),
            "oracle uses raw .qsig bytes"
        );
    }

    #[test]
    fn stellar_v2_xdr_identity_is_stable() {
        let h512 = "a".repeat(128);
        let h256a = "c".repeat(64);
        let h256b = "b".repeat(64);
        let doc = serde_json::json!({
            "schema": "stellar-signature/v2",
            "proofType": "xdr-envelope-proof",
            "payloadType": "detached-digests",
            "signatureScheme": "tx-envelope-ed25519",
            "signer": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
            "network": { "passphrase": "Public Global Stellar Network ; September 2015" },
            "signedXdr": "AAAAAgAAAAB",
            "hashes": [
                { "alg": "SHA3-512", "hex": &h512 }
            ],
            "manageData": {
                "entries": [
                    { "name": "b", "alg": "SHA-256", "digestHex": &h256b },
                    { "name": "a", "alg": "SHA-256", "digestHex": &h256a }
                ]
            }
        });
        let bytes = serde_json::to_vec(&doc).unwrap();
        let a = compute_detached_signature_identity_digest_hex("stellar-sig", &bytes).unwrap();
        let doc2 = serde_json::json!({
            "schema": "stellar-signature/v2",
            "proofType": "xdr-envelope-proof",
            "payloadType": "detached-digests",
            "signatureScheme": "tx-envelope-ed25519",
            "signer": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
            "network": { "passphrase": "Public Global Stellar Network ; September 2015" },
            "signedXdr": "AAAAAgAAAAB",
            "hashes": [
                { "alg": "SHA3-512", "hex": &h512 }
            ],
            "manageData": {
                "entries": [
                    { "name": "a", "alg": "SHA-256", "digestHex": &h256a },
                    { "name": "b", "alg": "SHA-256", "digestHex": &h256b }
                ]
            }
        });
        let bytes2 = serde_json::to_vec(&doc2).unwrap();
        let b = compute_detached_signature_identity_digest_hex("stellar-sig", &bytes2).unwrap();
        assert_eq!(a, b, "manageData entry order should not change identity");
        assert_eq!(
            a.as_str(),
            "0ef1da9997356828b10b447a0b27d1d3da4b62501d39c50c2dab8cc5b2b74d9c9ba8422711e86452773cf1a877c94bd9c4a701fa30591f61921cd52e1177dea4",
            "must match quantum-vault computeDetachedSignatureIdentityDigestHex"
        );
    }
}
