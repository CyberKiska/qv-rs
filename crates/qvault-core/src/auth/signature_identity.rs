//! Detached signature proof identity (oracle: `signature-identity.js`).
//! Used for deduplicated archive-policy counting on successor restore.

use serde::Serialize;
use serde_json::Value;

use crate::hash::sha3_512;
use crate::manifest::jcs::canonicalize_json;

const STELLAR_V2_SCHEMA: &str = "stellar-signature/v2";
const SEP53_MESSAGE: &str = "sep53-message-signature";
const RAW_BYTES: &str = "raw-bytes";
const SEP53_SHA256_ED25519: &str = "sep53-sha256-ed25519";

#[derive(Debug, Clone, Serialize)]
struct StellarHashEntry {
    alg: String,
    hex: String,
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

fn stellar_v2_sep53_identity_payload(signature_bytes: &[u8]) -> Option<Vec<u8>> {
    let doc: Value = serde_json::from_slice(signature_bytes).ok()?;
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

/// Oracle: `computeDetachedSignatureIdentityDigestHex` (`signature-identity.js`).
/// Returns `None` when the oracle would not assign a stable proof identity (for example
/// legacy `stellar-file-signature/v1` payloads).
pub fn compute_detached_signature_identity_digest_hex(
    format: &str,
    signature_bytes: &[u8],
) -> Option<String> {
    match format {
        "qsig" => Some(hex::encode(sha3_512(signature_bytes))),
        "stellar-sig" => stellar_v2_sep53_identity_payload(signature_bytes)
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
}
