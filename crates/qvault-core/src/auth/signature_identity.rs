//! Detached signature proof identity (oracle: `signature-identity.js`).
//! Used for deduplicated archive-policy counting on successor restore.

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use serde::Serialize;
use serde_json::Value;

use crate::auth::qsig::{
    unpack_qsig, AUTH_DIGEST_ALG_ID_SHA3_256, SIGNATURE_PROFILE_ID_PQ_DETACHED_PURE_CONTEXT_V2,
};
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
    #[serde(rename = "signatureHex")]
    signature_hex: String,
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
    #[serde(rename = "signedXdrHex")]
    signed_xdr_hex: String,
    hashes: Vec<StellarHashEntry>,
    #[serde(rename = "manageDataEntries")]
    manage_data_entries: Vec<ManageDataEntry>,
}

#[derive(Debug, Clone, Serialize)]
struct QsigIdentity {
    format: &'static str,
    #[serde(rename = "versionMajor")]
    version_major: u8,
    #[serde(rename = "versionMinor")]
    version_minor: u8,
    #[serde(rename = "suiteId")]
    suite_id: u8,
    #[serde(rename = "signatureProfileId")]
    signature_profile_id: u8,
    #[serde(rename = "payloadDigestAlgId")]
    payload_digest_alg_id: u8,
    #[serde(rename = "authDigestAlgId")]
    auth_digest_alg_id: u8,
    #[serde(rename = "tbsHex")]
    tbs_hex: String,
    #[serde(rename = "contextHex")]
    context_hex: String,
    #[serde(rename = "signatureHex")]
    signature_hex: String,
}

fn normalize_hash_entries(value: Option<&Value>) -> Vec<StellarHashEntry> {
    let Some(arr) = value.and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(arr.len());
    for entry in arr {
        let Some(obj) = entry.as_object() else {
            continue;
        };
        let alg = obj
            .get("alg")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_ascii_uppercase();
        let hex = obj
            .get("hex")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if alg.is_empty() || hex.is_empty() {
            continue;
        }
        out.push(StellarHashEntry { alg, hex });
    }
    out.sort_by(|a, b| a.alg.cmp(&b.alg).then_with(|| a.hex.cmp(&b.hex)));
    out
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
    let signature = BASE64_STANDARD.decode(signature_b64).ok()?;
    if signature.len() != 64 {
        return None;
    }
    let hashes = normalize_hash_entries(doc.get("hashes"));
    let identity = StellarV2Sep53Identity {
        format: "stellar-sig",
        schema: schema.to_string(),
        proof_type: proof_type.to_string(),
        payload_type: payload_type.to_string(),
        signature_scheme: signature_scheme.to_string(),
        signer: signer.to_string(),
        signature_hex: hex::encode(signature),
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
    let signed_xdr_bytes = BASE64_STANDARD.decode(signed_xdr).ok()?;
    if signed_xdr_bytes.is_empty() {
        return None;
    }
    let hashes = normalize_hash_entries(doc.get("hashes"));
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
        signed_xdr_hex: hex::encode(signed_xdr_bytes),
        hashes,
        manage_data_entries,
    };
    let canonical = canonicalize_json(&identity).ok()?;
    Some(canonical.into_bytes())
}

fn qsig_proof_identity_canonical_bytes(signature_bytes: &[u8]) -> Option<Vec<u8>> {
    let parsed = unpack_qsig(signature_bytes).ok()?;
    let identity = QsigIdentity {
        format: "qsig",
        version_major: parsed.version_major,
        version_minor: parsed.version_minor,
        suite_id: parsed.suite_id,
        signature_profile_id: SIGNATURE_PROFILE_ID_PQ_DETACHED_PURE_CONTEXT_V2,
        payload_digest_alg_id: parsed.hash_alg_id,
        auth_digest_alg_id: AUTH_DIGEST_ALG_ID_SHA3_256,
        tbs_hex: hex::encode(parsed.tbs),
        context_hex: hex::encode(parsed.ctx_bytes),
        signature_hex: hex::encode(parsed.signature),
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
/// Returns `None` only when a known structured signature format cannot be parsed into its
/// stable proof identity. Unknown formats use the content digest, matching the oracle.
pub fn compute_detached_signature_identity_digest_hex(
    format: &str,
    signature_bytes: &[u8],
) -> Option<String> {
    match format {
        "qsig" => qsig_proof_identity_canonical_bytes(signature_bytes)
            .map(|bytes| hex::encode(sha3_512(&bytes))),
        "stellar-sig" => stellar_proof_identity_canonical_bytes(signature_bytes)
            .map(|bytes| hex::encode(sha3_512(&bytes))),
        _ => Some(hex::encode(sha3_512(signature_bytes))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;

    #[test]
    fn qsig_display_only_variants_share_proof_identity() {
        let fixture: Value = serde_json::from_slice(include_bytes!(
            "../../tests/data/corpus/qsig/mldsa-44.valid.json"
        ))
        .unwrap();
        let bytes = B64.decode(fixture["bytes"].as_str().unwrap()).unwrap();
        let mut display_variant = bytes.clone();
        let context_len = usize::from(display_variant[108]);
        let authenticated_metadata_len = usize::from(u16::from_le_bytes([
            display_variant[110],
            display_variant[111],
        ]));
        let display_metadata_len = usize::from(u16::from_le_bytes([
            display_variant[112],
            display_variant[113],
        ]));
        assert!(display_metadata_len >= 4);
        let display_metadata_offset = 118 + context_len + authenticated_metadata_len;
        display_variant[display_metadata_offset + 3] ^= 1;

        let id = compute_detached_signature_identity_digest_hex("qsig", &bytes).unwrap();
        let variant_id =
            compute_detached_signature_identity_digest_hex("qsig", &display_variant).unwrap();
        assert_eq!(id, variant_id, "display metadata is not part of the proof");
        assert_eq!(
            id,
            "d0842d9b87a73ac5293475419791979afcc6896a2d5e814791c4f0fda0246207c32775c9455e2025d9d91bdef803ac219b25652392ed21738f2a45ccdb86c4c3",
            "must match the current quantum-vault canonical QSIG proof identity"
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
            "signedXdr": "AAAAAgAAAAA=",
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
            "signedXdr": "AAAAAgAAAAA=",
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
            "fad7336f7bc1d6aedf54f95b86b0b09192b0c6af45c8214682770cb2fedbf7ea936468dbf791cccc762d2ace52f65f6d97a894b534fee49f02d765e1699a6a0a",
            "must match quantum-vault's decoded-XDR canonical preimage"
        );
    }

    #[test]
    fn stellar_v2_sep53_identity_uses_decoded_signature_bytes() {
        let signature = [0xabu8; 64];
        let doc = serde_json::json!({
            "schema": "stellar-signature/v2",
            "proofType": "sep53-message-signature",
            "payloadType": "raw-bytes",
            "signatureScheme": "sep53-sha256-ed25519",
            "signer": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
            "signatureB64": B64.encode(signature),
            "hashes": []
        });
        let bytes = serde_json::to_vec(&doc).unwrap();
        let id = compute_detached_signature_identity_digest_hex("stellar-sig", &bytes).unwrap();
        assert_eq!(
            id,
            "4165c91676977637d8f3da07b104f336f91077d66edcfb8a4fe0a39451e5b1a70a81a2b4b6f0d6f361178326b517f866a7a9ede4f282544a76bdb93e831f5a5d"
        );
    }
}
