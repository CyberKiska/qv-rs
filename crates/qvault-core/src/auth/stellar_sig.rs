use std::collections::HashSet;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use serde_json::Value;

use crate::auth::detached_archive_approval_format::{
    is_stellar_file_signature_v1_document, try_validate_supported_stellar_signature_document,
    StellarV2ProofKind,
};
use crate::auth::SignatureCheckResult;
use crate::error::Result;
use crate::hash::{sha256, sha256_hex, sha3_512_hex};
use crate::manifest::strict_json::parse_json_bytes_strict;

const SIGNATURE_SCHEMA: &str = "stellar-file-signature/v1";
const MODE_SEP53: &str = "sep53";
const MAGIC: &str = "STELLAR-WSIGN/v1";
const SEP53_PREFIX: &str = "Stellar Signed Message:\n";
const HASH_ALG_SHA256: &str = "SHA-256";
const HASH_ALG_SHA3_512: &str = "SHA3-512";
const BASE32_ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const STRKEY_VERSION_ED25519_PUBLIC: u8 = 6 << 3;

#[derive(Debug, Clone, Deserialize)]
struct StellarSigDoc {
    schema: Option<String>,
    mode: Option<String>,
    input: Option<StellarSigInput>,
    signer: Option<String>,
    message: Option<String>,
    hashes: Option<Vec<StellarHashEntry>>,
    #[serde(rename = "signatureB64")]
    signature_b64: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct StellarSigInput {
    #[serde(rename = "type")]
    input_type: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct StellarHashEntry {
    alg: Option<String>,
    hex: Option<String>,
}

fn fail_result(error: impl Into<String>, warnings: Vec<String>) -> SignatureCheckResult {
    SignatureCheckResult {
        ok: false,
        family: "archive-approval".to_string(),
        self_signed: false,
        bundle_pinned: false,
        user_pinned: false,
        signer_pinned: false,
        name: String::new(),
        source: String::new(),
        format: "stellar-sig".to_string(),
        suite: None,
        suite_display: None,
        strong_pq: false,
        key_source: None,
        signer_fingerprint_hex: None,
        signer_label: None,
        signer: None,
        error: Some(error.into()),
        warnings,
        artifact_id: String::new(),
        target_type: None,
        target_ref: None,
        target_digest: None,
        transition_index: None,
        maintenance_purpose_labels: Vec::new(),
        signature_content_digest_alg: None,
        signature_content_digest_hex: None,
        ots_stamped_digest_alg: None,
        ots_stamped_digest_hex: None,
        proof_identity_digest_alg: None,
        proof_identity_digest_hex: None,
        counted_for_policy: false,
        signature_bytes: None,
    }
}

fn normalize_alg(value: &str) -> Result<&'static str> {
    match value.trim().to_ascii_uppercase().as_str() {
        HASH_ALG_SHA256 => Ok(HASH_ALG_SHA256),
        HASH_ALG_SHA3_512 => Ok(HASH_ALG_SHA3_512),
        other => Err(crate::error::err(format!(
            "Unsupported hash algorithm: {other}"
        ))),
    }
}

fn expected_hex_length(alg: &str) -> usize {
    match alg {
        HASH_ALG_SHA256 => 64,
        HASH_ALG_SHA3_512 => 128,
        _ => 0,
    }
}

fn hash_field_name(alg: &str) -> &'static str {
    match alg {
        HASH_ALG_SHA256 => "sha256",
        HASH_ALG_SHA3_512 => "sha3_512",
        _ => unreachable!(),
    }
}

fn parse_hash_entries(doc: &StellarSigDoc) -> Result<Vec<(String, String)>> {
    let hashes = doc
        .hashes
        .as_ref()
        .filter(|values| !values.is_empty())
        .ok_or_else(|| crate::error::err("Signature has no hashes[] entries"))?;
    let mut out = Vec::with_capacity(hashes.len());
    let mut seen = HashSet::new();
    for entry in hashes {
        let alg = normalize_alg(entry.alg.as_deref().unwrap_or(""))?;
        let hex = entry.hex.as_deref().unwrap_or("").to_ascii_lowercase();
        if !hex.chars().all(|ch| ch.is_ascii_hexdigit()) || hex.len() != expected_hex_length(alg) {
            return Err(crate::error::err(format!("Invalid hash hex for {alg}")));
        }
        if !seen.insert(alg.to_string()) {
            return Err(crate::error::err(format!("Duplicate hash entry: {alg}")));
        }
        out.push((alg.to_string(), hex));
    }
    Ok(out)
}

fn parse_hash_entries_from_stellar_json(doc: &Value) -> Result<Vec<(String, String)>> {
    let hashes = doc
        .as_object()
        .and_then(|o| o.get("hashes"))
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
        .ok_or_else(|| crate::error::err("Signature has no hashes[] entries"))?;
    let mut out = Vec::with_capacity(hashes.len());
    let mut seen = HashSet::new();
    for entry in hashes {
        let obj = entry
            .as_object()
            .ok_or_else(|| crate::error::err("Invalid hashes[] entry"))?;
        let alg = normalize_alg(obj.get("alg").and_then(Value::as_str).unwrap_or(""))?;
        let hex = obj
            .get("hex")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_ascii_lowercase();
        if !hex.chars().all(|ch| ch.is_ascii_hexdigit()) || hex.len() != expected_hex_length(alg) {
            return Err(crate::error::err(format!("Invalid hash hex for {alg}")));
        }
        if !seen.insert(alg.to_string()) {
            return Err(crate::error::err(format!("Duplicate hash entry: {alg}")));
        }
        out.push((alg.to_string(), hex));
    }
    Ok(out)
}

fn validate_stellar_v2_input_descriptor(
    input: Option<&serde_json::Map<String, Value>>,
    message_bytes: &[u8],
) -> Result<()> {
    let Some(input) = input else {
        return Ok(());
    };
    let input_type = input
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if !input_type.is_empty() && input_type != "file" && input_type != "text" {
        return Err(crate::error::err(format!(
            "Unsupported input.type: {input_type}"
        )));
    }
    if let Some(size_val) = input.get("size") {
        if let Some(n) = size_val.as_u64() {
            // Compare in u64 so a declared size above usize::MAX (32-bit targets)
            // cannot truncate into a spurious match.
            if n != message_bytes.len() as u64 {
                return Err(crate::error::err(format!(
                    "Input size mismatch: signature expects {n}, got {}",
                    message_bytes.len()
                )));
            }
        } else if let Some(n) = size_val.as_i64() {
            if n >= 0 && (n as usize) != message_bytes.len() {
                return Err(crate::error::err(format!(
                    "Input size mismatch: signature expects {n}, got {}",
                    message_bytes.len()
                )));
            }
        }
    }
    Ok(())
}

fn build_expected_message(input_type: &str, size: usize, entries: &[(String, String)]) -> String {
    let mut lines = vec![
        MAGIC.to_string(),
        format!("type={input_type}"),
        format!("size={size}"),
        format!(
            "hashes={}",
            entries
                .iter()
                .map(|(alg, _)| alg.as_str())
                .collect::<Vec<_>>()
                .join(",")
        ),
    ];
    for (alg, hex) in entries {
        lines.push(format!("{}={hex}", hash_field_name(alg)));
    }
    lines.join("\n")
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
        return Err(crate::error::err("Empty base32 string"));
    }
    let mut bits = 0u32;
    let mut value = 0u32;
    let mut out = Vec::new();
    for ch in clean.chars() {
        let Some(index) = BASE32_ALPHABET.find(ch) else {
            return Err(crate::error::err(format!("Invalid base32 symbol: {ch}")));
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

fn decode_ed25519_public_key(address: &str) -> Result<[u8; 32]> {
    let address = address.trim();
    if address.len() != 56
        || !address.starts_with('G')
        || !address
            .chars()
            .all(|ch| matches!(ch, 'A'..='Z' | '2'..='7'))
    {
        return Err(crate::error::err("Invalid Stellar public address format"));
    }
    let decoded = base32_decode(address)?;
    if decoded.len() < 3 {
        return Err(crate::error::err("Invalid Stellar public address"));
    }
    let payload = &decoded[..decoded.len() - 2];
    let checksum_bytes = &decoded[decoded.len() - 2..];
    let expected_crc = crc16_xmodem(payload);
    let actual_crc = u16::from(checksum_bytes[0]) | (u16::from(checksum_bytes[1]) << 8);
    if expected_crc != actual_crc {
        return Err(crate::error::err("Invalid Stellar public address checksum"));
    }
    if payload[0] != STRKEY_VERSION_ED25519_PUBLIC {
        return Err(crate::error::err("Unexpected Stellar key version byte"));
    }
    let raw = &payload[1..];
    if raw.len() != 32 {
        return Err(crate::error::err("Unexpected Stellar public key length"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(raw);
    Ok(out)
}

fn stellar_success(
    sig_json_bytes: &[u8],
    signer: String,
    bundle_signer_empty: bool,
    user_pinned: bool,
    warnings: Vec<String>,
) -> SignatureCheckResult {
    SignatureCheckResult {
        ok: true,
        family: "archive-approval".to_string(),
        self_signed: false,
        bundle_pinned: !bundle_signer_empty,
        user_pinned,
        signer_pinned: !bundle_signer_empty || user_pinned,
        name: String::new(),
        source: String::new(),
        format: "stellar-sig".to_string(),
        suite: Some("ed25519".to_string()),
        suite_display: Some("Ed25519".to_string()),
        strong_pq: false,
        key_source: Some("signature-document".to_string()),
        signer_fingerprint_hex: None,
        signer_label: Some(signer.clone()),
        signer: Some(signer),
        error: None,
        warnings,
        artifact_id: String::new(),
        target_type: None,
        target_ref: None,
        target_digest: None,
        transition_index: None,
        maintenance_purpose_labels: Vec::new(),
        signature_content_digest_alg: None,
        signature_content_digest_hex: None,
        ots_stamped_digest_alg: None,
        ots_stamped_digest_hex: None,
        proof_identity_digest_alg: None,
        proof_identity_digest_hex: None,
        counted_for_policy: false,
        signature_bytes: Some(sig_json_bytes.to_vec()),
    }
}

fn verify_stellar_file_signature_v1_sep53(
    message_bytes: &[u8],
    sig_json_bytes: &[u8],
    doc: StellarSigDoc,
    bundle_signer: Option<&str>,
    expected_signer: Option<&str>,
    mut warnings: Vec<String>,
) -> Result<SignatureCheckResult> {
    if doc.schema.as_deref() != Some(SIGNATURE_SCHEMA) {
        return Ok(fail_result(
            format!(
                "Unsupported signature schema: {}",
                doc.schema.as_deref().unwrap_or("(missing)")
            ),
            warnings,
        ));
    }
    if doc.mode.as_deref() != Some(MODE_SEP53) {
        return Ok(fail_result(
            format!(
                "Unsupported .sig mode for Quantum Vault: {}",
                doc.mode.as_deref().unwrap_or("(missing)")
            ),
            warnings,
        ));
    }

    warnings.push(
        "Legacy Ed25519 signature is not post-quantum secure. Prefer .qsig for PQ authenticity."
            .to_string(),
    );

    let hash_entries = match parse_hash_entries(&doc) {
        Ok(entries) => entries,
        Err(error) => return Ok(fail_result(error.to_string(), warnings)),
    };

    let digest_sha256 = sha256_hex(message_bytes);
    let digest_sha3_512 = sha3_512_hex(message_bytes);
    for (alg, hex) in &hash_entries {
        let actual = match alg.as_str() {
            HASH_ALG_SHA256 => digest_sha256.as_str(),
            HASH_ALG_SHA3_512 => digest_sha3_512.as_str(),
            _ => unreachable!(),
        };
        if actual != hex {
            return Ok(fail_result(format!("Digest mismatch for {alg}"), warnings));
        }
    }

    let input_type = doc
        .input
        .as_ref()
        .and_then(|input| input.input_type.as_deref())
        .unwrap_or("file");
    let expected_message = build_expected_message(input_type, message_bytes.len(), &hash_entries);
    if doc.message.as_deref() != Some(expected_message.as_str()) {
        return Ok(fail_result("Deterministic message mismatch", warnings));
    }

    let signer = doc.signer.as_deref().unwrap_or("").trim().to_string();
    let signer_public = match decode_ed25519_public_key(&signer) {
        Ok(value) => value,
        Err(error) => {
            return Ok(fail_result(
                format!("Invalid signer address: {error}"),
                warnings,
            ))
        }
    };

    let declared_signer = bundle_signer.unwrap_or("").trim();
    if !declared_signer.is_empty() && declared_signer != signer {
        return Ok(fail_result(
            format!(
                "Bundled signer identifier does not match signature document signer (expected {declared_signer}, got {signer})"
            ),
            warnings,
        ));
    }

    let mut user_pinned = false;
    let expected = expected_signer.unwrap_or("").trim();
    if !expected.is_empty() {
        if expected != signer {
            warnings.push(format!(
                "Pinned Ed25519 signer did not match this verified signature (expected {expected}, got {signer})."
            ));
        } else {
            user_pinned = true;
        }
    }

    let signature_bytes = match BASE64_STANDARD.decode(doc.signature_b64.as_deref().unwrap_or("")) {
        Ok(bytes) => bytes,
        Err(error) => {
            return Ok(fail_result(
                format!("Malformed signatureB64: {error}"),
                warnings,
            ))
        }
    };
    if signature_bytes.len() != 64 {
        return Ok(fail_result(
            format!(
                "Expected 64-byte Ed25519 signature, got {}",
                signature_bytes.len()
            ),
            warnings,
        ));
    }

    let mut prefixed = String::with_capacity(SEP53_PREFIX.len() + expected_message.len());
    prefixed.push_str(SEP53_PREFIX);
    prefixed.push_str(&expected_message);
    let payload = sha256(prefixed.as_bytes());
    let verifying_key = VerifyingKey::from_bytes(&signer_public)
        .map_err(|error| crate::error::err(format!("Invalid signer key bytes: {error}")))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|error| crate::error::err(format!("Invalid signature bytes: {error}")))?;
    if verifying_key.verify(&payload, &signature).is_err() {
        return Ok(fail_result(
            "Ed25519 signature verification failed",
            warnings,
        ));
    }

    Ok(stellar_success(
        sig_json_bytes,
        signer,
        declared_signer.is_empty(),
        user_pinned,
        warnings,
    ))
}

fn verify_stellar_signature_v2_sep53_message(
    message_bytes: &[u8],
    sig_json_bytes: &[u8],
    value: &Value,
    bundle_signer: Option<&str>,
    expected_signer: Option<&str>,
    mut warnings: Vec<String>,
) -> Result<SignatureCheckResult> {
    warnings.push(
        "Legacy Ed25519 signature is not post-quantum secure. Prefer .qsig for PQ authenticity."
            .to_string(),
    );

    let hash_entries = match parse_hash_entries_from_stellar_json(value) {
        Ok(entries) => entries,
        Err(error) => return Ok(fail_result(error.to_string(), warnings)),
    };

    let digest_sha256 = sha256_hex(message_bytes);
    let digest_sha3_512 = sha3_512_hex(message_bytes);
    for (alg, hex) in &hash_entries {
        let actual = match alg.as_str() {
            HASH_ALG_SHA256 => digest_sha256.as_str(),
            HASH_ALG_SHA3_512 => digest_sha3_512.as_str(),
            _ => unreachable!(),
        };
        if actual != hex {
            return Ok(fail_result(format!("Digest mismatch for {alg}"), warnings));
        }
    }

    let input_map = value
        .as_object()
        .and_then(|o| o.get("input"))
        .and_then(Value::as_object);
    if let Err(error) = validate_stellar_v2_input_descriptor(input_map, message_bytes) {
        return Ok(fail_result(error.to_string(), warnings));
    }

    let signer = value
        .as_object()
        .and_then(|o| o.get("signer"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let signer_public = match decode_ed25519_public_key(&signer) {
        Ok(value) => value,
        Err(error) => {
            return Ok(fail_result(
                format!("Invalid signer address: {error}"),
                warnings,
            ))
        }
    };

    let declared_signer = bundle_signer.unwrap_or("").trim();
    if !declared_signer.is_empty() && declared_signer != signer {
        return Ok(fail_result(
            format!(
                "Bundled signer identifier does not match signature document signer (expected {declared_signer}, got {signer})"
            ),
            warnings,
        ));
    }

    let mut user_pinned = false;
    let expected = expected_signer.unwrap_or("").trim();
    if !expected.is_empty() {
        if expected != signer {
            warnings.push(format!(
                "Pinned Ed25519 signer did not match this verified signature (expected {expected}, got {signer})."
            ));
        } else {
            user_pinned = true;
        }
    }

    let signature_b64 = value
        .as_object()
        .and_then(|o| o.get("signatureB64"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let signature_bytes = match BASE64_STANDARD.decode(signature_b64.trim()) {
        Ok(bytes) => bytes,
        Err(error) => {
            return Ok(fail_result(
                format!("Malformed signatureB64: {error}"),
                warnings,
            ))
        }
    };
    if signature_bytes.len() != 64 {
        return Ok(fail_result(
            format!(
                "Expected 64-byte Ed25519 signature, got {}",
                signature_bytes.len()
            ),
            warnings,
        ));
    }

    let mut payload_input = Vec::with_capacity(SEP53_PREFIX.len() + message_bytes.len());
    payload_input.extend_from_slice(SEP53_PREFIX.as_bytes());
    payload_input.extend_from_slice(message_bytes);
    let payload_hash = sha256(&payload_input);

    let verifying_key = VerifyingKey::from_bytes(&signer_public)
        .map_err(|error| crate::error::err(format!("Invalid signer key bytes: {error}")))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|error| crate::error::err(format!("Invalid signature bytes: {error}")))?;
    if verifying_key
        .verify(payload_hash.as_slice(), &signature)
        .is_err()
    {
        return Ok(fail_result(
            "SEP-53 content signature verification failed",
            warnings,
        ));
    }

    if !expected.is_empty() && expected != signer {
        return Ok(fail_result(
            format!(
                "Provided expected signer did not match the verified signer (expected {expected}, got {signer})"
            ),
            warnings,
        ));
    }

    Ok(stellar_success(
        sig_json_bytes,
        signer,
        declared_signer.is_empty(),
        user_pinned,
        warnings,
    ))
}

pub fn verify_stellar_sig_against_bytes(
    message_bytes: &[u8],
    sig_json_bytes: &[u8],
    bundle_signer: Option<&str>,
    expected_signer: Option<&str>,
) -> Result<SignatureCheckResult> {
    let warnings = Vec::new();
    let value = match parse_json_bytes_strict(sig_json_bytes) {
        Ok(v) => v,
        Err(error) => {
            return Ok(fail_result(
                format!("Invalid JSON signature document: {error}"),
                warnings,
            ))
        }
    };

    if is_stellar_file_signature_v1_document(&value) {
        let doc: StellarSigDoc = match serde_json::from_value(value.clone()) {
            Ok(d) => d,
            Err(error) => {
                return Ok(fail_result(
                    format!("Malformed stellar-file-signature/v1 document: {error}"),
                    warnings,
                ))
            }
        };
        return verify_stellar_file_signature_v1_sep53(
            message_bytes,
            sig_json_bytes,
            doc,
            bundle_signer,
            expected_signer,
            warnings,
        );
    }

    if try_validate_supported_stellar_signature_document(&value).is_ok() {
        let proof_kind =
            match crate::auth::detached_archive_approval_format::stellar_v2_proof_kind(&value) {
                Ok(k) => k,
                Err(error) => return Ok(fail_result(error.to_string(), warnings)),
            };
        return match proof_kind {
            StellarV2ProofKind::Sep53Message => verify_stellar_signature_v2_sep53_message(
                message_bytes,
                sig_json_bytes,
                &value,
                bundle_signer,
                expected_signer,
                warnings,
            ),
            StellarV2ProofKind::XdrEnvelope => Ok(fail_result(
                "stellar-signature/v2 xdr-envelope-proof is not supported in this Rust build",
                warnings,
            )),
        };
    }

    let schema_hint = value
        .get("schema")
        .and_then(Value::as_str)
        .unwrap_or("(missing)");
    Ok(fail_result(
        format!("Unsupported signature schema: {schema_hint}"),
        warnings,
    ))
}
