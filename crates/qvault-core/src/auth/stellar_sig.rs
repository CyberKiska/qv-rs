use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;

use crate::auth::SignatureCheckResult;
use crate::error::Result;
use crate::hash::{sha256, sha256_hex, sha3_512_hex};

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
        signature_content_digest_alg: None,
        signature_content_digest_hex: None,
        ots_stamped_digest_alg: None,
        ots_stamped_digest_hex: None,
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
    let mut seen = std::collections::HashSet::new();
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

pub fn verify_stellar_sig_against_bytes(
    message_bytes: &[u8],
    sig_json_bytes: &[u8],
    bundle_signer: Option<&str>,
    expected_signer: Option<&str>,
) -> Result<SignatureCheckResult> {
    let mut warnings = Vec::new();
    let doc: StellarSigDoc = match serde_json::from_slice(sig_json_bytes) {
        Ok(doc) => doc,
        Err(error) => {
            return Ok(fail_result(
                format!("Invalid JSON signature document: {error}"),
                warnings,
            ))
        }
    };

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

    Ok(SignatureCheckResult {
        ok: true,
        bundle_pinned: !declared_signer.is_empty(),
        user_pinned,
        signer_pinned: !declared_signer.is_empty() || user_pinned,
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
        signature_content_digest_alg: None,
        signature_content_digest_hex: None,
        ots_stamped_digest_alg: None,
        ots_stamped_digest_hex: None,
        counted_for_policy: false,
        signature_bytes: Some(sig_json_bytes.to_vec()),
    })
}
