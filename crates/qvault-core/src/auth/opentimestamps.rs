//! OpenTimestamps proof parsing and linkage to detached signature **bytes**.
//!
//! Policy (aligned with `quantum-vault` `src/core/crypto/auth/opentimestamps.js`):
//!
//! - OTS stamps **`SHA-256(detachedSignatureBytes)`** only. Callers must not substitute
//!   precomputed digest fields when resolving targets; always hash [`SignatureArtifact::bytes`].
//! - `appears_complete` / `complete_proof` are **non-cryptographic UX heuristics** (filename
//!   tokens and proof size). They are **not** calendar verification and must not be read as
//!   cryptographic proof that a timestamp was anchored on calendars.
//! - Linkage is **fail-closed**: zero or multiple matching detached signatures are errors.

use crate::auth::SignatureArtifact;
use crate::error::{err, Result};
use crate::hash::sha256_hex;

const OTS_PREFIX: &[u8] =
    b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94\x01";
const OTS_HASH_OP_SHA256: u8 = 0x08;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedOpenTimestampProof {
    pub stamped_digest_hex: String,
    /// Heuristic only: filename tokens and proof size; not cryptographic calendar completeness.
    pub appears_complete: bool,
    /// Same source as `appears_complete`; retained for JSON field parity with the JS oracle.
    pub complete_proof: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedOpenTimestampTarget {
    pub target_ref: String,
    pub target_name: String,
    pub target_source: String,
    pub target_verified: bool,
    pub linked: bool,
    /// Heuristic from proof parse; not a cryptographic calendar verdict.
    pub apparently_complete: bool,
    /// Same as `apparently_complete` (JS field parity).
    pub complete_proof: bool,
    pub stamped_digest_hex: String,
}

/// ASCII-lowercase token boundaries match the JS oracle `inferCompleteProof` regex:
/// `(^|[^a-z])(token)([^a-z]|$)` on the lowercased filename.
fn matches_bounded_lower_token(lower: &str, token: &str) -> bool {
    if token.is_empty() || lower.len() < token.len() {
        return false;
    }
    let hay = lower.as_bytes();
    let needle = token.as_bytes();
    for start in 0..=hay.len().saturating_sub(needle.len()) {
        if hay.get(start..start + needle.len()) != Some(needle) {
            continue;
        }
        let left_ok = start == 0 || !hay[start - 1].is_ascii_lowercase();
        let right_ok = start + needle.len() == hay.len()
            || !hay[start + needle.len()].is_ascii_lowercase();
        if left_ok && right_ok {
            return true;
        }
    }
    false
}

fn infer_complete_proof(bytes: &[u8], name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    for token in ["initial", "pending", "incomplete"] {
        if matches_bounded_lower_token(&lower, token) {
            return false;
        }
    }
    for token in ["complete", "completed", "confirmed", "upgraded"] {
        if matches_bounded_lower_token(&lower, token) {
            return true;
        }
    }
    bytes.len() >= 1024
}

pub fn parse_open_timestamp_proof(
    bytes: &[u8],
    name: Option<&str>,
) -> Result<ParsedOpenTimestampProof> {
    let name = name.unwrap_or("proof");
    if bytes.len() < OTS_PREFIX.len() + 1 + 32 {
        return Err(err(format!(
            "Invalid OpenTimestamps proof: {name} is too short"
        )));
    }
    if !bytes.starts_with(OTS_PREFIX) {
        return Err(err(format!("Invalid OpenTimestamps proof header: {name}")));
    }
    if bytes[OTS_PREFIX.len()] != OTS_HASH_OP_SHA256 {
        return Err(err(format!(
            "Unsupported OpenTimestamps digest algorithm in {name}: expected SHA-256"
        )));
    }
    let stamped_digest_hex = hex::encode(&bytes[OTS_PREFIX.len() + 1..OTS_PREFIX.len() + 33]);
    let appears_complete = infer_complete_proof(bytes, name);
    Ok(ParsedOpenTimestampProof {
        stamped_digest_hex,
        appears_complete,
        complete_proof: appears_complete,
    })
}

pub fn resolve_open_timestamp_target(
    timestamp_bytes: &[u8],
    timestamp_name: Option<&str>,
    signatures: &[SignatureArtifact],
) -> Result<ResolvedOpenTimestampTarget> {
    let parsed = parse_open_timestamp_proof(timestamp_bytes, timestamp_name)?;
    let mut unique = Vec::<&SignatureArtifact>::new();
    let mut seen = std::collections::HashSet::new();
    for signature in signatures {
        if signature.bytes.is_empty() {
            continue;
        }
        let computed_stamped_digest_hex = sha256_hex(&signature.bytes);
        let dedupe_key = signature
            .signature_content_digest_hex
            .as_deref()
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .or_else(|| Some(computed_stamped_digest_hex.clone()))
            .or_else(|| {
                let id = signature.id.as_str();
                (!id.is_empty()).then(|| signature.id.clone())
            })
            .or_else(|| {
                let name = signature.name.as_str();
                (!name.is_empty()).then(|| signature.name.clone())
            })
            .unwrap_or_default();
        if !dedupe_key.is_empty() && !seen.insert(dedupe_key) {
            continue;
        }
        unique.push(signature);
    }

    let mut matches = Vec::new();
    for signature in unique {
        let digest_hex = sha256_hex(&signature.bytes);
        if digest_hex == parsed.stamped_digest_hex {
            matches.push(signature);
        }
    }

    let name = timestamp_name.unwrap_or("proof");
    if matches.is_empty() {
        return Err(err(format!(
            "OpenTimestamps proof {name} does not match any detached signature"
        )));
    }
    if matches.len() > 1 {
        return Err(err(format!(
            "OpenTimestamps proof {name} matches multiple detached signatures"
        )));
    }

    let signature = matches[0];
    Ok(ResolvedOpenTimestampTarget {
        target_ref: signature.id.clone(),
        target_name: signature.name.clone(),
        target_source: signature.source.clone(),
        target_verified: signature.ok,
        linked: true,
        apparently_complete: parsed.appears_complete,
        complete_proof: parsed.complete_proof,
        stamped_digest_hex: parsed.stamped_digest_hex,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_proof_bytes(total_len: usize) -> Vec<u8> {
        let mut v = OTS_PREFIX.to_vec();
        v.push(OTS_HASH_OP_SHA256);
        v.resize(OTS_PREFIX.len() + 1 + 32, 0);
        if total_len > v.len() {
            v.resize(total_len, 0);
        }
        v
    }

    #[test]
    fn infer_complete_matches_js_word_boundaries() {
        let short = minimal_proof_bytes(64);
        let p = parse_open_timestamp_proof(&short, Some("myinitial.ots")).expect("parse");
        assert!(!p.appears_complete, "substring 'initial' must not imply incomplete");

        let p = parse_open_timestamp_proof(&short, Some("proof_pending_review.ots")).expect("parse");
        assert!(!p.appears_complete, "bounded 'pending' implies incomplete-looking proof");

        let p = parse_open_timestamp_proof(&short, Some("sig_complete.ots")).expect("parse");
        assert!(p.appears_complete, "bounded 'complete' implies complete-looking proof");

        let long = minimal_proof_bytes(1100);
        let p = parse_open_timestamp_proof(&long, Some("neutral-name.ots")).expect("parse");
        assert!(p.appears_complete, "long proof uses size heuristic like JS");
    }

    #[test]
    fn resolve_uses_sha256_of_signature_bytes_not_cached_digest_field() {
        let sig_bytes = vec![7u8; 200];
        let digest_hex = sha256_hex(&sig_bytes);
        let digest_bin = hex::decode(&digest_hex).expect("digest hex");
        let mut proof = OTS_PREFIX.to_vec();
        proof.push(OTS_HASH_OP_SHA256);
        proof.extend_from_slice(&digest_bin);

        let parsed = parse_open_timestamp_proof(&proof, Some("t")).expect("parse");
        let wrong_cached = "00".repeat(32);
        let sig = SignatureArtifact {
            id: "a".to_string(),
            name: "a.qsig".to_string(),
            source: "t".to_string(),
            format: "qsig".to_string(),
            signature_content_digest_hex: None,
            ots_stamped_digest_hex: Some(wrong_cached),
            bytes: sig_bytes.clone(),
            ok: true,
        };
        let resolved = resolve_open_timestamp_target(&proof, Some("t"), &[sig]).expect("resolve");
        assert_eq!(resolved.stamped_digest_hex, parsed.stamped_digest_hex);
        assert_eq!(resolved.stamped_digest_hex, digest_hex);
    }
}
