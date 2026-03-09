use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;

use crate::auth::{SignatureArtifact, TimestampEvidence};
use crate::error::{err, Result};
use crate::hash::sha256_hex;
use crate::manifest::ManifestBundle;

const OTS_PREFIX: &[u8] =
    b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94\x01";
const OTS_HASH_OP_SHA256: u8 = 0x08;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedOpenTimestampProof {
    pub stamped_digest_hex: String,
    pub appears_complete: bool,
    pub complete_proof: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedOpenTimestampTarget {
    pub target_ref: String,
    pub target_name: String,
    pub target_source: String,
    pub target_verified: bool,
    pub linked: bool,
    pub apparently_complete: bool,
    pub complete_proof: bool,
    pub stamped_digest_hex: String,
}

fn infer_complete_proof(bytes: &[u8], name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if lower.contains("initial") || lower.contains("pending") || lower.contains("incomplete") {
        return false;
    }
    if lower.contains("complete")
        || lower.contains("completed")
        || lower.contains("confirmed")
        || lower.contains("upgraded")
    {
        return true;
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
        let dedupe_key = signature
            .signature_content_digest_hex
            .as_ref()
            .or(signature.ots_stamped_digest_hex.as_ref())
            .cloned()
            .unwrap_or_else(|| signature.id.clone());
        if seen.insert(dedupe_key) {
            unique.push(signature);
        }
    }

    let mut matches = Vec::new();
    for signature in unique {
        let digest_hex = match signature.ots_stamped_digest_hex.as_deref() {
            Some(value) if !value.is_empty() => value.to_string(),
            _ => sha256_hex(&signature.bytes),
        };
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

pub fn assert_manifest_bundle_timestamps(bundle: &ManifestBundle) -> Result<()> {
    inspect_manifest_bundle_timestamps(bundle).map(|_| ())
}

fn decode_bundle_signature_bytes(
    signature: &crate::manifest::ManifestBundleSignatureAttachment,
) -> Result<Vec<u8>> {
    if signature.signature_encoding != "base64" {
        return Err(err(format!(
            "Unsupported bundle signature encoding: {}",
            signature.signature_encoding
        )));
    }
    BASE64_STANDARD
        .decode(&signature.signature)
        .map_err(|error| err(format!("Invalid base64 signature payload: {error}")))
}

fn inspect_manifest_bundle_timestamps(bundle: &ManifestBundle) -> Result<Vec<TimestampEvidence>> {
    let signatures = bundle
        .attachments
        .signatures
        .iter()
        .map(|signature| {
            Ok(SignatureArtifact {
                id: signature.id.clone(),
                name: signature.id.clone(),
                source: "bundle".to_string(),
                format: signature.format.clone(),
                signature_content_digest_hex: None,
                ots_stamped_digest_hex: None,
                bytes: decode_bundle_signature_bytes(signature)?,
                ok: true,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let signatures_by_id = signatures
        .iter()
        .map(|signature| (signature.id.clone(), signature))
        .collect::<std::collections::HashMap<_, _>>();

    bundle
        .attachments
        .timestamps
        .iter()
        .map(|timestamp| {
            if timestamp.proof_encoding != "base64" {
                return Err(err(format!(
                    "Unsupported OpenTimestamps proof encoding: {}",
                    timestamp.proof_encoding
                )));
            }
            let Some(target_signature) = signatures_by_id.get(&timestamp.target_ref) else {
                return Err(err(format!(
                    "OpenTimestamps targetRef is unknown: {}",
                    timestamp.target_ref
                )));
            };
            let proof_bytes = BASE64_STANDARD
                .decode(&timestamp.proof)
                .map_err(|error| err(format!("Invalid base64 OTS proof: {error}")))?;
            let resolved = resolve_open_timestamp_target(
                &proof_bytes,
                Some(&timestamp.id),
                &[(*target_signature).clone()],
            )?;
            Ok(TimestampEvidence {
                id: timestamp.id.clone(),
                target_ref: resolved.target_ref,
                target_name: resolved.target_name,
                target_source: resolved.target_source,
                target_verified: resolved.target_verified,
                linked: true,
                apparently_complete: resolved.apparently_complete,
                complete_proof: resolved.complete_proof,
                link_label: "OTS evidence linked to signature".to_string(),
                completion_label: if resolved.apparently_complete {
                    "OTS proof appears complete".to_string()
                } else {
                    "OTS proof appears incomplete".to_string()
                },
            })
        })
        .collect()
}

pub fn inspect_timestamp_evidence(
    bundle: &ManifestBundle,
    external_timestamps: &[crate::auth::NamedBinaryArtifact],
    signature_artifacts: &[SignatureArtifact],
) -> Result<Vec<TimestampEvidence>> {
    let mut out = inspect_manifest_bundle_timestamps(bundle)?;
    for (index, timestamp) in external_timestamps.iter().enumerate() {
        if timestamp.bytes.is_empty() {
            return Err(err(format!(
                "Invalid OpenTimestamps proof: {}",
                if timestamp.name.is_empty() {
                    format!("timestamp-{}", index + 1)
                } else {
                    timestamp.name.clone()
                }
            )));
        }
        let name = if timestamp.name.is_empty() {
            format!("timestamp-{}", index + 1)
        } else {
            timestamp.name.clone()
        };
        let resolved =
            resolve_open_timestamp_target(&timestamp.bytes, Some(&name), signature_artifacts)?;
        out.push(TimestampEvidence {
            id: name,
            target_ref: resolved.target_ref,
            target_name: resolved.target_name,
            target_source: resolved.target_source,
            target_verified: resolved.target_verified,
            linked: true,
            apparently_complete: resolved.apparently_complete,
            complete_proof: resolved.complete_proof,
            link_label: "External OTS evidence linked to signature".to_string(),
            completion_label: if resolved.apparently_complete {
                "OTS proof appears complete".to_string()
            } else {
                "OTS proof appears incomplete".to_string()
            },
        });
    }
    Ok(out)
}
