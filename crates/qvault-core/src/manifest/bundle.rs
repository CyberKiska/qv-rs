use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::auth::{normalize_signature_suite, AuthPolicy, AuthPolicyLevel};
use crate::error::{err, Result};
use crate::hash::sha3_512_hex;
use crate::manifest::archive::{
    canonicalize_archive_manifest, ArchiveManifest, AuthPolicyCommitment, QV_CANONICALIZATION_LABEL,
};
use crate::manifest::jcs::{canonicalize_json, canonicalize_json_to_bytes};

pub const MANIFEST_BUNDLE_TYPE: &str = "QV-Manifest-Bundle";
pub const MANIFEST_BUNDLE_VERSION: u64 = 1;
pub const MANIFEST_DIGEST_ALG: &str = "SHA3-512";
pub const AUTH_POLICY_COMMITMENT_ALG: &str = "SHA3-512";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestDigestObject {
    pub alg: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestBundlePublicKeyAttachment {
    pub id: String,
    pub kty: String,
    pub suite: String,
    pub encoding: String,
    pub value: String,
    pub legacy: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestBundleSignatureTarget {
    #[serde(rename = "type")]
    pub target_type: String,
    #[serde(rename = "digestAlg")]
    pub digest_alg: String,
    #[serde(rename = "digestValue")]
    pub digest_value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestBundleSignatureAttachment {
    pub id: String,
    pub format: String,
    pub suite: String,
    pub target: ManifestBundleSignatureTarget,
    #[serde(rename = "signatureEncoding")]
    pub signature_encoding: String,
    pub signature: String,
    #[serde(rename = "publicKeyRef")]
    pub public_key_ref: Option<String>,
    pub legacy: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestBundleTimestampAttachment {
    pub id: String,
    #[serde(rename = "type")]
    pub timestamp_type: String,
    #[serde(rename = "targetRef")]
    pub target_ref: String,
    #[serde(rename = "proofEncoding")]
    pub proof_encoding: String,
    pub proof: String,
    #[serde(rename = "apparentlyComplete")]
    pub apparently_complete: bool,
    #[serde(rename = "completeProof")]
    pub complete_proof: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestBundleAttachments {
    #[serde(rename = "publicKeys")]
    pub public_keys: Vec<ManifestBundlePublicKeyAttachment>,
    pub signatures: Vec<ManifestBundleSignatureAttachment>,
    pub timestamps: Vec<ManifestBundleTimestampAttachment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestBundle {
    #[serde(rename = "type")]
    pub bundle_type: String,
    pub version: u64,
    #[serde(rename = "bundleCanonicalization")]
    pub bundle_canonicalization: String,
    #[serde(rename = "manifestCanonicalization")]
    pub manifest_canonicalization: String,
    pub manifest: ArchiveManifest,
    #[serde(rename = "manifestDigest")]
    pub manifest_digest: ManifestDigestObject,
    #[serde(rename = "authPolicy")]
    pub auth_policy: AuthPolicy,
    pub attachments: ManifestBundleAttachments,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestBundleCanonicalized {
    pub bundle: ManifestBundle,
    pub canonical: String,
    pub bytes: Vec<u8>,
    pub digest_hex: String,
    pub manifest_bytes: Vec<u8>,
    pub manifest_digest_hex: String,
}

pub type ParsedManifestBundle = ManifestBundleCanonicalized;

pub fn normalize_auth_policy(auth_policy: &AuthPolicy) -> Result<AuthPolicy> {
    let min_valid_signatures = auth_policy.min_valid_signatures.max(1);
    let level = match auth_policy.level {
        AuthPolicyLevel::IntegrityOnly => AuthPolicyLevel::IntegrityOnly,
        AuthPolicyLevel::AnySignature => AuthPolicyLevel::AnySignature,
        AuthPolicyLevel::StrongPqSignature => AuthPolicyLevel::StrongPqSignature,
    };
    Ok(AuthPolicy {
        level,
        min_valid_signatures,
    })
}

pub fn compute_auth_policy_commitment(auth_policy: &AuthPolicy) -> Result<AuthPolicyCommitment> {
    let normalized = normalize_auth_policy(auth_policy)?;
    Ok(AuthPolicyCommitment {
        alg: AUTH_POLICY_COMMITMENT_ALG.to_string(),
        canonicalization: QV_CANONICALIZATION_LABEL.to_string(),
        value: sha3_512_hex(&canonicalize_json_to_bytes(&normalized)?),
    })
}

pub fn validate_auth_policy_commitment_shape(
    commitment: &AuthPolicyCommitment,
) -> Result<AuthPolicyCommitment> {
    if commitment.alg != AUTH_POLICY_COMMITMENT_ALG {
        return Err(err("Unsupported authPolicyCommitment.alg"));
    }
    if commitment.canonicalization != QV_CANONICALIZATION_LABEL {
        return Err(err("Unsupported authPolicyCommitment.canonicalization"));
    }
    if commitment.value.len() != 128 || !commitment.value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(err("Invalid authPolicyCommitment.value"));
    }
    Ok(AuthPolicyCommitment {
        alg: commitment.alg.clone(),
        canonicalization: commitment.canonicalization.clone(),
        value: commitment.value.to_ascii_lowercase(),
    })
}

pub fn assert_auth_policy_commitment(
    commitment: &AuthPolicyCommitment,
    auth_policy: &AuthPolicy,
) -> Result<AuthPolicyCommitment> {
    let actual = validate_auth_policy_commitment_shape(commitment)?;
    let expected = compute_auth_policy_commitment(auth_policy)?;
    if actual.value != expected.value {
        return Err(err("authPolicyCommitment mismatch"));
    }
    Ok(actual)
}

pub fn recover_committed_auth_policy(
    commitment: &AuthPolicyCommitment,
    max_min_valid_signatures: Option<u64>,
) -> Result<AuthPolicy> {
    let actual = validate_auth_policy_commitment_shape(commitment)?;
    let max_min_valid_signatures = max_min_valid_signatures.unwrap_or(64);
    let mut matches = Vec::new();
    for level in [
        AuthPolicyLevel::IntegrityOnly,
        AuthPolicyLevel::AnySignature,
        AuthPolicyLevel::StrongPqSignature,
    ] {
        for min_valid_signatures in 1..=max_min_valid_signatures {
            let candidate = AuthPolicy {
                level,
                min_valid_signatures,
            };
            if compute_auth_policy_commitment(&candidate)?.value == actual.value {
                matches.push(candidate);
            }
        }
    }
    match matches.len() {
        1 => Ok(matches.remove(0)),
        0 => Err(err(
            "Unable to recover authPolicy from authPolicyCommitment",
        )),
        _ => Err(err("authPolicyCommitment is ambiguous")),
    }
}

pub fn compute_manifest_digest(manifest: &ArchiveManifest) -> Result<(String, Vec<u8>, String)> {
    let canonicalized = canonicalize_archive_manifest(manifest)?;
    Ok((
        canonicalized.canonical,
        canonicalized.bytes,
        canonicalized.digest_hex,
    ))
}

fn assert_unique_ids<T>(values: &[T], field: &str, id_of: impl Fn(&T) -> &str) -> Result<()> {
    let mut seen = std::collections::HashSet::new();
    for value in values {
        let id = id_of(value);
        if !seen.insert(id.to_string()) {
            return Err(err(format!("Duplicate {field} id: {id}")));
        }
    }
    Ok(())
}

fn assert_unique_signature_payloads(
    signatures: &[ManifestBundleSignatureAttachment],
) -> Result<()> {
    let mut seen = std::collections::BTreeMap::<String, String>::new();
    for signature in signatures {
        if signature.signature_encoding != "base64" {
            return Err(err(format!(
                "Unsupported signatureEncoding for {}: {}",
                signature.id, signature.signature_encoding
            )));
        }
        let signature_bytes = BASE64_STANDARD
            .decode(&signature.signature)
            .map_err(|error| err(format!("Invalid base64 signature payload: {error}")))?;
        let digest_hex = sha3_512_hex(&signature_bytes);
        if let Some(existing_id) = seen.get(&digest_hex) {
            return Err(err(format!(
                "Duplicate signature payload bytes detected across bundle signatures: {existing_id}, {}",
                signature.id
            )));
        }
        seen.insert(digest_hex, signature.id.clone());
    }
    Ok(())
}

fn normalize_public_key(
    entry: &ManifestBundlePublicKeyAttachment,
) -> Result<ManifestBundlePublicKeyAttachment> {
    if entry.id.is_empty()
        || entry.kty.is_empty()
        || entry.encoding.is_empty()
        || entry.value.is_empty()
    {
        return Err(err("Invalid attachments.publicKeys entry"));
    }
    Ok(ManifestBundlePublicKeyAttachment {
        id: entry.id.clone(),
        kty: entry.kty.clone(),
        suite: normalize_signature_suite(&entry.suite)?.to_string(),
        encoding: entry.encoding.clone(),
        value: entry.value.clone(),
        legacy: entry.legacy,
    })
}

fn normalize_signature(
    entry: &ManifestBundleSignatureAttachment,
    manifest_digest_hex: &str,
) -> Result<ManifestBundleSignatureAttachment> {
    if entry.format != "qsig" && entry.format != "stellar-sig" {
        return Err(err("Unsupported attachments.signatures[i].format"));
    }
    if entry.target.target_type != "canonical-manifest" {
        return Err(err("Unsupported signature target.type"));
    }
    if entry.target.digest_alg != MANIFEST_DIGEST_ALG {
        return Err(err("Unsupported signature target.digestAlg"));
    }
    let digest_value = entry.target.digest_value.to_ascii_lowercase();
    if digest_value != manifest_digest_hex {
        return Err(err("Signature target digest mismatch"));
    }
    Ok(ManifestBundleSignatureAttachment {
        id: entry.id.clone(),
        format: entry.format.clone(),
        suite: normalize_signature_suite(&entry.suite)?.to_string(),
        target: ManifestBundleSignatureTarget {
            target_type: "canonical-manifest".to_string(),
            digest_alg: MANIFEST_DIGEST_ALG.to_string(),
            digest_value,
        },
        signature_encoding: entry.signature_encoding.clone(),
        signature: entry.signature.clone(),
        public_key_ref: entry
            .public_key_ref
            .as_deref()
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned),
        legacy: entry.legacy,
    })
}

fn normalize_timestamp(
    entry: &ManifestBundleTimestampAttachment,
    signature_ids: &std::collections::HashSet<String>,
) -> Result<ManifestBundleTimestampAttachment> {
    if entry.timestamp_type != "opentimestamps" {
        return Err(err("Unsupported attachments.timestamps[i].type"));
    }
    if !signature_ids.contains(&entry.target_ref) {
        return Err(err(format!(
            "attachments.timestamps[i].targetRef does not reference a known signature"
        )));
    }
    Ok(ManifestBundleTimestampAttachment {
        id: entry.id.clone(),
        timestamp_type: "opentimestamps".to_string(),
        target_ref: entry.target_ref.clone(),
        proof_encoding: entry.proof_encoding.clone(),
        proof: entry.proof.clone(),
        apparently_complete: entry.apparently_complete || entry.complete_proof,
        complete_proof: entry.apparently_complete || entry.complete_proof,
    })
}

pub fn normalize_manifest_bundle(bundle: &ManifestBundle) -> Result<ManifestBundle> {
    if bundle.bundle_type != MANIFEST_BUNDLE_TYPE {
        return Err(err("Unsupported manifest bundle type"));
    }
    if bundle.version != MANIFEST_BUNDLE_VERSION {
        return Err(err("Unsupported manifest bundle version"));
    }
    if bundle.bundle_canonicalization != QV_CANONICALIZATION_LABEL {
        return Err(err("Unsupported bundleCanonicalization"));
    }
    if bundle.manifest_canonicalization != QV_CANONICALIZATION_LABEL {
        return Err(err("Unsupported manifestCanonicalization"));
    }

    let manifest_parsed = canonicalize_archive_manifest(&bundle.manifest)?;
    if bundle.manifest_digest.alg != MANIFEST_DIGEST_ALG {
        return Err(err("Unsupported bundle.manifestDigest.alg"));
    }
    if bundle.manifest_digest.value.to_ascii_lowercase() != manifest_parsed.digest_hex {
        return Err(err("bundle.manifestDigest mismatch"));
    }

    let auth_policy = normalize_auth_policy(&bundle.auth_policy)?;
    let public_keys = bundle
        .attachments
        .public_keys
        .iter()
        .map(normalize_public_key)
        .collect::<Result<Vec<_>>>()?;
    let signatures = bundle
        .attachments
        .signatures
        .iter()
        .map(|entry| normalize_signature(entry, &manifest_parsed.digest_hex))
        .collect::<Result<Vec<_>>>()?;
    assert_unique_ids(&public_keys, "publicKeys", |value| &value.id)?;
    assert_unique_ids(&signatures, "signatures", |value| &value.id)?;
    assert_unique_signature_payloads(&signatures)?;

    let public_key_ids = public_keys
        .iter()
        .map(|item| item.id.clone())
        .collect::<std::collections::HashSet<_>>();
    for signature in &signatures {
        if let Some(public_key_ref) = signature.public_key_ref.as_deref() {
            if !public_key_ids.contains(public_key_ref) {
                return Err(err(format!(
                    "attachments.signatures publicKeyRef is unknown: {public_key_ref}"
                )));
            }
        }
    }
    let signature_ids = signatures
        .iter()
        .map(|item| item.id.clone())
        .collect::<std::collections::HashSet<_>>();
    let timestamps = bundle
        .attachments
        .timestamps
        .iter()
        .map(|entry| normalize_timestamp(entry, &signature_ids))
        .collect::<Result<Vec<_>>>()?;
    assert_unique_ids(&timestamps, "timestamps", |value| &value.id)?;

    Ok(ManifestBundle {
        bundle_type: MANIFEST_BUNDLE_TYPE.to_string(),
        version: MANIFEST_BUNDLE_VERSION,
        bundle_canonicalization: QV_CANONICALIZATION_LABEL.to_string(),
        manifest_canonicalization: QV_CANONICALIZATION_LABEL.to_string(),
        manifest: bundle.manifest.clone(),
        manifest_digest: ManifestDigestObject {
            alg: MANIFEST_DIGEST_ALG.to_string(),
            value: manifest_parsed.digest_hex.clone(),
        },
        auth_policy,
        attachments: ManifestBundleAttachments {
            public_keys,
            signatures,
            timestamps,
        },
    })
}

pub fn canonicalize_manifest_bundle(
    bundle: &ManifestBundle,
) -> Result<ManifestBundleCanonicalized> {
    let normalized = normalize_manifest_bundle(bundle)?;
    let canonical = canonicalize_json(&normalized)?;
    let bytes = canonicalize_json_to_bytes(&normalized)?;
    let parsed_manifest = compute_manifest_digest(&normalized.manifest)?;
    Ok(ManifestBundleCanonicalized {
        bundle: normalized,
        canonical,
        bytes: bytes.clone(),
        digest_hex: sha3_512_hex(&bytes),
        manifest_bytes: parsed_manifest.1,
        manifest_digest_hex: parsed_manifest.2,
    })
}

pub fn parse_manifest_bundle_bytes(
    bundle_bytes: &[u8],
    require_canonical: bool,
) -> Result<ParsedManifestBundle> {
    let parsed: ManifestBundle = serde_json::from_slice(bundle_bytes)
        .map_err(|error| err(format!("Invalid manifest bundle JSON: {error}")))?;
    let canonicalized = canonicalize_manifest_bundle(&parsed)?;
    if require_canonical && bundle_bytes != canonicalized.bytes.as_slice() {
        return Err(err(format!(
            "Manifest bundle is not {QV_CANONICALIZATION_LABEL} canonical JSON"
        )));
    }
    Ok(canonicalized)
}

pub fn build_initial_manifest_bundle(
    manifest: &ArchiveManifest,
    auth_policy: &AuthPolicy,
) -> Result<ManifestBundle> {
    Ok(normalize_manifest_bundle(&ManifestBundle {
        bundle_type: MANIFEST_BUNDLE_TYPE.to_string(),
        version: MANIFEST_BUNDLE_VERSION,
        bundle_canonicalization: QV_CANONICALIZATION_LABEL.to_string(),
        manifest_canonicalization: QV_CANONICALIZATION_LABEL.to_string(),
        manifest: manifest.clone(),
        manifest_digest: ManifestDigestObject {
            alg: MANIFEST_DIGEST_ALG.to_string(),
            value: canonicalize_archive_manifest(manifest)?.digest_hex,
        },
        auth_policy: auth_policy.clone(),
        attachments: ManifestBundleAttachments {
            public_keys: Vec::new(),
            signatures: Vec::new(),
            timestamps: Vec::new(),
        },
    })?)
}
