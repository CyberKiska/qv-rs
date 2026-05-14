use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;

use crate::auth::{
    get_signature_suite_info, qsig::qsig_suite_name, unpack_pqpk, unpack_qsig,
    verify_qsig_against_bytes, verify_stellar_sig_against_bytes, NamedBinaryArtifact,
    SignatureArtifact, SignatureCheckResult, SignatureVerificationCounts,
    SignatureVerificationReport, SignatureVerificationStatus,
};
use crate::bytes::timing_safe_equal;
use crate::error::{err, Result};
use crate::hash::{sha256_hex, sha3_512_hex};
use crate::manifest::{ManifestBundlePublicKeyAttachment, ManifestBundleSignatureAttachment};

const MAGIC_QSIG: &[u8; 4] = b"PQSG";

fn decode_json_bytes(bytes: &[u8]) -> Option<serde_json::Value> {
    serde_json::from_slice(bytes).ok()
}

fn detect_external_signature_type(signature: &NamedBinaryArtifact) -> &'static str {
    if signature.bytes.len() >= 4 && timing_safe_equal(&signature.bytes[..4], MAGIC_QSIG) {
        return "qsig";
    }

    if !signature.name.is_empty() {
        let lower = signature.name.to_ascii_lowercase();
        if lower.ends_with(".sig") || lower.ends_with(".json") || !lower.is_empty() {
            if let Some(json) = decode_json_bytes(&signature.bytes) {
                if json.get("schema").and_then(|value| value.as_str())
                    == Some("stellar-file-signature/v1")
                {
                    return "stellar-sig";
                }
            }
        }
    }

    "unknown"
}

fn failed_signature_check(format: &str, error: impl Into<String>) -> SignatureCheckResult {
    SignatureCheckResult {
        ok: false,
        self_signed: false,
        bundle_pinned: false,
        user_pinned: false,
        signer_pinned: false,
        name: String::new(),
        source: String::new(),
        format: format.to_string(),
        suite: None,
        suite_display: None,
        strong_pq: false,
        key_source: None,
        signer_fingerprint_hex: None,
        signer_label: None,
        signer: None,
        error: Some(error.into()),
        warnings: Vec::new(),
        artifact_id: String::new(),
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

fn load_bundle_public_key_bytes(
    public_key_entry: &ManifestBundlePublicKeyAttachment,
) -> Result<Vec<u8>> {
    if public_key_entry.encoding != "base64" {
        return Err(err(format!(
            "Bundle publicKeyRef {} must use base64 encoding for PQ signatures",
            public_key_entry.id
        )));
    }
    BASE64_STANDARD
        .decode(&public_key_entry.value)
        .map_err(|error| err(format!("Invalid base64 bundle public key: {error}")))
}

fn resolve_bundle_qsig_key(
    signature: &ManifestBundleSignatureAttachment,
    public_key_entry: Option<&ManifestBundlePublicKeyAttachment>,
    qsig_bytes: &[u8],
) -> Result<Option<Vec<u8>>> {
    let Some(public_key_ref) = signature.public_key_ref.as_deref() else {
        return Ok(None);
    };
    let Some(public_key_entry) = public_key_entry else {
        return Err(err(format!(
            "Signature publicKeyRef {public_key_ref} is not present in the bundle"
        )));
    };

    let parsed_qsig = unpack_qsig(qsig_bytes)?;
    let actual_suite = qsig_suite_name(parsed_qsig.suite_id)?;
    if signature.suite != actual_suite {
        return Err(err(format!(
            "Bundle signature {} declares suite {} but the .qsig payload is {}",
            signature.id, signature.suite, actual_suite
        )));
    }
    if public_key_entry.suite != actual_suite {
        return Err(err(format!(
            "Bundle publicKeyRef {} declares suite {} but the referenced .pqpk is required to match {}",
            public_key_entry.id, public_key_entry.suite, actual_suite
        )));
    }

    let suite_info = get_signature_suite_info(actual_suite)?;
    if public_key_entry.kty != suite_info.public_key_type {
        return Err(err(format!(
            "Bundle publicKeyRef {} has incompatible kty {} for suite {}",
            public_key_entry.id, public_key_entry.kty, actual_suite
        )));
    }

    let public_key_bytes = load_bundle_public_key_bytes(public_key_entry)?;
    let unpacked = unpack_pqpk(&public_key_bytes)?;
    if unpacked.suite_id != parsed_qsig.suite_id {
        return Err(err(format!(
            "Bundle publicKeyRef {} does not match the .qsig suite",
            public_key_entry.id
        )));
    }
    Ok(Some(public_key_bytes))
}

fn resolve_bundle_stellar_signer(
    signature: &ManifestBundleSignatureAttachment,
    public_key_entry: Option<&ManifestBundlePublicKeyAttachment>,
) -> Result<Option<String>> {
    let Some(public_key_ref) = signature.public_key_ref.as_deref() else {
        return Ok(None);
    };
    let Some(public_key_entry) = public_key_entry else {
        return Err(err(format!(
            "Signature publicKeyRef {public_key_ref} is not present in the bundle"
        )));
    };

    if signature.suite != "ed25519" {
        return Err(err(format!(
            "Bundle stellar-sig {} declares unsupported suite {}",
            signature.id, signature.suite
        )));
    }
    if public_key_entry.suite != "ed25519" {
        return Err(err(format!(
            "Bundle publicKeyRef {} has incompatible suite {} for stellar-sig",
            public_key_entry.id, public_key_entry.suite
        )));
    }
    if public_key_entry.kty != "ed25519-public-key" {
        return Err(err(format!(
            "Bundle publicKeyRef {} has incompatible kty {} for stellar-sig",
            public_key_entry.id, public_key_entry.kty
        )));
    }
    if public_key_entry.encoding != "stellar-address" {
        return Err(err(format!(
            "Bundle publicKeyRef {} must use stellar-address encoding for stellar-sig",
            public_key_entry.id
        )));
    }
    Ok(Some(public_key_entry.value.trim().to_string()))
}

fn attach_signature_digests(mut result: SignatureCheckResult) -> SignatureCheckResult {
    if let Some(signature_bytes) = &result.signature_bytes {
        result.signature_content_digest_alg = Some("SHA3-512".to_string());
        result.signature_content_digest_hex = Some(sha3_512_hex(signature_bytes));
        result.ots_stamped_digest_alg = Some("SHA-256".to_string());
        result.ots_stamped_digest_hex = Some(sha256_hex(signature_bytes));
    }
    result
}

fn verify_bundle_signature(
    manifest_bytes: &[u8],
    signature: &ManifestBundleSignatureAttachment,
    public_keys_by_id: &std::collections::HashMap<String, ManifestBundlePublicKeyAttachment>,
    pinned_pq_public_key_file_bytes: Option<&[u8]>,
    expected_ed25519_signer: Option<&str>,
) -> Result<SignatureCheckResult> {
    let name = if signature.id.is_empty() {
        "bundle-signature".to_string()
    } else {
        signature.id.clone()
    };
    let bundle_public_key_entry =
        public_keys_by_id.get(signature.public_key_ref.as_deref().unwrap_or(""));

    let mut result = if signature.format == "qsig" {
        let qsig_bytes = if signature.signature_encoding == "base64" {
            BASE64_STANDARD
                .decode(&signature.signature)
                .map_err(|error| err(format!("Invalid base64 bundle signature: {error}")))?
        } else {
            return Err(err(format!(
                "Unsupported bundle signature encoding: {}",
                signature.signature_encoding
            )));
        };
        match resolve_bundle_qsig_key(signature, bundle_public_key_entry, &qsig_bytes) {
            Ok(bundle_verification_key_bytes) => verify_qsig_against_bytes(
                manifest_bytes,
                &qsig_bytes,
                bundle_verification_key_bytes.as_deref(),
                pinned_pq_public_key_file_bytes,
            )?,
            Err(error) => {
                let mut failed = failed_signature_check("qsig", error.to_string());
                failed.signature_bytes = Some(qsig_bytes);
                failed
            }
        }
    } else if signature.format == "stellar-sig" {
        let sig_json_bytes = if signature.signature_encoding == "base64" {
            BASE64_STANDARD
                .decode(&signature.signature)
                .map_err(|error| err(format!("Invalid base64 bundle signature: {error}")))?
        } else {
            return Err(err(format!(
                "Unsupported bundle signature encoding: {}",
                signature.signature_encoding
            )));
        };
        match resolve_bundle_stellar_signer(signature, bundle_public_key_entry) {
            Ok(bundle_signer) => verify_stellar_sig_against_bytes(
                manifest_bytes,
                &sig_json_bytes,
                bundle_signer.as_deref(),
                expected_ed25519_signer,
            )?,
            Err(error) => {
                let mut failed = failed_signature_check("stellar-sig", error.to_string());
                failed.signature_bytes = Some(sig_json_bytes);
                failed
            }
        }
    } else {
        failed_signature_check(
            &signature.format,
            format!("Unsupported signature format: {}", signature.format),
        )
    };
    result.name = name.clone();
    result.source = "bundle".to_string();
    result.artifact_id = if signature.id.is_empty() {
        name
    } else {
        signature.id.clone()
    };
    Ok(attach_signature_digests(result))
}

fn verify_external_signature(
    manifest_bytes: &[u8],
    signature: &NamedBinaryArtifact,
    pinned_pq_public_key_file_bytes: Option<&[u8]>,
    expected_ed25519_signer: Option<&str>,
) -> Result<SignatureCheckResult> {
    let sig_type = detect_external_signature_type(signature);
    let mut result = match sig_type {
        "qsig" => verify_qsig_against_bytes(
            manifest_bytes,
            &signature.bytes,
            None,
            pinned_pq_public_key_file_bytes,
        )?,
        "stellar-sig" => verify_stellar_sig_against_bytes(
            manifest_bytes,
            &signature.bytes,
            None,
            expected_ed25519_signer,
        )?,
        _ => failed_signature_check("unknown", "Unsupported signature format"),
    };
    result.name = if signature.name.is_empty() {
        match sig_type {
            "qsig" => "signature.qsig".to_string(),
            "stellar-sig" => "signature.sig".to_string(),
            _ => "unknown".to_string(),
        }
    } else {
        signature.name.clone()
    };
    result.source = "external".to_string();
    result.artifact_id = result.name.clone();
    Ok(attach_signature_digests(result))
}

fn build_counts(
    results: &mut [SignatureCheckResult],
) -> (SignatureVerificationCounts, Vec<String>) {
    let mut counts = SignatureVerificationCounts {
        valid_total: 0,
        valid_strong_pq: 0,
        pinned_valid_total: 0,
        pinned_valid_strong_pq: 0,
        bundle_pinned_valid_total: 0,
        user_pinned_valid_total: 0,
        valid_archive_approval: 0,
        valid_archive_approval_strong_pq: 0,
        archive_approval_pinned_valid_total: 0,
        archive_approval_bundle_pinned_valid_total: 0,
        archive_approval_user_pinned_valid_total: 0,
        valid_maintenance: 0,
        valid_source_evidence: 0,
    };
    let mut duplicate_warnings = Vec::new();
    let mut unique_valid =
        std::collections::BTreeMap::<String, (usize, bool, bool, bool, bool, Vec<String>)>::new();

    for index in 0..results.len() {
        results[index].counted_for_policy = false;
        let Some(signature_content_digest_hex) =
            results[index].signature_content_digest_hex.as_deref()
        else {
            continue;
        };
        if !results[index].ok {
            continue;
        }
        let dedupe_key = format!("{}:{signature_content_digest_hex}", results[index].format);
        match unique_valid.get_mut(&dedupe_key) {
            Some(entry) => {
                entry.1 |= results[index].strong_pq;
                entry.2 |= results[index].signer_pinned;
                entry.3 |= results[index].bundle_pinned;
                entry.4 |= results[index].user_pinned;
                if entry.2 {
                    results[entry.0].counted_for_policy = true;
                }
                entry.5.push(if results[index].name.is_empty() {
                    results[index].artifact_id.clone()
                } else {
                    results[index].name.clone()
                });
            }
            None => {
                results[index].counted_for_policy = results[index].signer_pinned;
                unique_valid.insert(
                    dedupe_key,
                    (
                        index,
                        results[index].strong_pq,
                        results[index].signer_pinned,
                        results[index].bundle_pinned,
                        results[index].user_pinned,
                        vec![if results[index].name.is_empty() {
                            results[index].artifact_id.clone()
                        } else {
                            results[index].name.clone()
                        }],
                    ),
                );
            }
        }
    }

    for (_, (_, strong_pq, signer_pinned, bundle_pinned, user_pinned, names)) in unique_valid {
        counts.valid_total += 1;
        if strong_pq {
            counts.valid_strong_pq += 1;
        }
        if signer_pinned {
            counts.pinned_valid_total += 1;
        }
        if signer_pinned && strong_pq {
            counts.pinned_valid_strong_pq += 1;
        }
        if bundle_pinned {
            counts.bundle_pinned_valid_total += 1;
        }
        if user_pinned {
            counts.user_pinned_valid_total += 1;
        }
        if names.len() > 1 {
            duplicate_warnings.push(format!(
                "Duplicate detached signature ignored for policy counting: {}",
                names.join(", ")
            ));
        }
    }

    (counts, duplicate_warnings)
}

pub fn verify_manifest_signatures(
    manifest_bytes: &[u8],
    bundle_signatures: &[ManifestBundleSignatureAttachment],
    bundle_public_keys: &[ManifestBundlePublicKeyAttachment],
    external_signatures: &[NamedBinaryArtifact],
    pinned_pq_public_key_file_bytes: Option<&[u8]>,
    expected_ed25519_signer: Option<&str>,
) -> Result<SignatureVerificationReport> {
    let public_keys_by_id = bundle_public_keys
        .iter()
        .cloned()
        .map(|item| (item.id.clone(), item))
        .collect::<std::collections::HashMap<_, _>>();
    let user_pin_provided = pinned_pq_public_key_file_bytes.is_some()
        || expected_ed25519_signer
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false);

    let mut results = Vec::new();
    let mut warnings = Vec::new();

    for signature in bundle_signatures {
        let result = verify_bundle_signature(
            manifest_bytes,
            signature,
            &public_keys_by_id,
            pinned_pq_public_key_file_bytes,
            expected_ed25519_signer,
        )?;
        warnings.extend(result.warnings.clone());
        results.push(result);
    }

    for signature in external_signatures {
        let result = verify_external_signature(
            manifest_bytes,
            signature,
            pinned_pq_public_key_file_bytes,
            expected_ed25519_signer,
        )?;
        warnings.extend(result.warnings.clone());
        results.push(result);
    }

    let (counts, duplicate_warnings) = build_counts(&mut results);
    warnings.extend(duplicate_warnings);
    if counts.valid_total > counts.pinned_valid_total {
        warnings.push(
            "Verified signatures without a trusted signer binding were ignored for archive policy counting."
                .to_string(),
        );
    }
    let signature_artifacts = results
        .iter()
        .filter_map(|result| {
            result
                .signature_bytes
                .as_ref()
                .map(|bytes| SignatureArtifact {
                    id: if result.artifact_id.is_empty() {
                        result.name.clone()
                    } else {
                        result.artifact_id.clone()
                    },
                    name: result.name.clone(),
                    source: result.source.clone(),
                    format: result.format.clone(),
                    bytes: bytes.clone(),
                    ok: result.ok,
                    signature_content_digest_hex: result.signature_content_digest_hex.clone(),
                    ots_stamped_digest_hex: result.ots_stamped_digest_hex.clone(),
                })
        })
        .collect::<Vec<_>>();

    Ok(SignatureVerificationReport {
        provided: !bundle_signatures.is_empty() || !external_signatures.is_empty(),
        results,
        warnings,
        counts: counts.clone(),
        signature_artifacts,
        status: SignatureVerificationStatus {
            signature_verified: counts.valid_total > 0,
            strong_pq_signature_verified: counts.valid_strong_pq > 0,
            signer_pinned: counts.pinned_valid_total > 0,
            signer_identity_pinned: counts.pinned_valid_total > 0,
            bundle_pinned: counts.bundle_pinned_valid_total > 0,
            user_pinned: counts.user_pinned_valid_total > 0,
            user_pin_provided,
        },
    })
}
