//! Successor lifecycle signature verification counting (oracle: `restore.js` `buildLifecycleVerificationCounts`).

use std::collections::{BTreeMap, BTreeSet};

use crate::auth::signature_identity::compute_detached_signature_identity_digest_hex;
use crate::auth::{SignatureCheckResult, SignatureVerificationCounts};

fn self_signed_policy_warning(result: &SignatureCheckResult) -> String {
    let name = if result.name.is_empty() {
        result.artifact_id.as_str()
    } else {
        result.name.as_str()
    };
    let name = name.trim();
    let label = if name.is_empty() {
        "detached PQ signature"
    } else {
        name
    };
    format!(
        "{label}: detached PQ signature verified only with the embedded signer key and was ignored for trust/policy because no bundled or user-pinned signer key verified."
    )
}

fn attach_proof_identity(result: &mut SignatureCheckResult) {
    result.proof_identity_digest_alg = None;
    result.proof_identity_digest_hex = None;
    let Some(bytes) = result.signature_bytes.as_ref() else {
        return;
    };
    if let Some(hex) = compute_detached_signature_identity_digest_hex(&result.format, bytes) {
        result.proof_identity_digest_alg = Some("SHA3-512".to_string());
        result.proof_identity_digest_hex = Some(hex);
    }
}

fn verified_signer_identity(result: &SignatureCheckResult) -> Option<String> {
    match result.format.as_str() {
        "qsig" => {
            let fingerprint = result
                .signer_fingerprint_hex
                .as_deref()?
                .trim()
                .to_ascii_lowercase();
            if fingerprint.len() != 64 || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                return None;
            }
            Some(format!("pq-sha3-256:{fingerprint}"))
        }
        "stellar-sig" => {
            let signer = result.signer.as_deref()?.trim().to_ascii_uppercase();
            if signer.is_empty() {
                return None;
            }
            Some(format!("stellar-ed25519:{signer}"))
        }
        _ => None,
    }
}

/// Oracle-aligned successor path: proof identity, self-signed exclusion, deduplicated policy
/// counting, and aggregate [`SignatureVerificationCounts`].
pub(crate) fn finalize_successor_lifecycle_verification(
    results: &mut [SignatureCheckResult],
    warnings: &mut Vec<String>,
) -> SignatureVerificationCounts {
    for result in results.iter_mut() {
        result.counted_for_policy = false;
        attach_proof_identity(result);
    }

    for result in results.iter() {
        if result.self_signed {
            warnings.push(self_signed_policy_warning(result));
        }
    }

    #[derive(Clone)]
    struct DedupeEntry {
        family: String,
        strong_pq: bool,
        signer_pinned: bool,
        bundle_pinned: bool,
        user_pinned: bool,
        names: Vec<String>,
        proof_identities: BTreeSet<String>,
        first_policy_index: usize,
    }

    let mut by_key: BTreeMap<String, DedupeEntry> = BTreeMap::new();

    for (index, result) in results.iter().enumerate() {
        if result.self_signed {
            continue;
        }
        if !result.ok {
            continue;
        }
        let Some(digest) = result.proof_identity_digest_hex.as_deref() else {
            continue;
        };
        let family = if result.family.is_empty() {
            "archive-approval"
        } else {
            result.family.as_str()
        };
        let Some(signer_identity) = verified_signer_identity(result) else {
            let display = if result.name.is_empty() {
                result.artifact_id.as_str()
            } else {
                result.name.as_str()
            };
            let display = if display.is_empty() {
                "unnamed signature"
            } else {
                display
            };
            warnings.push(format!(
                "Verified detached {family} signature was not counted because no stable verified signer identity was available: {display}"
            ));
            continue;
        };
        let key = format!("{family}:{signer_identity}");
        let display = if result.name.is_empty() {
            result.artifact_id.clone()
        } else {
            result.name.clone()
        };
        if let Some(entry) = by_key.get_mut(&key) {
            entry.strong_pq |= result.strong_pq;
            entry.signer_pinned |= result.signer_pinned;
            entry.bundle_pinned |= result.bundle_pinned;
            entry.user_pinned |= result.user_pinned;
            entry.proof_identities.insert(digest.to_string());
            entry.names.push(if display.is_empty() {
                key.clone()
            } else {
                display
            });
            continue;
        }
        by_key.insert(
            key.clone(),
            DedupeEntry {
                family: family.to_string(),
                strong_pq: result.strong_pq,
                signer_pinned: result.signer_pinned,
                bundle_pinned: result.bundle_pinned,
                user_pinned: result.user_pinned,
                names: vec![if display.is_empty() { key } else { display }],
                proof_identities: BTreeSet::from([digest.to_string()]),
                first_policy_index: index,
            },
        );
    }

    for entry in by_key.values() {
        if entry.family == "archive-approval" {
            results[entry.first_policy_index].counted_for_policy = true;
        }
    }

    for entry in by_key.values() {
        if entry.names.len() <= 1 {
            continue;
        }
        let detail = if entry.proof_identities.len() == 1 {
            "Duplicate detached signature proof"
        } else {
            "Additional detached signature from the same verified signer"
        };
        warnings.push(format!(
            "{detail} ignored for {} policy/state counting: {}",
            entry.family,
            entry.names.join(", ")
        ));
    }

    let invalid_signature_count = results.iter().filter(|result| !result.ok).count();
    if invalid_signature_count > 0 {
        warnings.push(format!(
            "{invalid_signature_count} detached signature(s) did not verify and were ignored for archive policy evaluation."
        ));
    }

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

    for entry in by_key.values() {
        counts.valid_total += 1;
        if entry.strong_pq {
            counts.valid_strong_pq += 1;
        }
        if entry.signer_pinned {
            counts.pinned_valid_total += 1;
            if entry.strong_pq {
                counts.pinned_valid_strong_pq += 1;
            }
        }
        if entry.bundle_pinned {
            counts.bundle_pinned_valid_total += 1;
        }
        if entry.user_pinned {
            counts.user_pinned_valid_total += 1;
        }
        match entry.family.as_str() {
            "archive-approval" => {
                counts.valid_archive_approval += 1;
                if entry.strong_pq {
                    counts.valid_archive_approval_strong_pq += 1;
                }
                if entry.signer_pinned {
                    counts.archive_approval_pinned_valid_total += 1;
                }
                if entry.bundle_pinned {
                    counts.archive_approval_bundle_pinned_valid_total += 1;
                }
                if entry.user_pinned {
                    counts.archive_approval_user_pinned_valid_total += 1;
                }
            }
            "maintenance" => counts.valid_maintenance += 1,
            "source-evidence" => counts.valid_source_evidence += 1,
            _ => {}
        }
    }

    counts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{
        create_detached_qsig, generate_signing_keypair, pack_public_key_file,
        verify_qsig_against_bytes, DetachedSignOptions, PqSignatureSuite,
    };
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    use serde_json::Value;

    #[test]
    fn embedded_only_qsig_is_self_signed_and_excluded_from_policy_counts() {
        let fixture: Value = serde_json::from_slice(include_bytes!(
            "../../tests/data/corpus/qsig/mldsa-44.valid.json"
        ))
        .unwrap();
        let qsig = B64.decode(fixture["bytes"].as_str().unwrap()).unwrap();
        let message = B64
            .decode(fixture["runtime"]["messageBytes"].as_str().unwrap())
            .unwrap();

        let mut verified =
            verify_qsig_against_bytes(&message, &qsig, None, None).expect("verify qsig");
        assert!(verified.ok);
        assert!(verified.self_signed);
        verified.name = "ext.qsig".to_string();
        verified.artifact_id = "ext.qsig".to_string();

        let mut results = vec![verified];
        let mut warnings = Vec::new();
        let counts = finalize_successor_lifecycle_verification(&mut results, &mut warnings);
        assert_eq!(counts.valid_archive_approval, 0);
        assert!(!results[0].counted_for_policy);
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("ignored for trust/policy")),
            "{warnings:?}"
        );
    }

    #[test]
    fn matching_pqpk_clears_self_signed_and_counts_for_policy() {
        let fixture: Value = serde_json::from_slice(include_bytes!(
            "../../tests/data/corpus/qsig/mldsa-44.valid.json"
        ))
        .unwrap();
        let pqpk_fixture: Value = serde_json::from_slice(include_bytes!(
            "../../tests/data/corpus/pqpk/mldsa-44.valid.json"
        ))
        .unwrap();
        let qsig = B64.decode(fixture["bytes"].as_str().unwrap()).unwrap();
        let pqpk = B64.decode(pqpk_fixture["bytes"].as_str().unwrap()).unwrap();
        let message = B64
            .decode(fixture["runtime"]["messageBytes"].as_str().unwrap())
            .unwrap();

        let mut verified =
            verify_qsig_against_bytes(&message, &qsig, None, Some(&pqpk)).expect("verify qsig");
        assert!(verified.ok);
        assert!(!verified.self_signed);
        verified.name = "ext.qsig".to_string();
        let mut results = vec![verified];
        let mut warnings = Vec::new();
        let counts = finalize_successor_lifecycle_verification(&mut results, &mut warnings);
        assert_eq!(counts.valid_archive_approval, 1);
        assert!(results[0].counted_for_policy);
    }

    #[test]
    fn duplicate_proof_identity_collapses_counts() {
        let fixture: Value = serde_json::from_slice(include_bytes!(
            "../../tests/data/corpus/qsig/mldsa-44.valid.json"
        ))
        .unwrap();
        let pqpk_fixture: Value = serde_json::from_slice(include_bytes!(
            "../../tests/data/corpus/pqpk/mldsa-44.valid.json"
        ))
        .unwrap();
        let qsig = B64.decode(fixture["bytes"].as_str().unwrap()).unwrap();
        let pqpk = B64.decode(pqpk_fixture["bytes"].as_str().unwrap()).unwrap();
        let message = B64
            .decode(fixture["runtime"]["messageBytes"].as_str().unwrap())
            .unwrap();

        let mut a = verify_qsig_against_bytes(&message, &qsig, None, Some(&pqpk)).unwrap();
        a.name = "a.qsig".to_string();
        a.artifact_id = "a".to_string();
        let mut b = verify_qsig_against_bytes(&message, &qsig, None, Some(&pqpk)).unwrap();
        b.name = "b.qsig".to_string();
        b.artifact_id = "b".to_string();
        let mut results = vec![a, b];
        let mut warnings = Vec::new();
        let counts = finalize_successor_lifecycle_verification(&mut results, &mut warnings);
        assert_eq!(counts.valid_archive_approval, 1);
        assert!(results[0].counted_for_policy);
        assert!(!results[1].counted_for_policy);
        assert!(
            warnings
                .iter()
                .any(|warning| warning.starts_with("Duplicate detached")),
            "{warnings:?}"
        );
    }

    #[test]
    fn one_signer_with_distinct_signature_proofs_counts_once() {
        let message = b"same archive state, randomized approvals";
        let keypair = generate_signing_keypair(PqSignatureSuite::MlDsa44).unwrap();
        let first_artifact = create_detached_qsig(DetachedSignOptions::new(
            PqSignatureSuite::MlDsa44,
            keypair.secret_key_bytes(),
            message,
        ))
        .unwrap();
        let second_artifact = create_detached_qsig(DetachedSignOptions::new(
            PqSignatureSuite::MlDsa44,
            keypair.secret_key_bytes(),
            message,
        ))
        .unwrap();
        let pqpk =
            pack_public_key_file(PqSignatureSuite::MlDsa44, keypair.public_key_bytes()).unwrap();

        let mut first =
            verify_qsig_against_bytes(message, &first_artifact.qsig_bytes, None, Some(&pqpk))
                .unwrap();
        first.name = "first.qsig".to_string();
        let mut second =
            verify_qsig_against_bytes(message, &second_artifact.qsig_bytes, None, Some(&pqpk))
                .unwrap();
        second.name = "second.qsig".to_string();

        let mut results = vec![first, second];
        let mut warnings = Vec::new();
        let counts = finalize_successor_lifecycle_verification(&mut results, &mut warnings);
        assert_ne!(
            results[0].proof_identity_digest_hex,
            results[1].proof_identity_digest_hex
        );
        assert_eq!(counts.valid_archive_approval, 1);
        assert!(results[0].counted_for_policy);
        assert!(!results[1].counted_for_policy);
        assert!(warnings.iter().any(|warning| warning
            .starts_with("Additional detached signature from the same verified signer")));
    }

    #[test]
    fn two_distinct_verified_signer_identities_count_twice() {
        let message = b"archive state approved by two signers";
        let first_keypair = generate_signing_keypair(PqSignatureSuite::MlDsa44).unwrap();
        let second_keypair = generate_signing_keypair(PqSignatureSuite::MlDsa44).unwrap();
        let first_artifact = create_detached_qsig(DetachedSignOptions::new(
            PqSignatureSuite::MlDsa44,
            first_keypair.secret_key_bytes(),
            message,
        ))
        .unwrap();
        let second_artifact = create_detached_qsig(DetachedSignOptions::new(
            PqSignatureSuite::MlDsa44,
            second_keypair.secret_key_bytes(),
            message,
        ))
        .unwrap();
        let first_pqpk =
            pack_public_key_file(PqSignatureSuite::MlDsa44, first_keypair.public_key_bytes())
                .unwrap();
        let second_pqpk =
            pack_public_key_file(PqSignatureSuite::MlDsa44, second_keypair.public_key_bytes())
                .unwrap();

        let mut first =
            verify_qsig_against_bytes(message, &first_artifact.qsig_bytes, None, Some(&first_pqpk))
                .unwrap();
        first.name = "first-signer.qsig".to_string();
        let mut second = verify_qsig_against_bytes(
            message,
            &second_artifact.qsig_bytes,
            None,
            Some(&second_pqpk),
        )
        .unwrap();
        second.name = "second-signer.qsig".to_string();

        let mut results = vec![first, second];
        let mut warnings = Vec::new();
        let counts = finalize_successor_lifecycle_verification(&mut results, &mut warnings);
        assert_eq!(counts.valid_archive_approval, 2);
        assert!(results.iter().all(|result| result.counted_for_policy));
        assert!(warnings
            .iter()
            .all(|warning| !warning.contains("policy/state counting")));
    }
}
