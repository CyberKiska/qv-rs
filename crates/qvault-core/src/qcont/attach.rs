use std::collections::HashSet;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;

use crate::auth::{
    assert_manifest_bundle_timestamps, get_signature_suite_info, resolve_open_timestamp_target,
    unpack_pqpk, verify_manifest_signatures, verify_qsig_against_bytes,
    verify_stellar_sig_against_bytes, NamedBinaryArtifact,
};
use crate::bytes::bytes_equal;
use crate::error::{err, Result};
use crate::hash::sha3_512_hex;
use crate::manifest::{
    build_initial_manifest_bundle, canonicalize_manifest_bundle, parse_archive_manifest_bytes,
    parse_manifest_bundle_bytes, recover_committed_auth_policy, ManifestBundle,
    ManifestBundlePublicKeyAttachment, ManifestBundleSignatureAttachment,
    ManifestBundleSignatureTarget, ManifestBundleTimestampAttachment, ParsedArchiveManifest,
};
use crate::qcont::shard::{QcontShard, QcontShardMetadata};
use crate::qcont::split::{build_qcont_shard_blob, BuiltQcontShard, QcontShardBlobParams};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AttachManifestBundleOptions {
    pub manifest_bytes: Option<Vec<u8>>,
    pub bundle_bytes: Option<Vec<u8>>,
    pub signatures: Vec<NamedBinaryArtifact>,
    pub pq_public_key_file_bytes_list: Vec<Vec<u8>>,
    pub timestamps: Vec<NamedBinaryArtifact>,
    pub expected_ed25519_signer: Option<String>,
    pub embed_into_shards: Option<bool>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct AttachedManifestBundle {
    pub shards: Vec<BuiltQcontShard>,
    pub manifest_bytes: Vec<u8>,
    pub manifest_digest_hex: String,
    pub bundle: ManifestBundle,
    pub bundle_bytes: Vec<u8>,
    pub bundle_digest_hex: String,
    pub signable_manifest_bytes: Vec<u8>,
}

impl std::fmt::Debug for AttachedManifestBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachedManifestBundle")
            .field("shard_count", &self.shards.len())
            .field("manifest_digest_hex", &self.manifest_digest_hex)
            .field("bundle_digest_hex", &self.bundle_digest_hex)
            .finish()
    }
}

struct AttachContext {
    prepared_shards: Vec<QcontShard>,
    embedded_manifest: ParsedArchiveManifest,
    working_bundle: ManifestBundle,
}

fn ensure_single_cohort(shards: &[QcontShard]) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut cohort: Option<(&str, &str, &[u8], &[u8])> = None;
    for shard in shards {
        match cohort {
            Some((manifest_digest_hex, bundle_digest_hex, manifest_bytes, bundle_bytes)) => {
                if shard.manifest_digest_hex != manifest_digest_hex
                    || shard.bundle_digest_hex != bundle_digest_hex
                {
                    return Err(err(
                        "Attach requires shards from exactly one archive cohort.",
                    ));
                }
                if !bytes_equal(manifest_bytes, &shard.manifest_bytes)
                    || !bytes_equal(bundle_bytes, &shard.bundle_bytes)
                {
                    return Err(err(
                        "Selected shards do not agree on embedded manifest/bundle bytes",
                    ));
                }
            }
            None => {
                cohort = Some((
                    &shard.manifest_digest_hex,
                    &shard.bundle_digest_hex,
                    &shard.manifest_bytes,
                    &shard.bundle_bytes,
                ));
            }
        }
    }
    let Some((_, _, manifest_bytes, bundle_bytes)) = cohort else {
        return Err(err(
            "Attach requires at least one shard, manifest, or bundle.",
        ));
    };
    Ok((manifest_bytes.to_vec(), bundle_bytes.to_vec()))
}

fn attachment_id(prefix: &str, bytes: &[u8]) -> String {
    format!("{}-{}", prefix, &sha3_512_hex(bytes)[..16])
}

fn detect_external_signature_type(signature: &NamedBinaryArtifact) -> &'static str {
    if signature.bytes.len() >= 4 && &signature.bytes[..4] == b"PQSG" {
        return "qsig";
    }
    if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&signature.bytes) {
        if json.get("schema").and_then(|value| value.as_str()) == Some("stellar-file-signature/v1")
        {
            return "stellar-sig";
        }
    }
    "unknown"
}

fn build_public_key_attachment(pqpk_bytes: &[u8]) -> Result<ManifestBundlePublicKeyAttachment> {
    let unpacked = unpack_pqpk(pqpk_bytes)?;
    let suite = match unpacked.suite_id {
        crate::auth::qsig::SUITE_ID_ML_DSA_44 => "mldsa-44",
        crate::auth::qsig::SUITE_ID_ML_DSA_65 => "mldsa-65",
        crate::auth::qsig::SUITE_ID_ML_DSA_87 => "mldsa-87",
        crate::auth::qsig::SUITE_ID_SLH_DSA_SHAKE_128S => "slhdsa-shake-128s",
        crate::auth::qsig::SUITE_ID_SLH_DSA_SHAKE_192S => "slhdsa-shake-192s",
        crate::auth::qsig::SUITE_ID_SLH_DSA_SHAKE_256S => "slhdsa-shake-256s",
        crate::auth::qsig::SUITE_ID_SLH_DSA_SHAKE_256F => "slhdsa-shake-256f",
        other => return Err(err(format!("Unsupported .pqpk suite id: {other}"))),
    };
    let suite_info = get_signature_suite_info(suite)?;
    Ok(ManifestBundlePublicKeyAttachment {
        id: attachment_id("key", pqpk_bytes),
        kty: suite_info.public_key_type.to_string(),
        suite: suite.to_string(),
        encoding: "base64".to_string(),
        value: BASE64_STANDARD.encode(pqpk_bytes),
        legacy: false,
    })
}

fn build_stellar_signer_attachment(
    signer: Option<&str>,
) -> Option<ManifestBundlePublicKeyAttachment> {
    let signer = signer.unwrap_or("").trim();
    if signer.is_empty() {
        return None;
    }
    Some(ManifestBundlePublicKeyAttachment {
        id: attachment_id("key", signer.as_bytes()),
        kty: "ed25519-public-key".to_string(),
        suite: "ed25519".to_string(),
        encoding: "stellar-address".to_string(),
        value: signer.to_string(),
        legacy: true,
    })
}

fn merge_by_id<T: Clone>(existing: &[T], next: &[T], id_of: impl Fn(&T) -> &str) -> Vec<T> {
    let mut out = existing.to_vec();
    let mut seen = existing
        .iter()
        .map(|item| id_of(item).to_string())
        .collect::<std::collections::HashSet<_>>();
    for value in next {
        if seen.insert(id_of(value).to_string()) {
            out.push(value.clone());
        }
    }
    out
}

fn build_bundle_signature_payloads(
    signatures: &[ManifestBundleSignatureAttachment],
) -> Result<Vec<crate::auth::SignatureArtifact>> {
    signatures
        .iter()
        .map(|signature| {
            if signature.signature_encoding != "base64" {
                return Err(err(format!(
                    "Unsupported bundle signature encoding: {}",
                    signature.signature_encoding
                )));
            }
            Ok(crate::auth::SignatureArtifact {
                id: signature.id.clone(),
                name: signature.id.clone(),
                source: "bundle".to_string(),
                format: signature.format.clone(),
                bytes: BASE64_STANDARD
                    .decode(&signature.signature)
                    .map_err(|error| err(format!("Invalid base64 signature payload: {error}")))?,
                ok: true,
                signature_content_digest_hex: None,
                ots_stamped_digest_hex: None,
            })
        })
        .collect()
}

fn import_external_qsig(
    manifest_bytes: &[u8],
    signature: &NamedBinaryArtifact,
    pq_public_key_file_bytes_list: &[Vec<u8>],
) -> Result<(
    Vec<ManifestBundlePublicKeyAttachment>,
    ManifestBundleSignatureAttachment,
)> {
    let mut matched_key = None;
    let mut successful = Vec::new();
    let mut seen_pinned_keys = HashSet::new();
    for pqpk_bytes in pq_public_key_file_bytes_list {
        let dedupe_key = sha3_512_hex(pqpk_bytes);
        if !seen_pinned_keys.insert(dedupe_key) {
            continue;
        }
        let result = verify_qsig_against_bytes(
            manifest_bytes,
            &signature.bytes,
            Some(pqpk_bytes),
            Some(pqpk_bytes),
        )?;
        if result.ok && result.signer_pinned {
            successful.push((result, pqpk_bytes.clone()));
        }
    }

    let verified = if successful.len() == 1 {
        matched_key = Some(successful[0].1.clone());
        successful.remove(0).0
    } else if successful.len() > 1 {
        return Err(err(format!(
            "Multiple .pqpk files verify {}. Keep only the intended signer key.",
            if signature.name.is_empty() {
                "signature.qsig"
            } else {
                &signature.name
            }
        )));
    } else {
        if !seen_pinned_keys.is_empty() {
            return Err(err(format!(
                "{}: no provided .pqpk file matches this detached PQ signature.",
                if signature.name.is_empty() {
                    "signature.qsig"
                } else {
                    &signature.name
                }
            )));
        }
        let verified = verify_qsig_against_bytes(manifest_bytes, &signature.bytes, None, None)?;
        if !verified.ok {
            return Err(err(format!(
                "{}: {}",
                if signature.name.is_empty() {
                    "signature.qsig"
                } else {
                    &signature.name
                },
                verified
                    .error
                    .unwrap_or_else(|| "signature verification failed".to_string())
            )));
        }
        verified
    };

    let public_key_attachment = matched_key
        .as_deref()
        .map(build_public_key_attachment)
        .transpose()?;
    let digest_value = sha3_512_hex(manifest_bytes);
    Ok((
        public_key_attachment.clone().into_iter().collect(),
        ManifestBundleSignatureAttachment {
            id: attachment_id("sig", &signature.bytes),
            format: "qsig".to_string(),
            suite: verified.suite.unwrap_or_else(|| "unknown".to_string()),
            target: ManifestBundleSignatureTarget {
                target_type: "canonical-manifest".to_string(),
                digest_alg: "SHA3-512".to_string(),
                digest_value,
            },
            signature_encoding: "base64".to_string(),
            signature: BASE64_STANDARD.encode(&signature.bytes),
            public_key_ref: public_key_attachment.as_ref().map(|value| value.id.clone()),
            legacy: false,
        },
    ))
}

fn import_external_stellar_sig(
    manifest_bytes: &[u8],
    signature: &NamedBinaryArtifact,
    expected_ed25519_signer: Option<&str>,
) -> Result<(
    Vec<ManifestBundlePublicKeyAttachment>,
    ManifestBundleSignatureAttachment,
)> {
    let verified = verify_stellar_sig_against_bytes(
        manifest_bytes,
        &signature.bytes,
        None,
        expected_ed25519_signer,
    )?;
    if !verified.ok {
        return Err(err(format!(
            "{}: {}",
            if signature.name.is_empty() {
                "signature.sig"
            } else {
                &signature.name
            },
            verified
                .error
                .unwrap_or_else(|| "signature verification failed".to_string())
        )));
    }
    if expected_ed25519_signer
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
        && verified.user_pinned != true
    {
        return Err(err(format!(
            "{}: signer does not match the expected pinned Stellar signer",
            if signature.name.is_empty() {
                "signature.sig"
            } else {
                &signature.name
            }
        )));
    }
    let public_key_attachment = build_stellar_signer_attachment(verified.signer.as_deref());
    let digest_value = sha3_512_hex(manifest_bytes);
    Ok((
        public_key_attachment.clone().into_iter().collect(),
        ManifestBundleSignatureAttachment {
            id: attachment_id("sig", &signature.bytes),
            format: "stellar-sig".to_string(),
            suite: "ed25519".to_string(),
            target: ManifestBundleSignatureTarget {
                target_type: "canonical-manifest".to_string(),
                digest_alg: "SHA3-512".to_string(),
                digest_value,
            },
            signature_encoding: "base64".to_string(),
            signature: BASE64_STANDARD.encode(&signature.bytes),
            public_key_ref: public_key_attachment.as_ref().map(|value| value.id.clone()),
            legacy: true,
        },
    ))
}

fn resolve_attach_context(
    shards: &[QcontShard],
    options: &AttachManifestBundleOptions,
) -> Result<AttachContext> {
    if !shards.is_empty() {
        let (manifest_bytes, bundle_bytes) = ensure_single_cohort(shards)?;
        let embedded_manifest = parse_archive_manifest_bytes(&manifest_bytes)?;
        let embedded_bundle = parse_manifest_bundle_bytes(&bundle_bytes, true)?;
        if !bytes_equal(&embedded_bundle.manifest_bytes, &embedded_manifest.bytes) {
            return Err(err(
                "Embedded bundle manifest does not match embedded canonical manifest bytes",
            ));
        }

        let working_bundle = if let Some(bundle_bytes) = options.bundle_bytes.as_deref() {
            let parsed_bundle = parse_manifest_bundle_bytes(bundle_bytes, true)?;
            if !bytes_equal(&parsed_bundle.manifest_bytes, &embedded_manifest.bytes) {
                return Err(err(
                    "Provided bundle does not match selected shard manifest",
                ));
            }
            parsed_bundle.bundle
        } else if let Some(manifest_bytes) = options.manifest_bytes.as_deref() {
            let parsed_manifest = parse_archive_manifest_bytes(manifest_bytes)?;
            if !bytes_equal(&parsed_manifest.bytes, &embedded_manifest.bytes) {
                return Err(err(
                    "Provided canonical manifest does not match selected shard manifest",
                ));
            }
            embedded_bundle.bundle
        } else {
            embedded_bundle.bundle
        };

        return Ok(AttachContext {
            prepared_shards: shards.to_vec(),
            embedded_manifest,
            working_bundle,
        });
    }

    if let Some(bundle_bytes) = options.bundle_bytes.as_deref() {
        let parsed_bundle = parse_manifest_bundle_bytes(bundle_bytes, true)?;
        let embedded_manifest = parse_archive_manifest_bytes(&parsed_bundle.manifest_bytes)?;
        return Ok(AttachContext {
            prepared_shards: Vec::new(),
            embedded_manifest,
            working_bundle: parsed_bundle.bundle,
        });
    }

    if let Some(manifest_bytes) = options.manifest_bytes.as_deref() {
        let embedded_manifest = parse_archive_manifest_bytes(manifest_bytes)?;
        let auth_policy = recover_committed_auth_policy(
            &embedded_manifest.manifest.auth_policy_commitment,
            None,
        )?;
        let working_bundle =
            build_initial_manifest_bundle(&embedded_manifest.manifest, &auth_policy)?;
        return Ok(AttachContext {
            prepared_shards: Vec::new(),
            embedded_manifest,
            working_bundle,
        });
    }

    Err(err(
        "No .qcont shards or manifest bundle were provided for attach.",
    ))
}

pub fn attach_manifest_bundle_to_shards(
    shards: &[QcontShard],
    options: &AttachManifestBundleOptions,
) -> Result<AttachedManifestBundle> {
    let AttachContext {
        prepared_shards,
        embedded_manifest,
        working_bundle,
    } = resolve_attach_context(shards, options)?;

    let existing_verification = verify_manifest_signatures(
        &embedded_manifest.bytes,
        &working_bundle.attachments.signatures,
        &working_bundle.attachments.public_keys,
        &[],
        None,
        None,
    )?;
    if let Some(invalid) = existing_verification.results.iter().find(|item| !item.ok) {
        return Err(err(format!(
            "Existing manifest bundle contains invalid signatures: {}",
            invalid
                .error
                .clone()
                .unwrap_or_else(|| "signature verification failed".to_string())
        )));
    }
    assert_manifest_bundle_timestamps(&working_bundle)?;

    let mut imported_public_keys = Vec::new();
    let mut imported_signatures = Vec::new();
    for signature in &options.signatures {
        match detect_external_signature_type(signature) {
            "qsig" => {
                let (public_keys, bundle_signature) = import_external_qsig(
                    &embedded_manifest.bytes,
                    signature,
                    &options.pq_public_key_file_bytes_list,
                )?;
                imported_public_keys.extend(public_keys);
                imported_signatures.push(bundle_signature);
            }
            "stellar-sig" => {
                let (public_keys, bundle_signature) = import_external_stellar_sig(
                    &embedded_manifest.bytes,
                    signature,
                    options.expected_ed25519_signer.as_deref(),
                )?;
                imported_public_keys.extend(public_keys);
                imported_signatures.push(bundle_signature);
            }
            _ => {
                return Err(err(format!(
                    "Unsupported signature file: {}",
                    if signature.name.is_empty() {
                        "unknown"
                    } else {
                        &signature.name
                    }
                )))
            }
        }
    }

    let mut merged_bundle = working_bundle.clone();
    merged_bundle.attachments.public_keys = merge_by_id(
        &working_bundle.attachments.public_keys,
        &imported_public_keys,
        |value| &value.id,
    );
    merged_bundle.attachments.signatures = merge_by_id(
        &working_bundle.attachments.signatures,
        &imported_signatures,
        |value| &value.id,
    );

    if !options.timestamps.is_empty() {
        let signature_payloads =
            build_bundle_signature_payloads(&merged_bundle.attachments.signatures)?;
        let imported_timestamps = options
            .timestamps
            .iter()
            .map(|timestamp| {
                if timestamp.bytes.is_empty() {
                    return Err(err(format!(
                        "Invalid timestamp file: {}",
                        if timestamp.name.is_empty() {
                            "unknown"
                        } else {
                            &timestamp.name
                        }
                    )));
                }
                let resolved = resolve_open_timestamp_target(
                    &timestamp.bytes,
                    Some(&timestamp.name),
                    &signature_payloads,
                )?;
                Ok(ManifestBundleTimestampAttachment {
                    id: attachment_id("ots", &timestamp.bytes),
                    timestamp_type: "opentimestamps".to_string(),
                    target_ref: resolved.target_ref,
                    proof_encoding: "base64".to_string(),
                    proof: BASE64_STANDARD.encode(&timestamp.bytes),
                    apparently_complete: resolved.apparently_complete,
                    complete_proof: resolved.complete_proof,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        merged_bundle.attachments.timestamps = merge_by_id(
            &working_bundle.attachments.timestamps,
            &imported_timestamps,
            |value| &value.id,
        );
    }
    assert_manifest_bundle_timestamps(&merged_bundle)?;

    let canonical_bundle = canonicalize_manifest_bundle(&merged_bundle)?;
    if !bytes_equal(&canonical_bundle.manifest_bytes, &embedded_manifest.bytes) {
        return Err(err(
            "Attach changed the canonical manifest bytes, which is forbidden",
        ));
    }

    let embed_into_shards = options.embed_into_shards.unwrap_or(true);
    let updated_shards = if embed_into_shards {
        prepared_shards
            .iter()
            .map(|shard| {
                let mut meta_json: QcontShardMetadata = shard.meta_json.clone();
                meta_json.has_embedded_bundle = true;
                meta_json.bundle_digest = canonical_bundle.digest_hex.clone();
                meta_json.auth_policy_level = merged_bundle.auth_policy.level;
                let meta_json_bytes = serde_json::to_vec(&meta_json)?;
                Ok(BuiltQcontShard {
                    index: shard.shard_index,
                    bytes: build_qcont_shard_blob(&QcontShardBlobParams {
                        meta_json_bytes: &meta_json_bytes,
                        manifest_bytes: &embedded_manifest.bytes,
                        bundle_bytes: &canonical_bundle.bytes,
                        encapsulated_key: &shard.encapsulated_key,
                        container_nonce: &shard.iv,
                        kdf_salt: &shard.salt,
                        qenc_meta_bytes: &shard.qenc_meta_bytes,
                        key_commitment: &shard.key_commit,
                        shard_index: shard.shard_index,
                        share: &shard.share,
                        body_bytes: &shard.fragments,
                    }),
                })
            })
            .collect::<Result<Vec<_>>>()?
    } else {
        Vec::new()
    };

    Ok(AttachedManifestBundle {
        shards: updated_shards,
        manifest_bytes: embedded_manifest.bytes.clone(),
        manifest_digest_hex: embedded_manifest.digest_hex.clone(),
        bundle: merged_bundle,
        bundle_bytes: canonical_bundle.bytes,
        bundle_digest_hex: canonical_bundle.digest_hex,
        signable_manifest_bytes: embedded_manifest.bytes,
    })
}
