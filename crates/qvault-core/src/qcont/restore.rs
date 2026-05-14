use std::collections::{BTreeMap, HashSet};

use crate::auth::{
    assert_manifest_bundle_timestamps, inspect_timestamp_evidence, verify_manifest_signatures,
    ArchivePolicyEvaluation, AuthPolicy, AuthPolicyLevel, AuthenticityReport, AuthenticityStatus,
    VerificationInputs,
};
use crate::bytes::bytes_equal;
use crate::erasure;
use crate::error::{err, Result};
use crate::hash::sha3_512_hex;
use crate::manifest::{
    assert_auth_policy_commitment, parse_archive_manifest_bytes, parse_manifest_bundle_bytes,
    ArchiveManifest,
};
use crate::policy::validate_container_policy_metadata;
use crate::qcont::shard::QcontShard;
use crate::qenc::build_qenc_header;
use crate::sss::combine_shares;
use zeroize::Zeroize;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RestoreQcontOptions {
    pub manifest_bytes: Option<Vec<u8>>,
    pub bundle_bytes: Option<Vec<u8>>,
    pub verification: VerificationInputs,
    pub strict: bool,
}

#[derive(Clone, PartialEq, Eq)]
pub struct RestoredQcont {
    pub qenc_bytes: Vec<u8>,
    pub priv_key: Vec<u8>,
    pub container_id: String,
    pub container_hash: String,
    pub private_key_hash: Option<String>,
    pub recovered_qenc_hash: String,
    pub recovered_priv_hash: String,
    pub rejected_shard_indices: Vec<u16>,
    pub qenc_ok: bool,
    pub qkey_ok: bool,
    pub manifest: ArchiveManifest,
    pub manifest_bytes: Vec<u8>,
    pub manifest_digest_hex: String,
    pub bundle: crate::manifest::ManifestBundle,
    pub bundle_bytes: Vec<u8>,
    pub bundle_digest_hex: String,
    pub manifest_source: String,
    pub authenticity: AuthenticityReport,
    pub warnings: Vec<String>,
}

impl std::fmt::Debug for RestoredQcont {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RestoredQcont")
            .field("qenc_bytes_len", &self.qenc_bytes.len())
            .field("priv_key_len", &self.priv_key.len())
            .field("container_id", &self.container_id)
            .field("container_hash", &self.container_hash)
            .field("private_key_hash", &self.private_key_hash)
            .field("recovered_qenc_hash", &self.recovered_qenc_hash)
            .field("recovered_priv_hash", &self.recovered_priv_hash)
            .field("rejected_shard_indices", &self.rejected_shard_indices)
            .field("manifest_digest_hex", &self.manifest_digest_hex)
            .field("bundle_digest_hex", &self.bundle_digest_hex)
            .field("manifest_source", &self.manifest_source)
            .finish()
    }
}

#[derive(Debug, Clone)]
struct CandidateCohort<'a> {
    manifest_digest_hex: String,
    bundle_digest_hex: String,
    manifest_bytes: &'a [u8],
    bundle_bytes: &'a [u8],
}

#[derive(Debug, Clone)]
struct EnrichedCandidate {
    manifest_digest_hex: String,
    bundle_digest_hex: String,
    embedded_bundle_digest_hex: String,
    manifest: ArchiveManifest,
    manifest_bytes: Vec<u8>,
    bundle: crate::manifest::ManifestBundle,
    bundle_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
struct CandidateAuthenticity {
    verification: crate::auth::SignatureVerificationReport,
    policy: ArchivePolicyEvaluation,
    timestamp_evidence: Vec<crate::auth::TimestampEvidence>,
    warnings: Vec<String>,
}

#[derive(Debug, Clone)]
struct ArchiveContext {
    candidate: EnrichedCandidate,
    authenticity: CandidateAuthenticity,
    source: String,
    use_manifest_wide_shard_selection: bool,
}

pub fn restore_from_shards(
    shards: &[QcontShard],
    options: &RestoreQcontOptions,
) -> Result<RestoredQcont> {
    if shards.is_empty() {
        return Err(err("No shards provided"));
    }
    if options.manifest_bytes.is_some() && options.bundle_bytes.is_some() {
        return Err(err(
            "manifest_bytes and bundle_bytes are mutually exclusive restore selectors",
        ));
    }

    let archive_context = resolve_archive_context(shards, options)?;
    let candidate = &archive_context.candidate;
    let manifest = &candidate.manifest;
    let bundle = &candidate.bundle;
    let manifest_digest_hex = candidate.manifest_digest_hex.clone();
    let bundle_digest_hex = candidate.bundle_digest_hex.clone();
    let use_manifest_wide_shard_selection = archive_context.use_manifest_wide_shard_selection;
    let selected_embedded_bundle_digest_hex = candidate.embedded_bundle_digest_hex.clone();

    let group = shards
        .iter()
        .filter(|shard| {
            shard.manifest_digest_hex == manifest_digest_hex
                && (use_manifest_wide_shard_selection
                    || shard.bundle_digest_hex == selected_embedded_bundle_digest_hex)
        })
        .cloned()
        .collect::<Vec<_>>();
    let rejected_shard_indices = shards
        .iter()
        .filter(|shard| {
            shard.manifest_digest_hex != manifest_digest_hex
                || (!use_manifest_wide_shard_selection
                    && shard.bundle_digest_hex != selected_embedded_bundle_digest_hex)
        })
        .map(|shard| shard.shard_index)
        .collect::<Vec<_>>();
    if group.is_empty() {
        return Err(err("No shard matches selected archive context"));
    }

    let n = ensure_positive_integer(
        manifest.sharding.reed_solomon.n as usize,
        "manifest.sharding.reedSolomon.n",
        2,
    )?;
    let k = ensure_positive_integer(
        manifest.sharding.reed_solomon.k as usize,
        "manifest.sharding.reedSolomon.k",
        2,
    )?;
    let m = ensure_positive_integer(
        manifest.sharding.reed_solomon.parity as usize,
        "manifest.sharding.reedSolomon.parity",
        0,
    )?;
    let t = ensure_positive_integer(
        manifest.sharding.shamir.threshold as usize,
        "manifest.sharding.shamir.threshold",
        2,
    )?;
    let share_count = ensure_positive_integer(
        manifest.sharding.shamir.share_count as usize,
        "manifest.sharding.shamir.shareCount",
        2,
    )?;
    if share_count != n {
        return Err(err(format!(
            "Invalid manifest sharding: Shamir shareCount {share_count} must equal RS n {n}"
        )));
    }
    if (m % 2) != 0 {
        return Err(err("Invalid manifest sharding: RS parity must be even"));
    }
    if k >= n {
        return Err(err("Invalid manifest sharding: expected k < n"));
    }
    let allowed_failures = m / 2;
    let expected_threshold = k + allowed_failures;
    if t != expected_threshold {
        return Err(err(format!(
            "Invalid manifest threshold: expected {expected_threshold}, got {t}"
        )));
    }

    let chunk_size = ensure_positive_integer(
        manifest.qenc.chunk_size as usize,
        "manifest.qenc.chunkSize",
        1,
    )? as u64;
    let chunk_count = ensure_positive_integer(
        manifest.qenc.chunk_count as usize,
        "manifest.qenc.chunkCount",
        1,
    )? as u64;
    let payload_length = ensure_positive_integer(
        manifest.qenc.payload_length as usize,
        "manifest.qenc.payloadLength",
        1,
    )? as u64;
    let container_id = manifest.qenc.container_id.clone();
    if container_id.is_empty() {
        return Err(err("Manifest is missing qenc.containerId"));
    }

    let base = &group[0];
    if base.key_commit.len() != 32 {
        return Err(err("Shard is missing required key commitment"));
    }
    let base_key_commit = base.key_commit;
    let mut shard_by_index = BTreeMap::new();
    for shard in &group {
        if usize::from(shard.shard_index) >= n {
            return Err(err(format!("Invalid shardIndex {}", shard.shard_index)));
        }
        if shard_by_index.insert(shard.shard_index, shard).is_some() {
            return Err(err(format!(
                "Duplicate shardIndex {} detected",
                shard.shard_index
            )));
        }
        ensure_equal(&shard.meta_json.container_id, &container_id, "containerId")?;
        ensure_equal(&(shard.meta_json.n as usize), &n, "n")?;
        ensure_equal(&(shard.meta_json.k as usize), &k, "k")?;
        ensure_equal(&(shard.meta_json.m as usize), &m, "m")?;
        ensure_equal(&(shard.meta_json.t as usize), &t, "t")?;
        ensure_equal(
            &normalize_hex_string(&shard.meta_json.manifest_digest),
            &manifest_digest_hex,
            "manifestDigest",
        )?;
        if !use_manifest_wide_shard_selection {
            ensure_equal(
                &normalize_hex_string(&shard.meta_json.bundle_digest),
                &selected_embedded_bundle_digest_hex,
                "bundleDigest",
            )?;
        }
        if !bytes_equal(&shard.encapsulated_key, &base.encapsulated_key) {
            return Err(err(format!(
                "Shard header mismatch: encapsulatedKey differs for shard {}",
                shard.shard_index
            )));
        }
        if !bytes_equal(&shard.iv, &base.iv) {
            return Err(err(format!(
                "Shard header mismatch: iv differs for shard {}",
                shard.shard_index
            )));
        }
        if !bytes_equal(&shard.salt, &base.salt) {
            return Err(err(format!(
                "Shard header mismatch: salt differs for shard {}",
                shard.shard_index
            )));
        }
        if !bytes_equal(&shard.qenc_meta_bytes, &base.qenc_meta_bytes) {
            return Err(err(format!(
                "Shard header mismatch: qenc metadata differs for shard {}",
                shard.shard_index
            )));
        }
        if !bytes_equal(&shard.key_commit, &base_key_commit) {
            return Err(err(format!(
                "Shard header mismatch: key commitment differs for shard {}",
                shard.shard_index
            )));
        }
    }

    let missing_indices = (0..n)
        .filter(|index| !shard_by_index.contains_key(&(*index as u16)))
        .map(|index| index as u16)
        .collect::<HashSet<_>>();

    let qenc_meta_json = &base.qenc_meta_json;
    validate_container_policy_metadata(qenc_meta_json, false)?;
    assert_manifest_matches_qenc_metadata(&candidate.manifest_bytes, qenc_meta_json)?;

    let ciphertext_length = ensure_positive_integer(
        base.meta_json.ciphertext_length as usize,
        "ciphertextLength",
        1,
    )? as u64;
    for shard in &group {
        ensure_equal(
            &(shard.meta_json.ciphertext_length as u64),
            &ciphertext_length,
            "ciphertextLength",
        )?;
        ensure_equal(
            &(shard.meta_json.chunk_count as u64),
            &chunk_count,
            "chunkCount",
        )?;
        ensure_equal(
            &(shard.meta_json.chunk_size as u64),
            &chunk_size,
            "chunkSize",
        )?;
    }

    let is_per_chunk_mode = match qenc_meta_json.aead_mode.as_str() {
        "per-chunk-aead" => true,
        "single-container-aead" => false,
        other => return Err(err(format!("Unsupported AEAD mode: {other}"))),
    };
    let expected_ciphertext_length = if is_per_chunk_mode {
        payload_length + (16 * chunk_count)
    } else {
        ciphertext_length
    };
    if is_per_chunk_mode && ciphertext_length != expected_ciphertext_length {
        return Err(err(format!(
            "Ciphertext length mismatch for per-chunk mode (expected {expected_ciphertext_length}, got {ciphertext_length})"
        )));
    }

    let encap_hash = sha3_512_hex(&base.encapsulated_key);
    if normalize_hex_string(&base.meta_json.encap_blob_hash) != normalize_hex_string(&encap_hash) {
        return Err(err("encapBlobHash mismatch"));
    }
    if group.len() < t {
        return Err(err(format!(
            "Need at least {t} matching shards for selected archive cohort, got {}",
            group.len()
        )));
    }

    let share_commitments = manifest
        .shard_binding
        .as_ref()
        .and_then(|binding| binding.share_commitments.clone())
        .or_else(|| base.meta_json.share_commitments.clone());
    let fragment_body_hashes = manifest
        .shard_binding
        .as_ref()
        .and_then(|binding| binding.shard_body_hashes.clone())
        .or_else(|| base.meta_json.fragment_body_hashes.clone());

    let mut warnings = archive_context.authenticity.warnings.clone();
    let mut valid_share_shards = group.clone();
    if let Some(share_commitments) = share_commitments {
        if share_commitments.len() != n {
            return Err(err("Invalid shareCommitments length"));
        }
        valid_share_shards = Vec::new();
        let mut invalid_share_indices = Vec::new();
        for shard in &group {
            let expected = normalize_hex_string(&share_commitments[usize::from(shard.shard_index)]);
            let actual = normalize_hex_string(&sha3_512_hex(&shard.share));
            if actual != expected {
                invalid_share_indices.push(shard.shard_index);
                continue;
            }
            valid_share_shards.push(shard.clone());
        }
        if valid_share_shards.len() < t {
            return Err(err(format!(
                "Not enough valid shards for Shamir reconstruction: need {t}, have {}",
                valid_share_shards.len()
            )));
        }
        if !invalid_share_indices.is_empty() {
            warnings.push(format!(
                "Share commitment failures: {} shard(s) rejected.",
                invalid_share_indices.len()
            ));
        }
    }

    let mut corrupted_shard_indices = HashSet::new();
    if let Some(fragment_body_hashes) = fragment_body_hashes {
        if fragment_body_hashes.len() != n {
            return Err(err("Invalid shardBodyHashes length"));
        }
        for shard in &group {
            let expected =
                normalize_hex_string(&fragment_body_hashes[usize::from(shard.shard_index)]);
            let actual = normalize_hex_string(&sha3_512_hex(&shard.fragments));
            if actual != expected {
                corrupted_shard_indices.insert(shard.shard_index);
            }
        }
    }

    let total_bad = missing_indices.len() + corrupted_shard_indices.len();
    if total_bad > allowed_failures {
        return Err(err(format!(
            "Too many missing/corrupted shards for RS reconstruction: allowed {allowed_failures}, got {total_bad}"
        )));
    }

    let mut sorted_shares = valid_share_shards;
    sorted_shares.sort_by_key(|shard| shard.shard_index);
    let mut selected_shares = sorted_shares
        .iter()
        .take(t)
        .map(|shard| shard.share.clone())
        .collect::<Vec<_>>();
    let priv_key = combine_shares(&selected_shares)?;
    for share in &mut selected_shares {
        share.zeroize();
    }

    let rs_encode_base = if base.meta_json.rs_encode_base > 0 {
        base.meta_json.rs_encode_base as usize
    } else {
        255
    };
    let mut cipher_chunks = Vec::new();
    let mut shard_offsets = vec![0usize; n];

    for i in 0..chunk_count {
        let plain_len = chunk_size.min(payload_length - (i * chunk_size)) as usize;
        let this_len = if is_per_chunk_mode {
            plain_len + 16
        } else {
            ciphertext_length as usize
        };

        let encode_size = (rs_encode_base / n) * n;
        if encode_size == 0 {
            return Err(err("RS parameters too large"));
        }
        let input_size = (encode_size * k) / n;
        let symbol_size = input_size / k;
        let blocks = this_len.div_ceil(input_size);
        let expected_frag_len = blocks * symbol_size;

        let mut encoded = Vec::with_capacity(n);
        for j in 0..n {
            let shard = shard_by_index.get(&(j as u16));
            if shard.is_none() || corrupted_shard_indices.contains(&(j as u16)) {
                encoded.push(vec![0u8; expected_frag_len]);
                continue;
            }
            let shard = *shard.unwrap();
            let stream_offset = shard_offsets[j];
            if stream_offset + 4 > shard.fragments.len() {
                return Err(err("Fragment stream underflow"));
            }
            let frag_len = u32::from_be_bytes([
                shard.fragments[stream_offset],
                shard.fragments[stream_offset + 1],
                shard.fragments[stream_offset + 2],
                shard.fragments[stream_offset + 3],
            ]) as usize;
            let frag_start = stream_offset + 4;
            let frag_end = frag_start + frag_len;
            if frag_end > shard.fragments.len() {
                return Err(err("Fragment length overflow"));
            }
            let mut fragment = shard.fragments[frag_start..frag_end].to_vec();
            if fragment.len() < expected_frag_len {
                fragment.resize(expected_frag_len, 0);
            } else if fragment.len() > expected_frag_len {
                fragment.truncate(expected_frag_len);
            }
            encoded.push(fragment);
            shard_offsets[j] = frag_end;
        }

        let recombined = erasure::recombine(&encoded, this_len, k, m / 2, rs_encode_base)
            .map_err(|error| err(format!("RS recombination failed on chunk {i}: {error}")))?;
        cipher_chunks.push(recombined);
        if !is_per_chunk_mode {
            break;
        }
    }

    for j in 0..n {
        if corrupted_shard_indices.contains(&(j as u16)) {
            continue;
        }
        let Some(shard) = shard_by_index.get(&(j as u16)) else {
            continue;
        };
        if shard_offsets[j] != shard.fragments.len() {
            return Err(err(format!(
                "Fragment stream has trailing or missing data in shard {j}"
            )));
        }
    }

    let ciphertext = if is_per_chunk_mode {
        let total = cipher_chunks.iter().map(Vec::len).sum::<usize>();
        let mut out = Vec::with_capacity(total);
        for chunk in &cipher_chunks {
            out.extend_from_slice(chunk);
        }
        out
    } else {
        cipher_chunks[0].clone()
    };
    if ciphertext.len() != ciphertext_length as usize {
        return Err(err("Reconstructed ciphertext length mismatch"));
    }

    let header = build_qenc_header(
        &base.encapsulated_key,
        &base.iv,
        &base.salt,
        &base.qenc_meta_bytes,
        &base.key_commit,
    )?;
    let mut qenc_bytes = Vec::with_capacity(header.len() + ciphertext.len());
    qenc_bytes.extend_from_slice(&header);
    qenc_bytes.extend_from_slice(&ciphertext);

    let recovered_qenc_hash = normalize_hex_string(&sha3_512_hex(&qenc_bytes));
    let expected_qenc_hash = normalize_hex_string(&manifest.qenc.qenc_hash);
    if recovered_qenc_hash != expected_qenc_hash {
        return Err(err(
            "Reconstructed .qenc hash does not match archive manifest",
        ));
    }

    let recovered_priv_hash = normalize_hex_string(&sha3_512_hex(&priv_key));
    let private_key_hash = normalize_hex_string(&base.meta_json.private_key_hash);
    let qkey_ok = private_key_hash.is_empty() || private_key_hash == recovered_priv_hash;
    if !qkey_ok {
        warnings.push("Recovered secret key hash does not match shard metadata.".to_string());
    }

    let authenticity = build_authenticity_report(&archive_context.authenticity);
    Ok(RestoredQcont {
        qenc_bytes,
        priv_key,
        container_id,
        container_hash: expected_qenc_hash,
        private_key_hash: if private_key_hash.is_empty() {
            None
        } else {
            Some(private_key_hash)
        },
        recovered_qenc_hash,
        recovered_priv_hash,
        rejected_shard_indices,
        qenc_ok: true,
        qkey_ok,
        manifest: manifest.clone(),
        manifest_bytes: candidate.manifest_bytes.clone(),
        manifest_digest_hex,
        bundle: bundle.clone(),
        bundle_bytes: candidate.bundle_bytes.clone(),
        bundle_digest_hex,
        manifest_source: archive_context.source.clone(),
        authenticity,
        warnings,
    })
}

fn build_authenticity_report(source: &CandidateAuthenticity) -> AuthenticityReport {
    AuthenticityReport {
        policy: source.policy.clone(),
        verification: source.verification.clone(),
        warnings: source.warnings.clone(),
        status: AuthenticityStatus {
            integrity_verified: true,
            signature_verified: source.verification.status.signature_verified,
            strong_pq_signature_verified: source.verification.status.strong_pq_signature_verified,
            signer_pinned: source.verification.status.signer_pinned,
            signer_identity_pinned: source.verification.status.signer_identity_pinned,
            bundle_pinned: source.verification.status.bundle_pinned,
            user_pinned: source.verification.status.user_pinned,
            user_pin_provided: source.verification.status.user_pin_provided,
            policy_satisfied: source.policy.satisfied,
            archive_policy_satisfied: source.policy.satisfied,
        },
        timestamp_evidence: source.timestamp_evidence.clone(),
    }
}

fn evaluate_archive_policy(
    auth_policy: &AuthPolicy,
    verification: &crate::auth::SignatureVerificationReport,
) -> Result<ArchivePolicyEvaluation> {
    let min_valid_signatures = auth_policy.min_valid_signatures.max(1);
    Ok(match auth_policy.level {
        AuthPolicyLevel::IntegrityOnly => ArchivePolicyEvaluation {
            level: auth_policy.level,
            min_valid_signatures,
            satisfied: true,
            reason: "integrity-only policy does not require signatures".to_string(),
        },
        AuthPolicyLevel::AnySignature => {
            let satisfied = verification.counts.pinned_valid_total >= min_valid_signatures;
            ArchivePolicyEvaluation {
                level: auth_policy.level,
                min_valid_signatures,
                satisfied,
                reason: if satisfied {
                    "required trusted signature count satisfied".to_string()
                } else {
                    "no valid pinned signature satisfies archive policy".to_string()
                },
            }
        }
        AuthPolicyLevel::StrongPqSignature => {
            let satisfied = verification.counts.pinned_valid_total >= min_valid_signatures
                && verification.counts.pinned_valid_strong_pq >= 1;
            ArchivePolicyEvaluation {
                level: auth_policy.level,
                min_valid_signatures,
                satisfied,
                reason: if satisfied {
                    "required trusted strong PQ signature present".to_string()
                } else {
                    "no valid pinned strong PQ signature satisfies archive policy".to_string()
                },
            }
        }
    })
}

fn collect_candidate_cohorts<'a>(shards: &'a [QcontShard]) -> Result<Vec<CandidateCohort<'a>>> {
    let mut by_digest = BTreeMap::<String, CandidateCohort<'a>>::new();
    for shard in shards {
        let key = format!("{}:{}", shard.manifest_digest_hex, shard.bundle_digest_hex);
        if let Some(existing) = by_digest.get(&key) {
            if !bytes_equal(existing.manifest_bytes, &shard.manifest_bytes) {
                return Err(err(format!("Manifest bytes mismatch inside cohort {key}")));
            }
            if !bytes_equal(existing.bundle_bytes, &shard.bundle_bytes) {
                return Err(err(format!("Bundle bytes mismatch inside cohort {key}")));
            }
            continue;
        }
        by_digest.insert(
            key,
            CandidateCohort {
                manifest_digest_hex: shard.manifest_digest_hex.clone(),
                bundle_digest_hex: shard.bundle_digest_hex.clone(),
                manifest_bytes: &shard.manifest_bytes,
                bundle_bytes: &shard.bundle_bytes,
            },
        );
    }
    Ok(by_digest.into_values().collect())
}

fn enrich_candidate(
    candidate: &CandidateCohort<'_>,
    bundle_bytes_override: Option<&[u8]>,
) -> Result<EnrichedCandidate> {
    let parsed_manifest = parse_archive_manifest_bytes(candidate.manifest_bytes)?;
    if parsed_manifest.digest_hex != candidate.manifest_digest_hex {
        return Err(err("Embedded manifest digest mismatch"));
    }
    let selected_bundle_bytes = bundle_bytes_override.unwrap_or(candidate.bundle_bytes);
    let parsed_bundle = parse_manifest_bundle_bytes(selected_bundle_bytes, true)?;
    if bundle_bytes_override.is_none() && parsed_bundle.digest_hex != candidate.bundle_digest_hex {
        return Err(err("Embedded bundle digest mismatch"));
    }
    if !bytes_equal(&parsed_bundle.manifest_bytes, &parsed_manifest.bytes) {
        return Err(err(
            "Embedded bundle manifest does not match embedded manifest bytes",
        ));
    }
    if parsed_bundle.manifest_digest_hex != parsed_manifest.digest_hex {
        return Err(err(
            "Embedded bundle manifestDigest does not match embedded manifest digest",
        ));
    }
    let _ = assert_auth_policy_commitment(
        &parsed_manifest.manifest.auth_policy_commitment,
        &parsed_bundle.bundle.auth_policy,
    )?;
    assert_manifest_bundle_timestamps(&parsed_bundle.bundle)?;
    Ok(EnrichedCandidate {
        manifest_digest_hex: candidate.manifest_digest_hex.clone(),
        bundle_digest_hex: parsed_bundle.digest_hex.clone(),
        embedded_bundle_digest_hex: candidate.bundle_digest_hex.clone(),
        manifest: parsed_manifest.manifest,
        manifest_bytes: parsed_manifest.bytes,
        bundle: parsed_bundle.bundle,
        bundle_bytes: parsed_bundle.bytes,
    })
}

fn evaluate_candidate_authenticity(
    candidate: &EnrichedCandidate,
    verification_options: &VerificationInputs,
) -> Result<CandidateAuthenticity> {
    let verification = verify_manifest_signatures(
        &candidate.manifest_bytes,
        &candidate.bundle.attachments.signatures,
        &candidate.bundle.attachments.public_keys,
        &verification_options.signatures,
        verification_options
            .pinned_pq_public_key_file_bytes
            .as_deref(),
        verification_options.expected_ed25519_signer.as_deref(),
    )?;
    let policy = evaluate_archive_policy(&candidate.bundle.auth_policy, &verification)?;
    let timestamp_evidence = inspect_timestamp_evidence(
        &candidate.bundle,
        &verification_options.timestamps,
        &verification.signature_artifacts,
    )?;
    let mut warnings = Vec::new();
    if candidate.bundle.auth_policy.level == AuthPolicyLevel::IntegrityOnly {
        warnings.push(
            "Archive policy is integrity-only; provenance is not bound to a verified signer."
                .to_string(),
        );
    }
    let invalid_signature_count = verification.results.iter().filter(|item| !item.ok).count();
    if invalid_signature_count > 0 {
        warnings.push(format!(
            "{invalid_signature_count} attached signature(s) did not verify and were ignored for policy evaluation."
        ));
    }
    if verification.counts.valid_total > verification.counts.pinned_valid_total {
        warnings.push(
            "Verified signatures without a trusted signer binding were ignored for archive policy evaluation."
                .to_string(),
        );
    }
    Ok(CandidateAuthenticity {
        verification,
        policy,
        timestamp_evidence,
        warnings,
    })
}

fn resolve_archive_context(
    shards: &[QcontShard],
    options: &RestoreQcontOptions,
) -> Result<ArchiveContext> {
    let raw_candidates = collect_candidate_cohorts(shards)?;
    if raw_candidates.is_empty() {
        return Err(err("No valid shard cohorts found"));
    }

    if let Some(bundle_bytes) = options.bundle_bytes.as_deref() {
        let parsed_bundle = parse_manifest_bundle_bytes(bundle_bytes, true)?;
        let matching = raw_candidates
            .iter()
            .filter(|candidate| {
                candidate.manifest_digest_hex == parsed_bundle.manifest_digest_hex
                    && bytes_equal(candidate.manifest_bytes, &parsed_bundle.manifest_bytes)
            })
            .collect::<Vec<_>>();
        if matching.is_empty() {
            return Err(err(
                "Provided manifest bundle does not match any shard manifest",
            ));
        }
        let explicit_candidate = enrich_candidate(matching[0], Some(&parsed_bundle.bytes))?;
        let authenticity =
            evaluate_candidate_authenticity(&explicit_candidate, &options.verification)?;
        if !authenticity.policy.satisfied {
            return Err(err(authenticity.policy.reason.clone()));
        }
        return Ok(ArchiveContext {
            candidate: explicit_candidate,
            authenticity,
            source: "uploaded-bundle".to_string(),
            use_manifest_wide_shard_selection: true,
        });
    }

    let candidates = raw_candidates
        .iter()
        .map(|candidate| enrich_candidate(candidate, None))
        .collect::<Result<Vec<_>>>()?;

    if let Some(manifest_bytes) = options.manifest_bytes.as_deref() {
        let parsed_manifest = parse_archive_manifest_bytes(manifest_bytes)?;
        let matching = candidates
            .iter()
            .filter(|candidate| candidate.manifest_digest_hex == parsed_manifest.digest_hex)
            .collect::<Vec<_>>();
        if matching.is_empty() {
            return Err(err(
                "Provided canonical manifest does not match any shard cohort",
            ));
        }
        if matching.len() > 1 {
            return Err(err(
                "Canonical manifest matches multiple bundle cohorts. Provide the bundle file or pinned signatures to disambiguate.",
            ));
        }
        let authenticity = evaluate_candidate_authenticity(matching[0], &options.verification)?;
        if !authenticity.policy.satisfied {
            return Err(err(authenticity.policy.reason.clone()));
        }
        return Ok(ArchiveContext {
            candidate: matching[0].clone(),
            authenticity,
            source: "uploaded-manifest".to_string(),
            use_manifest_wide_shard_selection: false,
        });
    }

    let mut evaluated = Vec::new();
    for candidate in &candidates {
        match evaluate_candidate_authenticity(candidate, &options.verification) {
            Ok(authenticity) => evaluated.push((candidate.clone(), authenticity, None::<String>)),
            Err(error) => {
                let empty_verification = crate::auth::SignatureVerificationReport {
                    provided: false,
                    results: Vec::new(),
                    warnings: Vec::new(),
                    counts: crate::auth::SignatureVerificationCounts::default(),
                    signature_artifacts: Vec::new(),
                    status: crate::auth::SignatureVerificationStatus {
                        signature_verified: false,
                        strong_pq_signature_verified: false,
                        signer_pinned: false,
                        signer_identity_pinned: false,
                        bundle_pinned: false,
                        user_pinned: false,
                        user_pin_provided: options
                            .verification
                            .pinned_pq_public_key_file_bytes
                            .is_some()
                            || options
                                .verification
                                .expected_ed25519_signer
                                .as_ref()
                                .map(|value| !value.trim().is_empty())
                                .unwrap_or(false),
                    },
                };
                evaluated.push((
                    candidate.clone(),
                    CandidateAuthenticity {
                        verification: empty_verification,
                        policy: ArchivePolicyEvaluation {
                            level: candidate.bundle.auth_policy.level,
                            min_valid_signatures: candidate.bundle.auth_policy.min_valid_signatures,
                            satisfied: false,
                            reason: error.to_string(),
                        },
                        timestamp_evidence: Vec::new(),
                        warnings: Vec::new(),
                    },
                    Some(error.to_string()),
                ));
            }
        }
    }

    let satisfying = evaluated
        .iter()
        .filter(|(_, authenticity, _)| authenticity.policy.satisfied)
        .collect::<Vec<_>>();
    if satisfying.len() == 1 {
        let (candidate, authenticity, _) = satisfying[0];
        return Ok(ArchiveContext {
            candidate: (*candidate).clone(),
            authenticity: (*authenticity).clone(),
            source: "embedded".to_string(),
            use_manifest_wide_shard_selection: false,
        });
    }
    if satisfying.len() > 1 {
        return Err(err(
            "Multiple shard cohorts satisfy archive policy. Provide the manifest bundle, canonical manifest, or signer pins to disambiguate.",
        ));
    }
    if candidates.len() == 1 {
        return Err(err(evaluated[0].1.policy.reason.clone()));
    }
    Err(err("No shard cohort satisfies archive policy."))
}

fn assert_manifest_matches_qenc_metadata(
    manifest_bytes: &[u8],
    qenc_meta_json: &crate::qenc::QencMetadata,
) -> Result<()> {
    let parsed_manifest = parse_archive_manifest_bytes(manifest_bytes)?;
    let manifest = &parsed_manifest.manifest;

    ensure_equal(
        &manifest.qenc.hash_alg,
        &"SHA3-512".to_string(),
        "qenc.hashAlg",
    )?;
    ensure_equal(
        &manifest.qenc.primary_anchor,
        &"qencHash".to_string(),
        "qenc.primaryAnchor",
    )?;
    ensure_equal(
        &manifest.qenc.container_id_role,
        &"secondary-header-id".to_string(),
        "qenc.containerIdRole",
    )?;
    ensure_equal(
        &manifest.qenc.container_id_alg,
        &"SHA3-512(qenc-header-bytes)".to_string(),
        "qenc.containerIdAlg",
    )?;

    ensure_equal(&qenc_meta_json.fmt, &manifest.qenc.format, "qenc.format")?;
    ensure_equal(
        &qenc_meta_json.aead_mode,
        &manifest.qenc.aead_mode,
        "qenc.aeadMode",
    )?;
    ensure_equal(
        &qenc_meta_json.iv_strategy,
        &manifest.qenc.iv_strategy,
        "qenc.ivStrategy",
    )?;
    ensure_equal(
        &(qenc_meta_json.chunk_size.unwrap_or_default()),
        &manifest.qenc.chunk_size,
        "qenc.chunkSize",
    )?;
    ensure_equal(
        &(qenc_meta_json.chunk_count.unwrap_or_default()),
        &manifest.qenc.chunk_count,
        "qenc.chunkCount",
    )?;
    ensure_equal(
        &(qenc_meta_json.payload_length.unwrap_or_default()),
        &manifest.qenc.payload_length,
        "qenc.payloadLength",
    )?;
    ensure_equal(
        qenc_meta_json
            .crypto_profile_id
            .as_ref()
            .unwrap_or(&String::new()),
        &manifest.crypto_profile_id,
        "cryptoProfileId",
    )?;
    ensure_equal(
        qenc_meta_json
            .kdf_tree_id
            .as_ref()
            .unwrap_or(&String::new()),
        &manifest.kdf_tree_id,
        "kdfTreeId",
    )?;
    ensure_equal(
        &qenc_meta_json.nonce_policy_id,
        &manifest.nonce_policy_id,
        "noncePolicyId",
    )?;
    ensure_equal(
        &qenc_meta_json.nonce_mode,
        &manifest.nonce_mode,
        "nonceMode",
    )?;
    ensure_equal(
        &qenc_meta_json.counter_bits,
        &manifest.counter_bits,
        "counterBits",
    )?;
    ensure_equal(
        &qenc_meta_json.max_chunk_count,
        &manifest.max_chunk_count,
        "maxChunkCount",
    )?;
    ensure_equal(
        qenc_meta_json
            .aad_policy_id
            .as_ref()
            .unwrap_or(&String::new()),
        &manifest.aad_policy_id,
        "aadPolicyId",
    )?;
    Ok(())
}

fn normalize_hex_string(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn ensure_positive_integer(value: usize, field: &str, min: usize) -> Result<usize> {
    if value < min {
        return Err(err(format!("Invalid {field}")));
    }
    Ok(value)
}

fn ensure_equal<T: PartialEq + std::fmt::Display>(
    actual: &T,
    expected: &T,
    field: &str,
) -> Result<()> {
    if actual != expected {
        return Err(err(format!(
            "{field} mismatch (expected {expected}, got {actual})"
        )));
    }
    Ok(())
}
