use std::collections::{BTreeMap, HashMap, HashSet};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use serde_json::Value;
use zeroize::Zeroize;

use crate::auth::{
    resolve_open_timestamp_target, verify_qsig_against_bytes, verify_stellar_sig_against_bytes,
    ArchivePolicyEvaluation, AuthPolicy, AuthPolicyLevel, AuthenticityReport, AuthenticityStatus,
    NamedBinaryArtifact, SignatureArtifact, SignatureCheckResult, SignatureVerificationCounts,
    SignatureVerificationReport, SignatureVerificationStatus, TimestampEvidence,
    VerificationInputs,
};
use crate::auth::successor_policy::finalize_successor_archive_approval_verification;
use crate::erasure;
use crate::error::{coded, err, QvCode, Result};
use crate::hash::{sha256_hex, sha3_512_hex};
use crate::kdf::{derive_key_with_kmac, verify_key_commitment};
use crate::lifecycle::{
    canonicalize_archive_state_descriptor, canonicalize_cohort_binding,
    parse_lifecycle_bundle_bytes, CanonicalLifecycleBundle,
};
use crate::mlkem::decapsulate;
use crate::qcont::shard_v7::Qvqcont7Shard;
use crate::qenc::{build_qenc_header, parse_qenc_header, parse_qenc_metadata_bytes};
use crate::sss::combine_shares;

const RS_MAX_CODEWORD: usize = 255;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RestoreQvqcont7Selection {
    pub selected_archive_id: Option<String>,
    pub selected_state_id: Option<String>,
    pub selected_cohort_id: Option<String>,
    pub archive_state_bytes: Option<Vec<u8>>,
    pub lifecycle_bundle_bytes: Option<Vec<u8>>,
    pub selected_lifecycle_bundle_digest_hex: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreQvqcont7Options {
    pub selection: RestoreQvqcont7Selection,
    pub verification: VerificationInputs,
    pub enforce_policy: bool,
}

impl Default for RestoreQvqcont7Options {
    fn default() -> Self {
        Self {
            selection: RestoreQvqcont7Selection::default(),
            verification: VerificationInputs::default(),
            enforce_policy: true,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct RestoredQvqcont7 {
    pub qenc_bytes: Vec<u8>,
    pub priv_key: Vec<u8>,
    pub archive_id: String,
    pub state_id: String,
    pub cohort_id: String,
    pub container_id: String,
    pub container_hash: String,
    pub private_key_hash: Option<String>,
    pub recovered_qenc_hash: String,
    pub recovered_priv_hash: String,
    pub rejected_shard_indices: Vec<u16>,
    pub qenc_ok: bool,
    pub qkey_ok: bool,
    pub archive_state_bytes: Vec<u8>,
    pub archive_state_digest_hex: String,
    pub cohort_binding_bytes: Vec<u8>,
    pub cohort_binding_digest_hex: String,
    pub lifecycle_bundle_bytes: Vec<u8>,
    pub lifecycle_bundle_digest_hex: String,
    pub authenticity: AuthenticityReport,
    pub warnings: Vec<String>,
}

impl std::fmt::Debug for RestoredQvqcont7 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RestoredQvqcont7")
            .field("archive_id", &self.archive_id)
            .field("state_id", &self.state_id)
            .field("cohort_id", &self.cohort_id)
            .field("container_id", &self.container_id)
            .field("qenc_ok", &self.qenc_ok)
            .field("qkey_ok", &self.qkey_ok)
            .field("rejected_shard_indices", &self.rejected_shard_indices)
            .finish()
    }
}

struct CandidateCohort<'a> {
    archive_id: String,
    state_id: String,
    cohort_id: String,
    archive_state_bytes: &'a [u8],
    archive_state_digest_hex: String,
    cohort_binding_bytes: &'a [u8],
    cohort_binding_digest_hex: String,
    lifecycle_bundles: BTreeMap<String, (&'a [u8], &'a CanonicalLifecycleBundle)>,
    shards: Vec<&'a Qvqcont7Shard>,
}

struct SelectedLifecycleBundle {
    bytes: Vec<u8>,
    digest_hex: String,
    bundle: CanonicalLifecycleBundle,
}

struct ValidShard<'a> {
    shard: &'a Qvqcont7Shard,
    chunk_fragments: Vec<Vec<u8>>,
}

struct Reconstruction {
    qenc_bytes: Vec<u8>,
    priv_key: Vec<u8>,
    container_id: String,
    container_hash: String,
    private_key_hash: Option<String>,
    recovered_qenc_hash: String,
    recovered_priv_hash: String,
    rejected_shard_indices: Vec<u16>,
    qkey_ok: bool,
    warnings: Vec<String>,
}

pub fn restore_qvqcont7_from_shards(
    shards: &[Qvqcont7Shard],
    options: &RestoreQvqcont7Options,
) -> Result<RestoredQvqcont7> {
    if shards.is_empty() {
        return Err(coded(
            QvCode::NotEnoughShards,
            "No QVqcont-7 shards were provided",
        ));
    }

    let candidates = collect_candidate_cohorts(shards)?;
    let (candidate, selected_bundle) = resolve_successor_archive_context(&candidates, options)?;
    let reconstruction = reconstruct_lifecycle_cohort_material(candidate)?;
    let authenticity = evaluate_successor_authenticity(
        &selected_bundle.bundle,
        &selected_bundle.bytes,
        candidate.archive_state_bytes,
        &options.verification,
    )?;
    if options.enforce_policy && !authenticity.policy.satisfied {
        return Err(coded(
            QvCode::PolicyNotSatisfied,
            authenticity.policy.reason.clone(),
        ));
    }

    let mut warnings = reconstruction.warnings;
    warnings.extend(authenticity.warnings.iter().cloned());

    Ok(RestoredQvqcont7 {
        qenc_bytes: reconstruction.qenc_bytes,
        priv_key: reconstruction.priv_key,
        archive_id: candidate.archive_id.clone(),
        state_id: candidate.state_id.clone(),
        cohort_id: candidate.cohort_id.clone(),
        container_id: reconstruction.container_id,
        container_hash: reconstruction.container_hash,
        private_key_hash: reconstruction.private_key_hash,
        recovered_qenc_hash: reconstruction.recovered_qenc_hash,
        recovered_priv_hash: reconstruction.recovered_priv_hash,
        rejected_shard_indices: reconstruction.rejected_shard_indices,
        qenc_ok: true,
        qkey_ok: reconstruction.qkey_ok,
        archive_state_bytes: candidate.archive_state_bytes.to_vec(),
        archive_state_digest_hex: candidate.archive_state_digest_hex.clone(),
        cohort_binding_bytes: candidate.cohort_binding_bytes.to_vec(),
        cohort_binding_digest_hex: candidate.cohort_binding_digest_hex.clone(),
        lifecycle_bundle_bytes: selected_bundle.bytes,
        lifecycle_bundle_digest_hex: selected_bundle.digest_hex,
        authenticity,
        warnings,
    })
}

fn collect_candidate_cohorts<'a>(shards: &'a [Qvqcont7Shard]) -> Result<Vec<CandidateCohort<'a>>> {
    let mut by_key = BTreeMap::<String, CandidateCohort<'a>>::new();
    for shard in shards {
        let archive_id = string_field(
            &shard.archive_state.archive_state.value,
            "archiveId",
            "archiveState.archiveId",
        )?;
        let key = format!(
            "{}:{}:{}:{}:{}",
            archive_id,
            shard.state_id,
            shard.cohort_id,
            sha256_hex(&shard.archive_state_bytes),
            sha256_hex(&shard.cohort_binding_bytes)
        );
        let entry = by_key.entry(key).or_insert_with(|| CandidateCohort {
            archive_id: archive_id.clone(),
            state_id: shard.state_id.clone(),
            cohort_id: shard.cohort_id.clone(),
            archive_state_bytes: &shard.archive_state_bytes,
            archive_state_digest_hex: shard.archive_state_digest_hex.clone(),
            cohort_binding_bytes: &shard.cohort_binding_bytes,
            cohort_binding_digest_hex: shard.cohort_binding_digest_hex.clone(),
            lifecycle_bundles: BTreeMap::new(),
            shards: Vec::new(),
        });
        if entry.archive_id != archive_id
            || entry.state_id != shard.state_id
            || entry.cohort_id != shard.cohort_id
            || entry.archive_state_bytes != shard.archive_state_bytes
            || entry.cohort_binding_bytes != shard.cohort_binding_bytes
        {
            return Err(coded(
                QvCode::AmbiguousInputs,
                "Shard cohort grouping found conflicting archive/cohort bytes",
            ));
        }
        entry.lifecycle_bundles.insert(
            shard.lifecycle_bundle_digest_hex.clone(),
            (&shard.lifecycle_bundle_bytes, &shard.lifecycle_bundle),
        );
        entry.shards.push(shard);
    }
    Ok(by_key.into_values().collect())
}

fn resolve_successor_archive_context<'a>(
    candidates: &'a [CandidateCohort<'a>],
    options: &RestoreQvqcont7Options,
) -> Result<(&'a CandidateCohort<'a>, SelectedLifecycleBundle)> {
    let selection = &options.selection;
    let mut filtered = candidates
        .iter()
        .filter(|candidate| {
            selection
                .selected_archive_id
                .as_ref()
                .map(|value| value == &candidate.archive_id)
                .unwrap_or(true)
        })
        .filter(|candidate| {
            selection
                .selected_state_id
                .as_ref()
                .map(|value| value == &candidate.state_id)
                .unwrap_or(true)
        })
        .filter(|candidate| {
            selection
                .selected_cohort_id
                .as_ref()
                .map(|value| value == &candidate.cohort_id)
                .unwrap_or(true)
        })
        .filter(|candidate| {
            selection
                .archive_state_bytes
                .as_ref()
                .map(|bytes| bytes.as_slice() == candidate.archive_state_bytes)
                .unwrap_or(true)
        })
        .collect::<Vec<_>>();

    if let Some(bundle_bytes) = selection.lifecycle_bundle_bytes.as_deref() {
        let bundle = parse_lifecycle_bundle_bytes(bundle_bytes).map_err(|error| {
            coded(
                QvCode::InvalidSelection,
                format!("Selected lifecycle bundle is invalid: {error}"),
            )
        })?;
        let bundle_archive =
            canonicalize_archive_state_descriptor(&bundle.lifecycle_bundle.value["archiveState"])?;
        let bundle_cohort =
            canonicalize_cohort_binding(&bundle.lifecycle_bundle.value["currentCohortBinding"])?;
        filtered.retain(|candidate| {
            bundle_archive.bytes == candidate.archive_state_bytes
                && bundle_cohort.bytes == candidate.cohort_binding_bytes
        });
        if filtered.len() != 1 {
            return Err(coded(
                QvCode::InvalidSelection,
                "Selected lifecycle bundle does not identify exactly one shard cohort",
            ));
        }
        let digest_hex = sha3_512_hex(bundle_bytes);
        return Ok((
            filtered[0],
            SelectedLifecycleBundle {
                bytes: bundle_bytes.to_vec(),
                digest_hex,
                bundle,
            },
        ));
    }

    if filtered.is_empty() {
        return Err(coded(
            QvCode::InvalidSelection,
            "No shard cohort matches the selected archive/state/cohort filters",
        ));
    }
    if filtered.len() > 1 {
        if selection.selected_cohort_id.is_none() {
            let same_state = filtered
                .iter()
                .map(|candidate| (&candidate.archive_id, &candidate.state_id))
                .collect::<HashSet<_>>()
                .len()
                == 1;
            return Err(coded(
                QvCode::AmbiguousInputs,
                if same_state {
                    "Multiple cohorts exist for the selected archive-state; select cohortId explicitly"
                } else {
                    "Multiple archive contexts match; select archiveId/stateId/cohortId explicitly"
                },
            ));
        }
        return Err(coded(
            QvCode::AmbiguousInputs,
            "Selection filters still match multiple archive contexts",
        ));
    }

    let candidate = filtered[0];
    let digest = if let Some(selected_digest) = &selection.selected_lifecycle_bundle_digest_hex {
        if !candidate.lifecycle_bundles.contains_key(selected_digest) {
            return Err(coded(
                QvCode::InvalidSelection,
                "Selected lifecycle bundle digest is not embedded in the selected cohort",
            ));
        }
        selected_digest.clone()
    } else {
        if candidate.lifecycle_bundles.len() > 1 {
            return Err(coded(
                QvCode::AmbiguousInputs,
                "Selected cohort embeds multiple lifecycle bundles; select lifecycle bundle digest explicitly",
            ));
        }
        candidate
            .lifecycle_bundles
            .keys()
            .next()
            .cloned()
            .ok_or_else(|| {
                coded(
                    QvCode::InvalidFormat,
                    "Selected cohort has no lifecycle bundle",
                )
            })?
    };
    let (bytes, bundle) = candidate.lifecycle_bundles.get(&digest).ok_or_else(|| {
        coded(
            QvCode::InvalidSelection,
            "Missing selected lifecycle bundle",
        )
    })?;
    Ok((
        candidate,
        SelectedLifecycleBundle {
            bytes: (*bytes).to_vec(),
            digest_hex: digest,
            bundle: (*bundle).clone(),
        },
    ))
}

fn reconstruct_lifecycle_cohort_material<'a>(
    candidate: &'a CandidateCohort<'a>,
) -> Result<Reconstruction> {
    let base = *candidate.shards.first().ok_or_else(|| {
        coded(
            QvCode::NotEnoughShards,
            "Selected cohort contains no shards",
        )
    })?;
    let cohort_value = &base.cohort_binding.cohort_binding.value;
    let sharding = object_field(cohort_value, "sharding", "cohortBinding.sharding")?;
    let shamir = object_field(sharding, "shamir", "cohortBinding.sharding.shamir")?;
    let rs = object_field(
        sharding,
        "reedSolomon",
        "cohortBinding.sharding.reedSolomon",
    )?;
    let n = integer_field(rs, "n", "cohortBinding.sharding.reedSolomon.n")? as usize;
    let k = integer_field(rs, "k", "cohortBinding.sharding.reedSolomon.k")? as usize;
    let m = integer_field(rs, "parity", "cohortBinding.sharding.reedSolomon.parity")? as usize;
    let t = integer_field(
        shamir,
        "threshold",
        "cohortBinding.sharding.shamir.threshold",
    )? as usize;
    let share_count = integer_field(
        shamir,
        "shareCount",
        "cohortBinding.sharding.shamir.shareCount",
    )? as usize;
    if n != share_count || m != n.saturating_sub(k) || (m % 2) != 0 || t != k + (m / 2) {
        return Err(coded(
            QvCode::InvalidFormat,
            "Invalid lifecycle cohort sharding tuple",
        ));
    }
    if candidate.shards.len() < t {
        return Err(coded(
            QvCode::NotEnoughShards,
            format!("Not enough shards for threshold reconstruction: need {t}"),
        ));
    }
    let allowed_failures = m / 2;
    let qenc_meta = parse_qenc_metadata_bytes(&base.qenc_meta_bytes)?;
    validate_qenc_metadata_against_archive_state(
        &qenc_meta,
        &base.archive_state.archive_state.value,
    )?;

    let chunk_count =
        integer_field(&base.meta_json, "chunkCount", "shard.metadata.chunkCount")? as usize;
    let chunk_size =
        integer_field(&base.meta_json, "chunkSize", "shard.metadata.chunkSize")? as u64;
    let payload_length = integer_field(
        &base.meta_json,
        "payloadLength",
        "shard.metadata.payloadLength",
    )? as u64;
    let ciphertext_length = integer_field(
        &base.meta_json,
        "ciphertextLength",
        "shard.metadata.ciphertextLength",
    )? as usize;
    let rs_encode_base = integer_field(
        &base.meta_json,
        "rsEncodeBase",
        "shard.metadata.rsEncodeBase",
    )
    .unwrap_or(RS_MAX_CODEWORD as u64) as usize;
    if rs_encode_base == 0 {
        return Err(coded(QvCode::InvalidFormat, "Invalid rsEncodeBase"));
    }

    let expected_share_commitments = string_array_field(
        cohort_value,
        "shareCommitments",
        "cohortBinding.shareCommitments",
    )?;
    let expected_body_hashes = string_array_field(
        cohort_value,
        "shardBodyHashes",
        "cohortBinding.shardBodyHashes",
    )?;
    if expected_share_commitments.len() != n || expected_body_hashes.len() != n {
        return Err(coded(
            QvCode::InvalidFormat,
            "Cohort binding commitment list length mismatch",
        ));
    }

    let mut valid_by_index = Vec::<Option<ValidShard<'a>>>::with_capacity(n);
    valid_by_index.resize_with(n, || None);
    let mut seen_indices = HashSet::new();
    let mut rejected = Vec::<u16>::new();

    for shard in &candidate.shards {
        if usize::from(shard.shard_index) >= n || !seen_indices.insert(shard.shard_index) {
            return Err(coded(
                QvCode::InvalidFormat,
                "Duplicate or out-of-range shard index",
            ));
        }
        match validate_shard_against_base(
            candidate,
            base,
            shard,
            &expected_share_commitments,
            &expected_body_hashes,
            chunk_count,
        ) {
            Ok(chunk_fragments) => {
                valid_by_index[usize::from(shard.shard_index)] = Some(ValidShard {
                    shard,
                    chunk_fragments,
                });
            }
            Err(_) => rejected.push(shard.shard_index),
        }
    }
    rejected.sort_unstable();

    let valid_count = valid_by_index
        .iter()
        .filter(|entry| entry.is_some())
        .count();
    if valid_count < t {
        return Err(coded(
            QvCode::NotEnoughShards,
            format!(
                "Not enough valid shards for threshold reconstruction: need {t}, got {valid_count}"
            ),
        ));
    }
    let total_bad = n.saturating_sub(valid_count);
    if total_bad > allowed_failures {
        return Err(coded(
            QvCode::IntegrityMismatch,
            format!(
                "Too many missing/corrupted shards for RS reconstruction: allowed {allowed_failures}, got {total_bad}"
            ),
        ));
    }

    let mut shares = valid_by_index
        .iter()
        .flatten()
        .take(t)
        .map(|entry| entry.shard.share.clone())
        .collect::<Vec<_>>();
    let mut priv_key = combine_shares(&shares).map_err(|error| {
        coded(
            QvCode::RestoreFailed,
            format!("Shamir private key reconstruction failed: {error}"),
        )
    })?;
    for share in &mut shares {
        share.zeroize();
    }

    let is_per_chunk = qenc_meta.aead_mode == "per-chunk-aead";
    let mut cipher_chunks = Vec::new();
    for chunk_index in 0..chunk_count {
        let this_len = encrypted_chunk_len(
            is_per_chunk,
            chunk_index,
            chunk_size,
            payload_length,
            ciphertext_length,
        )?;
        let expected_frag_len = expected_fragment_len(this_len, n, k, rs_encode_base)?;
        let mut encoded = Vec::with_capacity(n);
        for entry in &valid_by_index {
            let fragment = entry
                .as_ref()
                .and_then(|entry| entry.chunk_fragments.get(chunk_index))
                .cloned()
                .unwrap_or_else(|| vec![0u8; expected_frag_len]);
            if fragment.len() != expected_frag_len {
                return Err(coded(
                    QvCode::IntegrityMismatch,
                    "Shard fragment length does not match RS layout",
                ));
            }
            encoded.push(fragment);
        }
        let recombined =
            erasure::recombine(&encoded, this_len, k, allowed_failures, rs_encode_base).map_err(
                |error| {
                    coded(
                        QvCode::RestoreFailed,
                        format!("RS recombination failed on chunk {chunk_index}: {error}"),
                    )
                },
            )?;
        cipher_chunks.push(recombined);
        if !is_per_chunk {
            break;
        }
    }

    let mut ciphertext = Vec::with_capacity(ciphertext_length);
    for chunk in cipher_chunks {
        ciphertext.extend_from_slice(&chunk);
    }
    if ciphertext.len() != ciphertext_length {
        return Err(coded(
            QvCode::IntegrityMismatch,
            "Reconstructed ciphertext length mismatch",
        ));
    }

    let mut shared_secret = decapsulate(&base.encapsulated_key, &priv_key).map_err(|error| {
        coded(
            QvCode::RestoreFailed,
            format!("Recovered private key cannot decapsulate this container: {error}"),
        )
    })?;
    let derived = derive_key_with_kmac(
        &shared_secret,
        &base.kdf_salt,
        &base.qenc_meta_bytes,
        &qenc_meta.domain_strings,
    )?;
    shared_secret.zeroize();
    if !verify_key_commitment(&derived.kenc, &base.key_commitment) {
        priv_key.zeroize();
        return Err(coded(
            QvCode::IntegrityMismatch,
            "Recovered private key does not satisfy the shard key commitment",
        ));
    }

    let header = build_qenc_header(
        &base.encapsulated_key,
        &base.container_nonce,
        &base.kdf_salt,
        &base.qenc_meta_bytes,
        &base.key_commitment,
    )?;
    let mut qenc_bytes = Vec::with_capacity(header.len() + ciphertext.len());
    qenc_bytes.extend_from_slice(&header);
    qenc_bytes.extend_from_slice(&ciphertext);
    let parsed_recovered = parse_qenc_header(&qenc_bytes)?;

    let recovered_qenc_hash = sha3_512_hex(&qenc_bytes);
    let archive_qenc = object_field(
        &base.archive_state.archive_state.value,
        "qenc",
        "archiveState.qenc",
    )?;
    let expected_qenc_hash = string_field(archive_qenc, "qencHash", "archiveState.qenc.qencHash")?;
    if recovered_qenc_hash != expected_qenc_hash {
        return Err(coded(
            QvCode::IntegrityMismatch,
            "Reconstructed .qenc hash does not match archive-state descriptor",
        ));
    }
    let container_id = string_field(archive_qenc, "containerId", "archiveState.qenc.containerId")?;
    if sha3_512_hex(&parsed_recovered.header) != container_id {
        return Err(coded(
            QvCode::IntegrityMismatch,
            "Reconstructed .qenc header hash does not match archive-state containerId",
        ));
    }

    let recovered_priv_hash = sha3_512_hex(&priv_key);
    let private_key_hash = base
        .meta_json
        .get("privateKeyHash")
        .and_then(Value::as_str)
        .map(str::to_string);
    let qkey_ok = private_key_hash
        .as_deref()
        .map(|expected| expected == recovered_priv_hash)
        .unwrap_or(true);
    if !qkey_ok {
        return Err(coded(
            QvCode::IntegrityMismatch,
            "Recovered secret key hash does not match shard metadata",
        ));
    }

    Ok(Reconstruction {
        qenc_bytes,
        priv_key,
        container_id,
        container_hash: expected_qenc_hash,
        private_key_hash,
        recovered_qenc_hash,
        recovered_priv_hash,
        rejected_shard_indices: rejected,
        qkey_ok,
        warnings: Vec::new(),
    })
}

fn validate_shard_against_base<'a>(
    candidate: &CandidateCohort<'a>,
    base: &Qvqcont7Shard,
    shard: &'a Qvqcont7Shard,
    expected_share_commitments: &[String],
    expected_body_hashes: &[String],
    chunk_count: usize,
) -> Result<Vec<Vec<u8>>> {
    if shard.archive_state_bytes != candidate.archive_state_bytes
        || shard.cohort_binding_bytes != candidate.cohort_binding_bytes
        || shard.archive_state_digest_hex != candidate.archive_state_digest_hex
        || shard.cohort_binding_digest_hex != candidate.cohort_binding_digest_hex
        || shard.state_id != candidate.state_id
        || shard.cohort_id != candidate.cohort_id
        || shard.encapsulated_key != base.encapsulated_key
        || shard.container_nonce != base.container_nonce
        || shard.kdf_salt != base.kdf_salt
        || shard.qenc_meta_bytes != base.qenc_meta_bytes
        || shard.key_commitment != base.key_commitment
    {
        return Err(err("Shard header fields do not match selected cohort"));
    }
    let index = usize::from(shard.shard_index);
    if expected_share_commitments[index] != sha3_512_hex(&shard.share) {
        return Err(err("Shard share commitment mismatch"));
    }
    if expected_body_hashes[index] != sha3_512_hex(&shard.fragments) {
        return Err(err("Shard body hash mismatch"));
    }
    parse_fragment_stream(&shard.fragments, chunk_count)
}

fn parse_fragment_stream(bytes: &[u8], chunk_count: usize) -> Result<Vec<Vec<u8>>> {
    let mut offset = 0usize;
    let mut out = Vec::with_capacity(chunk_count);
    for _ in 0..chunk_count {
        if offset + 4 > bytes.len() {
            return Err(err("Fragment stream underflow"));
        }
        let len = u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as usize;
        offset += 4;
        let end = offset
            .checked_add(len)
            .ok_or_else(|| err("Fragment length overflow"))?;
        if end > bytes.len() {
            return Err(err("Fragment length overflow"));
        }
        out.push(bytes[offset..end].to_vec());
        offset = end;
    }
    if offset != bytes.len() {
        return Err(err("Fragment stream has trailing data"));
    }
    Ok(out)
}

fn encrypted_chunk_len(
    is_per_chunk: bool,
    chunk_index: usize,
    chunk_size: u64,
    payload_length: u64,
    ciphertext_length: usize,
) -> Result<usize> {
    if !is_per_chunk {
        return Ok(ciphertext_length);
    }
    let chunk_start = (chunk_index as u64)
        .checked_mul(chunk_size)
        .ok_or_else(|| coded(QvCode::InvalidFormat, "QENC per-chunk framing overflow"))?;
    let remaining = payload_length.checked_sub(chunk_start).ok_or_else(|| {
        coded(
            QvCode::InvalidFormat,
            "QENC per-chunk framing exceeds payloadLength",
        )
    })?;
    let plain_len = usize::try_from(chunk_size.min(remaining)).map_err(|_| {
        coded(
            QvCode::InvalidFormat,
            "QENC chunk length exceeds platform limits",
        )
    })?;
    plain_len.checked_add(16).ok_or_else(|| {
        coded(
            QvCode::InvalidFormat,
            "QENC encrypted chunk length overflow",
        )
    })
}

fn expected_fragment_len(
    cipher_len: usize,
    n: usize,
    k: usize,
    max_codeword: usize,
) -> Result<usize> {
    let encode_size = (max_codeword / n) * n;
    if encode_size == 0 {
        return Err(coded(QvCode::InvalidFormat, "RS parameters too large"));
    }
    let input_size = (encode_size * k) / n;
    let symbol_size = input_size / k;
    Ok(cipher_len.div_ceil(input_size) * symbol_size)
}

fn validate_qenc_metadata_against_archive_state(
    metadata: &crate::qenc::QencMetadata,
    archive_state: &Value,
) -> Result<()> {
    let qenc = object_field(archive_state, "qenc", "archiveState.qenc")?;
    let chunk_size = integer_field(qenc, "chunkSize", "archiveState.qenc.chunkSize")?;
    let chunk_count = integer_field(qenc, "chunkCount", "archiveState.qenc.chunkCount")?;
    let payload_length = integer_field(qenc, "payloadLength", "archiveState.qenc.payloadLength")?;
    if metadata.chunk_size.unwrap_or_default() != chunk_size
        || metadata.chunk_count.unwrap_or_default() != chunk_count
        || metadata.payload_length.unwrap_or_default() != payload_length
    {
        return Err(coded(
            QvCode::IntegrityMismatch,
            "QENC metadata does not match archive-state qenc fields",
        ));
    }
    if metadata.crypto_profile_id.as_deref().unwrap_or_default()
        != string_field(
            archive_state,
            "cryptoProfileId",
            "archiveState.cryptoProfileId",
        )?
        || metadata.kdf_tree_id.as_deref().unwrap_or_default()
            != string_field(archive_state, "kdfTreeId", "archiveState.kdfTreeId")?
        || metadata.nonce_policy_id
            != string_field(archive_state, "noncePolicyId", "archiveState.noncePolicyId")?
        || metadata.nonce_mode
            != string_field(archive_state, "nonceMode", "archiveState.nonceMode")?
        || u64::from(metadata.counter_bits)
            != integer_field(archive_state, "counterBits", "archiveState.counterBits")?
        || metadata.max_chunk_count
            != integer_field(archive_state, "maxChunkCount", "archiveState.maxChunkCount")?
        || metadata.aad_policy_id.as_deref().unwrap_or_default()
            != string_field(archive_state, "aadPolicyId", "archiveState.aadPolicyId")?
    {
        return Err(coded(
            QvCode::IntegrityMismatch,
            "QENC policy metadata does not match archive-state descriptor",
        ));
    }
    Ok(())
}

fn evaluate_successor_authenticity(
    lifecycle_bundle: &CanonicalLifecycleBundle,
    lifecycle_bundle_bytes: &[u8],
    archive_state_bytes: &[u8],
    verification_inputs: &VerificationInputs,
) -> Result<AuthenticityReport> {
    let bundle_value = &lifecycle_bundle.lifecycle_bundle.value;
    let archive_state_digest_hex = sha3_512_hex(archive_state_bytes);
    let auth_policy = parse_auth_policy(bundle_value)?;
    let attachments = object_field(bundle_value, "attachments", "lifecycleBundle.attachments")?;
    let public_keys = public_key_map(attachments)?;
    let mut results = Vec::<SignatureCheckResult>::new();
    let mut warnings = Vec::<String>::new();
    let mut signature_artifacts = Vec::<SignatureArtifact>::new();

    for (index, signature) in array_field(
        attachments,
        "archiveApprovalSignatures",
        "lifecycleBundle.attachments.archiveApprovalSignatures",
    )?
    .iter()
    .enumerate()
    {
        match verify_bundle_archive_approval_signature(
            signature,
            index,
            &public_keys,
            archive_state_bytes,
            &archive_state_digest_hex,
            verification_inputs,
        ) {
            Ok(result) => {
                push_signature_artifact(&mut signature_artifacts, &result);
                warnings.extend(result.warnings.iter().cloned());
                results.push(result);
            }
            Err(error) => {
                warnings.push(format!(
                    "Bundled archive-approval signature ignored: {error}"
                ));
            }
        }
    }

    for (index, signature) in verification_inputs.signatures.iter().enumerate() {
        let result = verify_external_archive_approval_signature(
            signature,
            index,
            archive_state_bytes,
            verification_inputs,
        )?;
        push_signature_artifact(&mut signature_artifacts, &result);
        warnings.extend(result.warnings.iter().cloned());
        results.push(result);
    }

    let timestamp_evidence = inspect_lifecycle_timestamps(
        attachments,
        &verification_inputs.timestamps,
        &signature_artifacts,
        &mut warnings,
    )?;
    let counts = finalize_successor_archive_approval_verification(&mut results, &mut warnings);
    let status = signature_status(&counts, verification_inputs);
    let verification = SignatureVerificationReport {
        provided: !results.is_empty(),
        results,
        warnings: warnings.clone(),
        counts,
        signature_artifacts,
        status,
    };
    let policy = evaluate_archive_policy(&auth_policy, &verification);
    if auth_policy.level == AuthPolicyLevel::IntegrityOnly && verification.counts.valid_archive_approval == 0
    {
        warnings.push(
            "Archive policy is integrity-only; archive approval is not bound to a verified signer."
                .to_string(),
        );
    }
    if !policy.satisfied {
        warnings.push(policy.reason.clone());
    }
    let status = AuthenticityStatus {
        integrity_verified: true,
        signature_verified: verification.status.signature_verified,
        strong_pq_signature_verified: verification.status.strong_pq_signature_verified,
        signer_pinned: verification.status.signer_pinned,
        signer_identity_pinned: verification.status.signer_identity_pinned,
        bundle_pinned: verification.status.bundle_pinned,
        user_pinned: verification.status.user_pinned,
        user_pin_provided: verification.status.user_pin_provided,
        policy_satisfied: policy.satisfied,
        archive_policy_satisfied: policy.satisfied,
    };
    let _ = lifecycle_bundle_bytes;
    Ok(AuthenticityReport {
        policy,
        verification,
        warnings,
        status,
        timestamp_evidence,
    })
}

fn verify_bundle_archive_approval_signature(
    signature: &Value,
    index: usize,
    public_keys: &HashMap<String, Value>,
    archive_state_bytes: &[u8],
    archive_state_digest_hex: &str,
    verification_inputs: &VerificationInputs,
) -> Result<SignatureCheckResult> {
    validate_archive_approval_target(signature, archive_state_digest_hex)?;
    let id = string_field(signature, "id", "archiveApprovalSignatures.id")?;
    let format = string_field(signature, "format", "archiveApprovalSignatures.format")?;
    let sig_bytes = BASE64_STANDARD
        .decode(string_field(
            signature,
            "signature",
            "archiveApprovalSignatures.signature",
        )?)
        .map_err(|error| {
            err(format!(
                "Invalid archive-approval signature payload: {error}"
            ))
        })?;
    let public_key_ref = signature.get("publicKeyRef").and_then(Value::as_str);
    let mut result = if format == "qsig" {
        let bundled_pqpk = public_key_ref
            .map(|key_ref| {
                public_key_to_pqpk(public_keys.get(key_ref).ok_or_else(|| {
                    err(format!("Unknown archive-approval publicKeyRef: {key_ref}"))
                })?)
            })
            .transpose()?;
        verify_qsig_against_bytes(
            archive_state_bytes,
            &sig_bytes,
            bundled_pqpk.as_deref(),
            verification_inputs
                .pinned_pq_public_key_file_bytes
                .as_deref(),
        )?
    } else if format == "stellar-sig" {
        let bundled_signer = public_key_ref
            .map(|key_ref| {
                public_key_to_stellar_address(public_keys.get(key_ref).ok_or_else(|| {
                    err(format!("Unknown archive-approval publicKeyRef: {key_ref}"))
                })?)
            })
            .transpose()?;
        verify_stellar_sig_against_bytes(
            archive_state_bytes,
            &sig_bytes,
            bundled_signer.as_deref(),
            verification_inputs.expected_ed25519_signer.as_deref(),
        )?
    } else {
        return Err(err(format!(
            "Unsupported archive-approval format: {format}"
        )));
    };
    decorate_signature_result(
        &mut result,
        id,
        format!("archive-approval-{}", index + 1),
        "lifecycle-bundle".to_string(),
        sig_bytes,
    );
    Ok(result)
}

fn verify_external_archive_approval_signature(
    artifact: &NamedBinaryArtifact,
    index: usize,
    archive_state_bytes: &[u8],
    verification_inputs: &VerificationInputs,
) -> Result<SignatureCheckResult> {
    let name = if artifact.name.is_empty() {
        format!("external-signature-{}", index + 1)
    } else {
        artifact.name.clone()
    };
    let format = if artifact.bytes.starts_with(b"PQSG") {
        "qsig"
    } else {
        "stellar-sig"
    };
    let mut result = if format == "qsig" {
        verify_qsig_against_bytes(
            archive_state_bytes,
            &artifact.bytes,
            None,
            verification_inputs
                .pinned_pq_public_key_file_bytes
                .as_deref(),
        )?
    } else {
        verify_stellar_sig_against_bytes(
            archive_state_bytes,
            &artifact.bytes,
            None,
            verification_inputs.expected_ed25519_signer.as_deref(),
        )?
    };
    decorate_signature_result(
        &mut result,
        name.clone(),
        name,
        "external".to_string(),
        artifact.bytes.clone(),
    );
    Ok(result)
}

fn decorate_signature_result(
    result: &mut SignatureCheckResult,
    artifact_id: String,
    name: String,
    source: String,
    sig_bytes: Vec<u8>,
) {
    let content_digest = sha3_512_hex(&sig_bytes);
    let ots_digest = sha256_hex(&sig_bytes);
    result.artifact_id = artifact_id;
    result.name = name;
    result.source = source;
    result.signature_content_digest_alg = Some("SHA3-512".to_string());
    result.signature_content_digest_hex = Some(content_digest);
    result.ots_stamped_digest_alg = Some("SHA-256".to_string());
    result.ots_stamped_digest_hex = Some(ots_digest);
    result.signature_bytes = Some(sig_bytes);
}

fn push_signature_artifact(out: &mut Vec<SignatureArtifact>, result: &SignatureCheckResult) {
    let Some(bytes) = result.signature_bytes.clone() else {
        return;
    };
    out.push(SignatureArtifact {
        id: result.artifact_id.clone(),
        name: result.name.clone(),
        source: result.source.clone(),
        format: result.format.clone(),
        signature_content_digest_hex: result.signature_content_digest_hex.clone(),
        ots_stamped_digest_hex: result.ots_stamped_digest_hex.clone(),
        bytes,
        ok: result.ok,
    });
}

fn inspect_lifecycle_timestamps(
    attachments: &Value,
    external_timestamps: &[NamedBinaryArtifact],
    signatures: &[SignatureArtifact],
    warnings: &mut Vec<String>,
) -> Result<Vec<TimestampEvidence>> {
    let mut out = Vec::new();
    for timestamp in array_field(
        attachments,
        "timestamps",
        "lifecycleBundle.attachments.timestamps",
    )? {
        let id = string_field(timestamp, "id", "attachments.timestamps.id")?;
        let target_ref = string_field(timestamp, "targetRef", "attachments.timestamps.targetRef")?;
        let proof = BASE64_STANDARD
            .decode(string_field(
                timestamp,
                "proof",
                "attachments.timestamps.proof",
            )?)
            .map_err(|error| err(format!("Invalid lifecycle OTS proof: {error}")))?;
        let candidates = signatures
            .iter()
            .filter(|signature| signature.id == target_ref)
            .cloned()
            .collect::<Vec<_>>();
        if let Some(signature) = candidates.first() {
            let target_digest = object_field(
                timestamp,
                "targetDigest",
                "attachments.timestamps.targetDigest",
            )?;
            let expected = string_field(
                target_digest,
                "value",
                "attachments.timestamps.targetDigest.value",
            )?;
            if signature.ots_stamped_digest_hex.as_deref() != Some(expected.as_str()) {
                warnings.push(format!(
                    "Lifecycle OTS proof ignored: targetDigest does not match detached signature bytes for {target_ref}"
                ));
                continue;
            }
        }
        match resolve_open_timestamp_target(&proof, Some(&id), &candidates) {
            Ok(resolved) => out.push(timestamp_evidence_from_resolved(id, resolved)),
            Err(error) => warnings.push(format!("Lifecycle OTS proof ignored: {error}")),
        }
    }
    for (index, timestamp) in external_timestamps.iter().enumerate() {
        let id = if timestamp.name.is_empty() {
            format!("timestamp-{}", index + 1)
        } else {
            timestamp.name.clone()
        };
        match resolve_open_timestamp_target(&timestamp.bytes, Some(&id), signatures) {
            Ok(resolved) => out.push(timestamp_evidence_from_resolved(id, resolved)),
            Err(error) => warnings.push(format!("External OTS proof ignored: {error}")),
        }
    }
    Ok(out)
}

fn timestamp_evidence_from_resolved(
    id: String,
    resolved: crate::auth::opentimestamps::ResolvedOpenTimestampTarget,
) -> TimestampEvidence {
    TimestampEvidence {
        id,
        target_ref: resolved.target_ref,
        target_name: resolved.target_name,
        target_source: resolved.target_source,
        target_verified: resolved.target_verified,
        linked: resolved.linked,
        apparently_complete: resolved.apparently_complete,
        complete_proof: resolved.complete_proof,
        link_label: "OTS evidence linked to detached signature bytes".to_string(),
        completion_label: if resolved.apparently_complete {
            "OTS proof appears complete".to_string()
        } else {
            "OTS proof appears incomplete".to_string()
        },
    }
}

fn validate_archive_approval_target(
    signature: &Value,
    archive_state_digest_hex: &str,
) -> Result<()> {
    if string_field(
        signature,
        "signatureFamily",
        "archiveApprovalSignatures.signatureFamily",
    )? != "archive-approval"
        || string_field(
            signature,
            "targetType",
            "archiveApprovalSignatures.targetType",
        )? != "archive-state"
    {
        return Err(err("Invalid archive-approval signature target"));
    }
    let expected_ref = format!("state:{archive_state_digest_hex}");
    if string_field(
        signature,
        "targetRef",
        "archiveApprovalSignatures.targetRef",
    )? != expected_ref
    {
        return Err(err("archive-approval signature targetRef mismatch"));
    }
    let target_digest = object_field(
        signature,
        "targetDigest",
        "archiveApprovalSignatures.targetDigest",
    )?;
    if string_field(
        target_digest,
        "value",
        "archiveApprovalSignatures.targetDigest.value",
    )? != archive_state_digest_hex
    {
        return Err(err("archive-approval signature targetDigest mismatch"));
    }
    Ok(())
}

fn public_key_map(attachments: &Value) -> Result<HashMap<String, Value>> {
    let mut out = HashMap::new();
    for key in array_field(
        attachments,
        "publicKeys",
        "lifecycleBundle.attachments.publicKeys",
    )? {
        out.insert(string_field(key, "id", "publicKeys.id")?, key.clone());
    }
    Ok(out)
}

fn public_key_to_pqpk(public_key: &Value) -> Result<Vec<u8>> {
    let encoding = string_field(public_key, "encoding", "publicKeys.encoding")?;
    if encoding != "base64" {
        return Err(err("Bundled PQ public key must use base64 encoding"));
    }
    let suite = string_field(public_key, "suite", "publicKeys.suite")?;
    let suite_id = match suite.as_str() {
        "mldsa-44" => crate::auth::qsig::SUITE_ID_ML_DSA_44,
        "mldsa-65" => crate::auth::qsig::SUITE_ID_ML_DSA_65,
        "mldsa-87" => crate::auth::qsig::SUITE_ID_ML_DSA_87,
        "slhdsa-shake-128s" => crate::auth::qsig::SUITE_ID_SLH_DSA_SHAKE_128S,
        "slhdsa-shake-192s" => crate::auth::qsig::SUITE_ID_SLH_DSA_SHAKE_192S,
        "slhdsa-shake-256s" => crate::auth::qsig::SUITE_ID_SLH_DSA_SHAKE_256S,
        "slhdsa-shake-256f" => crate::auth::qsig::SUITE_ID_SLH_DSA_SHAKE_256F,
        _ => return Err(err(format!("Unsupported bundled PQ suite: {suite}"))),
    };
    let key_bytes = BASE64_STANDARD
        .decode(string_field(public_key, "value", "publicKeys.value")?)
        .map_err(|error| err(format!("Invalid bundled PQ public key: {error}")))?;
    let mut out = Vec::with_capacity(4 + 1 + 1 + 1 + 1 + 4 + key_bytes.len() + 4);
    out.extend_from_slice(b"PQPK");
    out.extend_from_slice(&[1, 0, suite_id, 0]);
    out.extend_from_slice(&(key_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&key_bytes);
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(&out);
    out.extend_from_slice(&hasher.finalize().to_le_bytes());
    Ok(out)
}

fn public_key_to_stellar_address(public_key: &Value) -> Result<String> {
    let encoding = string_field(public_key, "encoding", "publicKeys.encoding")?;
    let suite = string_field(public_key, "suite", "publicKeys.suite")?;
    if encoding != "stellar-address" || suite != "ed25519" {
        return Err(err(
            "Bundled Stellar public key must be an ed25519 stellar-address",
        ));
    }
    string_field(public_key, "value", "publicKeys.value")
}

fn signature_status(
    counts: &SignatureVerificationCounts,
    inputs: &VerificationInputs,
) -> SignatureVerificationStatus {
    SignatureVerificationStatus {
        signature_verified: counts.valid_archive_approval > 0,
        strong_pq_signature_verified: counts.valid_archive_approval_strong_pq > 0,
        signer_pinned: counts.archive_approval_pinned_valid_total > 0,
        signer_identity_pinned: counts.archive_approval_pinned_valid_total > 0,
        bundle_pinned: counts.archive_approval_bundle_pinned_valid_total > 0,
        user_pinned: counts.archive_approval_user_pinned_valid_total > 0,
        user_pin_provided: inputs.pinned_pq_public_key_file_bytes.is_some()
            || inputs.expected_ed25519_signer.is_some(),
    }
}

fn evaluate_archive_policy(
    auth_policy: &AuthPolicy,
    verification: &SignatureVerificationReport,
) -> ArchivePolicyEvaluation {
    let min_valid_signatures = auth_policy.min_valid_signatures.max(1);
    match auth_policy.level {
        AuthPolicyLevel::IntegrityOnly => ArchivePolicyEvaluation {
            level: auth_policy.level,
            min_valid_signatures,
            satisfied: true,
            reason: "integrity-only policy does not require signatures".to_string(),
        },
        AuthPolicyLevel::AnySignature => {
            let satisfied = verification.counts.valid_archive_approval >= min_valid_signatures;
            ArchivePolicyEvaluation {
                level: auth_policy.level,
                min_valid_signatures,
                satisfied,
                reason: if satisfied {
                    "required archive-approval signature count satisfied".to_string()
                } else {
                    "no verified archive-approval signature satisfies archive policy".to_string()
                },
            }
        }
        AuthPolicyLevel::StrongPqSignature => {
            let satisfied = verification.counts.valid_archive_approval >= min_valid_signatures
                && verification.counts.valid_archive_approval_strong_pq >= 1;
            ArchivePolicyEvaluation {
                level: auth_policy.level,
                min_valid_signatures,
                satisfied,
                reason: if satisfied {
                    "required strong PQ archive-approval signature present".to_string()
                } else {
                    "no verified strong PQ archive-approval signature satisfies archive policy"
                        .to_string()
                },
            }
        }
    }
}

fn parse_auth_policy(bundle_value: &Value) -> Result<AuthPolicy> {
    let policy = object_field(bundle_value, "authPolicy", "lifecycleBundle.authPolicy")?;
    let level = match string_field(policy, "level", "authPolicy.level")?.as_str() {
        "integrity-only" => AuthPolicyLevel::IntegrityOnly,
        "any-signature" => AuthPolicyLevel::AnySignature,
        "strong-pq-signature" => AuthPolicyLevel::StrongPqSignature,
        other => return Err(err(format!("Unsupported authPolicy.level: {other}"))),
    };
    let min_valid_signatures = integer_field(
        policy,
        "minValidSignatures",
        "authPolicy.minValidSignatures",
    )?;
    Ok(AuthPolicy {
        level,
        min_valid_signatures,
    })
}

fn object_field<'a>(value: &'a Value, key: &str, field: &str) -> Result<&'a Value> {
    let child = value
        .get(key)
        .ok_or_else(|| err(format!("Invalid {field}")))?;
    if !child.is_object() {
        return Err(err(format!("Invalid {field}")));
    }
    Ok(child)
}

fn array_field<'a>(value: &'a Value, key: &str, field: &str) -> Result<&'a Vec<Value>> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| err(format!("Invalid {field}")))
}

fn string_field(value: &Value, key: &str, field: &str) -> Result<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| err(format!("Invalid {field}")))
}

fn integer_field(value: &Value, key: &str, field: &str) -> Result<u64> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| err(format!("Invalid {field}")))
}

fn string_array_field(value: &Value, key: &str, field: &str) -> Result<Vec<String>> {
    array_field(value, key, field)?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_string)
                .ok_or_else(|| err(format!("Invalid {field}")))
        })
        .collect()
}
