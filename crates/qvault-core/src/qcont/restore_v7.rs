use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

use crate::auth::successor_policy::finalize_successor_lifecycle_verification;
use crate::auth::{
    classify_detached_archive_approval_bytes, resolve_open_timestamp_target,
    verify_qsig_against_bytes, verify_stellar_sig_against_bytes, ArchivePolicyEvaluation,
    AuthPolicy, AuthPolicyLevel, AuthenticityReport, AuthenticityStatus,
    DetachedArchiveApprovalKind, NamedBinaryArtifact, SignatureArtifact, SignatureCheckResult,
    SignatureTargetDigest, SignatureVerificationCounts, SignatureVerificationReport,
    SignatureVerificationStatus, SourceEvidenceReport, SourceEvidenceReportRecord,
    TimestampEvidence, TransitionReport, TransitionReportRecord, VerificationInputs,
};
use crate::erasure;
use crate::error::{coded, err, QvCode, Result};
use crate::hash::{sha256_hex, sha3_512_hex};
use crate::kdf::{derive_key_with_kmac, verify_key_commitment};
use crate::lifecycle::{
    canonicalize_archive_state_descriptor, canonicalize_cohort_binding,
    canonicalize_source_evidence, canonicalize_transition_record, derive_cohort_id,
    parse_lifecycle_bundle_bytes, CanonicalLifecycleBundle,
};
use crate::mlkem::decapsulate;
use crate::qcont::shard_v7::Qvqcont7Shard;
use crate::qenc::{build_qenc_header, parse_qenc_header, parse_qenc_metadata_bytes};
use crate::sss::combine_shares;

const RS_MAX_CODEWORD: usize = 255;
type MaintenanceSignatureEvidence = (BTreeSet<String>, BTreeSet<String>, BTreeSet<String>);
type SignatureDigestEvidence = (BTreeSet<String>, BTreeSet<String>);

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
    /// Sorted unique `lifecycleBundleDigestHex` values observed on input shards for the selected cohort.
    pub embedded_lifecycle_bundle_digests_used: Vec<String>,
    /// True when `embedded_lifecycle_bundle_digests_used.len() > 1` (oracle `mixedLifecycleBundleVariantsWithinSelectedCohort`).
    pub mixed_lifecycle_bundle_variants_within_selected_cohort: bool,
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

impl Drop for RestoredQvqcont7 {
    fn drop(&mut self) {
        self.priv_key.zeroize();
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
    let mut reconstruction = reconstruct_lifecycle_cohort_material(candidate)?;
    let mut reconstruction_priv_key = Zeroizing::new(std::mem::take(&mut reconstruction.priv_key));
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

    let embedded_lifecycle_bundle_digests_used =
        collect_embedded_lifecycle_bundle_digest_hexes(&candidate.shards);
    let mixed_lifecycle_bundle_variants_within_selected_cohort =
        embedded_lifecycle_bundle_digests_used.len() > 1;
    if let Some(message) = mixed_lifecycle_bundle_variant_warning(
        &embedded_lifecycle_bundle_digests_used,
        &selected_bundle.digest_hex,
    ) {
        warnings.push(message);
    }

    Ok(RestoredQvqcont7 {
        qenc_bytes: reconstruction.qenc_bytes,
        priv_key: std::mem::take(&mut *reconstruction_priv_key),
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
        embedded_lifecycle_bundle_digests_used,
        mixed_lifecycle_bundle_variants_within_selected_cohort,
    })
}

fn collect_embedded_lifecycle_bundle_digest_hexes(shards: &[&Qvqcont7Shard]) -> Vec<String> {
    let mut set = BTreeSet::new();
    for shard in shards {
        set.insert(shard.lifecycle_bundle_digest_hex.clone());
    }
    set.into_iter().collect()
}

fn mixed_lifecycle_bundle_variant_warning(
    digests: &[String],
    selected_digest_hex: &str,
) -> Option<String> {
    if digests.len() <= 1 {
        return None;
    }
    Some(format!(
        "Payload reconstruction used shards carrying multiple embedded lifecycle-bundle digests ({}); authenticity and policy were evaluated against selected lifecycle bundle {}.",
        digests.join(", "),
        selected_digest_hex
    ))
}

/// Verify successor lifecycle authenticity for canonical archive-state bytes and a lifecycle
/// bundle (oracle `verify` / dry-run style path without shards).
pub fn verify_successor_lifecycle_authenticity(
    archive_state_bytes: &[u8],
    lifecycle_bundle_bytes: &[u8],
    verification_inputs: &VerificationInputs,
) -> Result<AuthenticityReport> {
    let bundle = parse_lifecycle_bundle_bytes(lifecycle_bundle_bytes)?;
    evaluate_successor_authenticity(
        &bundle,
        lifecycle_bundle_bytes,
        archive_state_bytes,
        verification_inputs,
    )
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
    if n != share_count || m != n.saturating_sub(k) || !m.is_multiple_of(2) || t != k + (m / 2) {
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
            QvCode::NotEnoughShards,
            format!(
                "Too many missing/corrupted shards for RS reconstruction: allowed {allowed_failures}, got {total_bad}"
            ),
        ));
    }

    let shares = Zeroizing::new(
        valid_by_index
            .iter()
            .flatten()
            .take(t)
            .map(|entry| entry.shard.share.clone())
            .collect::<Vec<_>>(),
    );
    let priv_key = combine_shares(shares.as_slice()).map_err(|error| {
        coded(
            QvCode::RestoreFailed,
            format!("Shamir private key reconstruction failed: {error}"),
        )
    })?;
    let mut priv_key = Zeroizing::new(priv_key);
    drop(shares);

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
            QvCode::RestoredIntegrityFailed,
            "Reconstructed ciphertext length mismatch",
        ));
    }

    let shared_secret = Zeroizing::new(
        decapsulate(&base.encapsulated_key, priv_key.as_slice()).map_err(|error| {
            coded(
                QvCode::RestoreFailed,
                format!("Recovered private key cannot decapsulate this container: {error}"),
            )
        })?,
    );
    let derived = derive_key_with_kmac(
        &shared_secret[..],
        &base.kdf_salt,
        &base.qenc_meta_bytes,
        &qenc_meta.domain_strings,
    )?;
    if !verify_key_commitment(&derived.kenc, &base.key_commitment) {
        return Err(coded(
            QvCode::RestoredIntegrityFailed,
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
            QvCode::RestoredIntegrityFailed,
            "Reconstructed .qenc hash does not match archive-state descriptor",
        ));
    }
    let container_id = string_field(archive_qenc, "containerId", "archiveState.qenc.containerId")?;
    if sha3_512_hex(&parsed_recovered.header) != container_id {
        return Err(coded(
            QvCode::RestoredIntegrityFailed,
            "Reconstructed .qenc header hash does not match archive-state containerId",
        ));
    }

    let recovered_priv_hash = sha3_512_hex(priv_key.as_slice());
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
            QvCode::RestoredIntegrityFailed,
            "Recovered secret key hash does not match shard metadata",
        ));
    }

    Ok(Reconstruction {
        qenc_bytes,
        priv_key: std::mem::take(&mut *priv_key),
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
    let auth_policy = parse_auth_policy(bundle_value)?;
    let attachments = object_field(bundle_value, "attachments", "lifecycleBundle.attachments")?;
    let public_keys = public_key_map(attachments)?;
    let mut results = Vec::<SignatureCheckResult>::new();
    let mut warnings = Vec::<String>::new();
    let mut signature_artifacts = Vec::<SignatureArtifact>::new();
    let targets = build_lifecycle_signature_targets(bundle_value, archive_state_bytes)?;

    for descriptor in LifecycleSignatureFamily::descriptors() {
        for (index, signature) in array_field(
            attachments,
            descriptor.field,
            &format!("lifecycleBundle.attachments.{}", descriptor.field),
        )?
        .iter()
        .enumerate()
        {
            match verify_bundle_lifecycle_signature(
                signature,
                index,
                *descriptor,
                &public_keys,
                &targets,
                verification_inputs,
            ) {
                Ok(result) => {
                    push_signature_artifact(&mut signature_artifacts, &result);
                    warnings.extend(result.warnings.iter().cloned());
                    results.push(result);
                }
                Err(error) => {
                    warnings.push(format!(
                        "Bundled {} signature ignored: {error}",
                        descriptor.family
                    ));
                }
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
    let counts = finalize_successor_lifecycle_verification(&mut results, &mut warnings);
    let transition_report = build_successor_transition_report(bundle_value, &results)?;
    let source_evidence_report = build_successor_source_evidence_report(bundle_value, &results)?;
    let ots_evidence_linked = !timestamp_evidence.is_empty();
    let status = signature_status(
        &counts,
        verification_inputs,
        &transition_report,
        &source_evidence_report,
        ots_evidence_linked,
    );
    let verification = SignatureVerificationReport {
        provided: !results.is_empty(),
        results,
        warnings: warnings.clone(),
        counts,
        signature_artifacts,
        status,
    };
    let policy = evaluate_archive_policy(&auth_policy, &verification);
    if auth_policy.level == AuthPolicyLevel::IntegrityOnly
        && verification.counts.valid_archive_approval == 0
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
        archive_approval_signature_verified: verification
            .status
            .archive_approval_signature_verified,
        signature_verified: verification.status.signature_verified,
        strong_pq_signature_verified: verification.status.strong_pq_signature_verified,
        signer_pinned: verification.status.signer_pinned,
        signer_identity_pinned: verification.status.signer_identity_pinned,
        bundle_pinned: verification.status.bundle_pinned,
        user_pinned: verification.status.user_pinned,
        user_pin_provided: verification.status.user_pin_provided,
        transition_record_present: verification.status.transition_record_present,
        transition_chain_valid: verification.status.transition_chain_valid,
        source_evidence_present: verification.status.source_evidence_present,
        maintenance_signature_verified: verification.status.maintenance_signature_verified,
        source_evidence_signature_verified: verification.status.source_evidence_signature_verified,
        ots_evidence_linked: verification.status.ots_evidence_linked,
        policy_satisfied: policy.satisfied,
        archive_policy_satisfied: policy.satisfied,
    };
    let _ = lifecycle_bundle_bytes;
    Ok(AuthenticityReport {
        policy,
        verification,
        transition_report,
        source_evidence_report,
        warnings,
        status,
        timestamp_evidence,
    })
}

#[derive(Debug, Clone, Copy)]
struct LifecycleSignatureFamily {
    family: &'static str,
    field: &'static str,
    target_type: &'static str,
}

impl LifecycleSignatureFamily {
    const ARCHIVE_APPROVAL: Self = Self {
        family: "archive-approval",
        field: "archiveApprovalSignatures",
        target_type: "archive-state",
    };
    const MAINTENANCE: Self = Self {
        family: "maintenance",
        field: "maintenanceSignatures",
        target_type: "transition-record",
    };
    const SOURCE_EVIDENCE: Self = Self {
        family: "source-evidence",
        field: "sourceEvidenceSignatures",
        target_type: "source-evidence",
    };

    fn descriptors() -> &'static [Self] {
        &[
            Self::ARCHIVE_APPROVAL,
            Self::MAINTENANCE,
            Self::SOURCE_EVIDENCE,
        ]
    }
}

#[derive(Debug, Clone)]
struct LifecycleSignatureTarget {
    family: &'static str,
    target_type: &'static str,
    target_ref: String,
    digest: SignatureTargetDigest,
    bytes: Vec<u8>,
    transition_index: Option<usize>,
    maintenance_purpose_labels: Vec<String>,
}

#[derive(Debug, Clone)]
struct LifecycleSignatureTargets {
    archive_approval: LifecycleSignatureTarget,
    maintenance: HashMap<String, LifecycleSignatureTarget>,
    source_evidence: HashMap<String, LifecycleSignatureTarget>,
}

fn verify_bundle_lifecycle_signature(
    signature: &Value,
    index: usize,
    descriptor: LifecycleSignatureFamily,
    public_keys: &HashMap<String, Value>,
    targets: &LifecycleSignatureTargets,
    verification_inputs: &VerificationInputs,
) -> Result<SignatureCheckResult> {
    let target = resolve_lifecycle_signature_target(signature, descriptor, targets)?;
    let id = string_field(signature, "id", &format!("{}.id", descriptor.field))?;
    let format = string_field(signature, "format", &format!("{}.format", descriptor.field))?;
    let sig_bytes = BASE64_STANDARD
        .decode(string_field(
            signature,
            "signature",
            &format!("{}.signature", descriptor.field),
        )?)
        .map_err(|error| {
            err(format!(
                "Invalid {} signature payload: {error}",
                descriptor.family
            ))
        })?;
    let public_key_ref = signature.get("publicKeyRef").and_then(Value::as_str);
    let mut result = if format == "qsig" {
        let bundled_pqpk = public_key_ref
            .map(|key_ref| {
                public_key_to_pqpk(public_keys.get(key_ref).ok_or_else(|| {
                    err(format!(
                        "Unknown {} publicKeyRef: {key_ref}",
                        descriptor.family
                    ))
                })?)
            })
            .transpose()?;
        verify_qsig_against_bytes(
            &target.bytes,
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
                    err(format!(
                        "Unknown {} publicKeyRef: {key_ref}",
                        descriptor.family
                    ))
                })?)
            })
            .transpose()?;
        verify_stellar_sig_against_bytes(
            &target.bytes,
            &sig_bytes,
            bundled_signer.as_deref(),
            verification_inputs.expected_ed25519_signer.as_deref(),
        )?
    } else {
        return Err(err(format!(
            "Unsupported {} format: {format}",
            descriptor.family
        )));
    };
    decorate_signature_result(
        &mut result,
        id,
        format!("{}-{}", descriptor.family, index + 1),
        "bundle".to_string(),
        sig_bytes,
    );
    decorate_lifecycle_target_result(&mut result, &target);
    Ok(result)
}

fn build_lifecycle_signature_targets(
    bundle_value: &Value,
    archive_state_bytes: &[u8],
) -> Result<LifecycleSignatureTargets> {
    let archive_digest_hex = sha3_512_hex(archive_state_bytes);
    let archive_approval = LifecycleSignatureTarget {
        family: "archive-approval",
        target_type: "archive-state",
        target_ref: format!("state:{archive_digest_hex}"),
        digest: SignatureTargetDigest {
            alg: "SHA3-512".to_string(),
            value: archive_digest_hex,
        },
        bytes: archive_state_bytes.to_vec(),
        transition_index: None,
        maintenance_purpose_labels: Vec::new(),
    };

    let transitions = array_field(bundle_value, "transitions", "lifecycleBundle.transitions")?;
    let mut maintenance = HashMap::new();
    for (index, transition) in transitions.iter().enumerate() {
        let canonical = canonicalize_transition_record(transition)?;
        let labels = transition_maintenance_purpose_labels(transition, None)?;
        maintenance.insert(
            canonical.digest.value.clone(),
            LifecycleSignatureTarget {
                family: "maintenance",
                target_type: "transition-record",
                target_ref: format!("transition:sha3-512:{}", canonical.digest.value),
                digest: SignatureTargetDigest {
                    alg: canonical.digest.alg.clone(),
                    value: canonical.digest.value.clone(),
                },
                bytes: canonical.bytes,
                transition_index: Some(index),
                maintenance_purpose_labels: labels,
            },
        );
    }

    let source_evidence_entries = array_field(
        bundle_value,
        "sourceEvidence",
        "lifecycleBundle.sourceEvidence",
    )?;
    let mut source_evidence = HashMap::new();
    for evidence in source_evidence_entries {
        let canonical = canonicalize_source_evidence(evidence)?;
        source_evidence.insert(
            canonical.digest.value.clone(),
            LifecycleSignatureTarget {
                family: "source-evidence",
                target_type: "source-evidence",
                target_ref: format!("source-evidence:sha3-512:{}", canonical.digest.value),
                digest: SignatureTargetDigest {
                    alg: canonical.digest.alg.clone(),
                    value: canonical.digest.value.clone(),
                },
                bytes: canonical.bytes,
                transition_index: None,
                maintenance_purpose_labels: Vec::new(),
            },
        );
    }

    Ok(LifecycleSignatureTargets {
        archive_approval,
        maintenance,
        source_evidence,
    })
}

fn resolve_lifecycle_signature_target(
    signature: &Value,
    descriptor: LifecycleSignatureFamily,
    targets: &LifecycleSignatureTargets,
) -> Result<LifecycleSignatureTarget> {
    if string_field(
        signature,
        "signatureFamily",
        &format!("{}.signatureFamily", descriptor.field),
    )? != descriptor.family
        || string_field(
            signature,
            "targetType",
            &format!("{}.targetType", descriptor.field),
        )? != descriptor.target_type
    {
        return Err(err(format!(
            "Invalid {} signature target",
            descriptor.family
        )));
    }
    let target_digest = object_field(
        signature,
        "targetDigest",
        &format!("{}.targetDigest", descriptor.field),
    )?;
    let digest_alg = string_field(
        target_digest,
        "alg",
        &format!("{}.targetDigest.alg", descriptor.field),
    )?;
    if digest_alg != "SHA3-512" {
        return Err(err(format!(
            "{} signature targetDigest algorithm mismatch",
            descriptor.family
        )));
    }
    let digest_hex = string_field(
        target_digest,
        "value",
        &format!("{}.targetDigest.value", descriptor.field),
    )?;
    let target = match descriptor.family {
        "archive-approval" => {
            if targets.archive_approval.digest.value != digest_hex {
                return Err(err("archive-approval signature targetDigest mismatch"));
            }
            targets.archive_approval.clone()
        }
        "maintenance" => targets
            .maintenance
            .get(&digest_hex)
            .cloned()
            .ok_or_else(|| err("maintenance signature targetDigest mismatch"))?,
        "source-evidence" => targets
            .source_evidence
            .get(&digest_hex)
            .cloned()
            .ok_or_else(|| err("source-evidence signature targetDigest mismatch"))?,
        _ => return Err(err("Unsupported lifecycle signature family")),
    };
    if string_field(
        signature,
        "targetRef",
        &format!("{}.targetRef", descriptor.field),
    )? != target.target_ref
    {
        return Err(err(format!(
            "{} signature targetRef mismatch",
            descriptor.family
        )));
    }
    let mut target = target;
    if descriptor.family == "maintenance" {
        let id = string_field(signature, "id", &format!("{}.id", descriptor.field))?;
        let transitions = target.transition_index;
        if transitions.is_some() {
            target.maintenance_purpose_labels =
                transition_maintenance_purpose_labels_for_target(signature, &id, &target)?;
        }
    }
    Ok(target)
}

fn transition_maintenance_purpose_labels_for_target(
    _signature: &Value,
    _signature_id: &str,
    target: &LifecycleSignatureTarget,
) -> Result<Vec<String>> {
    Ok(target.maintenance_purpose_labels.clone())
}

fn decorate_lifecycle_target_result(
    result: &mut SignatureCheckResult,
    target: &LifecycleSignatureTarget,
) {
    result.family = target.family.to_string();
    result.target_type = Some(target.target_type.to_string());
    result.target_ref = Some(target.target_ref.clone());
    result.target_digest = Some(target.digest.clone());
    result.transition_index = target.transition_index;
    result.maintenance_purpose_labels = target.maintenance_purpose_labels.clone();
}

fn transition_maintenance_purpose_labels(
    transition: &Value,
    signature_id: Option<&str>,
) -> Result<Vec<String>> {
    let source = object_field(transition, "actorHints", "transitionRecord.actorHints")?;
    let mut out = BTreeSet::new();
    if let Some(by_signature) = source.get("maintenanceSignaturePurposes") {
        if let Some(object) = by_signature.as_object() {
            if let Some(id) = signature_id {
                collect_maintenance_purpose_labels(object.get(id), &mut out);
            } else {
                for value in object.values() {
                    collect_maintenance_purpose_labels(Some(value), &mut out);
                }
            }
        }
    }
    if out.is_empty() {
        collect_maintenance_purpose_labels(source.get("maintenanceSignaturePurpose"), &mut out);
    }
    Ok(out.into_iter().collect())
}

fn collect_maintenance_purpose_labels(value: Option<&Value>, out: &mut BTreeSet<String>) {
    match value {
        Some(Value::String(text)) if is_known_maintenance_purpose_label(text) => {
            out.insert(text.trim().to_string());
        }
        Some(Value::Array(values)) => {
            for value in values {
                collect_maintenance_purpose_labels(Some(value), out);
            }
        }
        _ => {}
    }
}

fn is_known_maintenance_purpose_label(value: &str) -> bool {
    matches!(
        value.trim(),
        "maintenance-authorization" | "operator-attestation" | "witness"
    )
}

fn build_successor_transition_report(
    bundle_value: &Value,
    signature_results: &[SignatureCheckResult],
) -> Result<TransitionReport> {
    let archive_state = object_field(bundle_value, "archiveState", "lifecycleBundle.archiveState")?;
    let canonical_archive_state = canonicalize_archive_state_descriptor(archive_state)?;
    let archive_id = string_field(archive_state, "archiveId", "archiveState.archiveId")?;
    let current_cohort_binding = object_field(
        bundle_value,
        "currentCohortBinding",
        "lifecycleBundle.currentCohortBinding",
    )?;
    let canonical_current_cohort = canonicalize_cohort_binding(current_cohort_binding)?;
    let current_cohort_id = derive_cohort_id(
        &archive_id,
        &canonical_archive_state.state_id,
        &canonical_current_cohort.digest,
    )?;

    let mut maintenance_by_digest: HashMap<String, MaintenanceSignatureEvidence> = HashMap::new();
    for result in signature_results {
        if result.family != "maintenance" {
            continue;
        }
        let Some(digest) = result.target_digest.as_ref() else {
            continue;
        };
        let entry = maintenance_by_digest
            .entry(digest.value.clone())
            .or_default();
        let signature_id = if result.artifact_id.is_empty() {
            result.name.clone()
        } else {
            result.artifact_id.clone()
        };
        if !signature_id.is_empty() {
            entry.0.insert(signature_id.clone());
            if result.ok {
                entry.1.insert(signature_id);
            }
        }
        for label in &result.maintenance_purpose_labels {
            entry.2.insert(label.clone());
        }
    }

    let transitions = array_field(bundle_value, "transitions", "lifecycleBundle.transitions")?;
    let mut records = Vec::with_capacity(transitions.len());
    for (index, transition) in transitions.iter().enumerate() {
        let canonical = canonicalize_transition_record(transition)?;
        let source = transition
            .as_object()
            .ok_or_else(|| err("Invalid transitionRecord"))?;
        let mut purpose_labels: BTreeSet<String> =
            transition_maintenance_purpose_labels(transition, None)?
                .into_iter()
                .collect();
        let (signature_ids, verified_signature_ids, signature_labels) = maintenance_by_digest
            .get(&canonical.digest.value)
            .cloned()
            .unwrap_or_default();
        purpose_labels.extend(signature_labels);
        records.push(TransitionReportRecord {
            index,
            digest_hex: canonical.digest.value.clone(),
            transition_type: string_field(
                transition,
                "transitionType",
                "transitionRecord.transitionType",
            )?,
            archive_id: string_field(transition, "archiveId", "transitionRecord.archiveId")?,
            from_state_id: string_field(transition, "fromStateId", "transitionRecord.fromStateId")?,
            to_state_id: string_field(transition, "toStateId", "transitionRecord.toStateId")?,
            from_cohort_id: string_field(
                transition,
                "fromCohortId",
                "transitionRecord.fromCohortId",
            )?,
            to_cohort_id: string_field(transition, "toCohortId", "transitionRecord.toCohortId")?,
            from_cohort_binding_digest: signature_digest_from_value(
                source
                    .get("fromCohortBindingDigest")
                    .ok_or_else(|| err("Missing transitionRecord.fromCohortBindingDigest"))?,
                "transitionRecord.fromCohortBindingDigest",
            )?,
            to_cohort_binding_digest: signature_digest_from_value(
                source
                    .get("toCohortBindingDigest")
                    .ok_or_else(|| err("Missing transitionRecord.toCohortBindingDigest"))?,
                "transitionRecord.toCohortBindingDigest",
            )?,
            maintenance_signature_count: signature_ids.len(),
            verified_maintenance_signature_count: verified_signature_ids.len(),
            maintenance_signature_ids: signature_ids.into_iter().collect(),
            verified_maintenance_signature_ids: verified_signature_ids.into_iter().collect(),
            maintenance_purpose_labels: purpose_labels.into_iter().collect(),
        });
    }

    let mut all_labels = BTreeSet::new();
    for record in &records {
        all_labels.extend(record.maintenance_purpose_labels.iter().cloned());
    }
    Ok(TransitionReport {
        present: !records.is_empty(),
        chain_valid: !records.is_empty(),
        validation_scope: if records.is_empty() {
            "unavailable".to_string()
        } else {
            "structural-referential".to_string()
        },
        count: records.len(),
        signed: records
            .iter()
            .any(|record| record.maintenance_signature_count > 0),
        maintenance_signature_verified: records
            .iter()
            .any(|record| record.verified_maintenance_signature_count > 0),
        maintenance_purpose_labels: all_labels.into_iter().collect(),
        current_archive_id: archive_id,
        current_state_id: canonical_archive_state.state_id,
        current_cohort_id,
        current_cohort_binding_digest_hex: canonical_current_cohort.digest.value,
        records,
    })
}

fn build_successor_source_evidence_report(
    bundle_value: &Value,
    signature_results: &[SignatureCheckResult],
) -> Result<SourceEvidenceReport> {
    let mut signatures_by_digest: HashMap<String, SignatureDigestEvidence> = HashMap::new();
    for result in signature_results {
        if result.family != "source-evidence" {
            continue;
        }
        let Some(digest) = result.target_digest.as_ref() else {
            continue;
        };
        let entry = signatures_by_digest
            .entry(digest.value.clone())
            .or_default();
        let signature_id = if result.artifact_id.is_empty() {
            result.name.clone()
        } else {
            result.artifact_id.clone()
        };
        if !signature_id.is_empty() {
            entry.0.insert(signature_id.clone());
            if result.ok {
                entry.1.insert(signature_id);
            }
        }
    }

    let entries = array_field(
        bundle_value,
        "sourceEvidence",
        "lifecycleBundle.sourceEvidence",
    )?;
    let mut records = Vec::with_capacity(entries.len());
    for (index, evidence) in entries.iter().enumerate() {
        let canonical = canonicalize_source_evidence(evidence)?;
        let source = evidence
            .as_object()
            .ok_or_else(|| err("Invalid sourceEvidence"))?;
        let (signature_ids, verified_signature_ids) = signatures_by_digest
            .get(&canonical.digest.value)
            .cloned()
            .unwrap_or_default();
        let external_refs = optional_string_array(source.get("externalSourceSignatureRefs"))?;
        let descriptive_field_names = if source
            .get("mediaType")
            .and_then(Value::as_str)
            .map(|text| !text.is_empty())
            .unwrap_or(false)
        {
            vec!["mediaType".to_string()]
        } else {
            Vec::new()
        };
        records.push(SourceEvidenceReportRecord {
            index,
            digest_hex: canonical.digest.value.clone(),
            target_ref: format!("source-evidence:sha3-512:{}", canonical.digest.value),
            relation_type: string_field(evidence, "relationType", "sourceEvidence.relationType")?,
            source_object_type: string_field(
                evidence,
                "sourceObjectType",
                "sourceEvidence.sourceObjectType",
            )?,
            source_digests: source_digest_list(evidence)?,
            external_source_signature_ref_count: external_refs.len(),
            external_source_signature_refs: external_refs,
            descriptive_field_names,
            media_type: source
                .get("mediaType")
                .and_then(Value::as_str)
                .map(ToString::to_string),
            source_evidence_signature_count: signature_ids.len(),
            verified_source_evidence_signature_count: verified_signature_ids.len(),
            source_evidence_signature_ids: signature_ids.into_iter().collect(),
            verified_source_evidence_signature_ids: verified_signature_ids.into_iter().collect(),
        });
    }
    let mut descriptive_names = BTreeSet::new();
    for record in &records {
        descriptive_names.extend(record.descriptive_field_names.iter().cloned());
    }
    let source_evidence_signature_count = records
        .iter()
        .map(|record| record.source_evidence_signature_count)
        .sum();
    let verified_source_evidence_signature_count = records
        .iter()
        .map(|record| record.verified_source_evidence_signature_count)
        .sum();
    let external_source_signature_ref_count = records
        .iter()
        .map(|record| record.external_source_signature_ref_count)
        .sum();
    Ok(SourceEvidenceReport {
        present: !records.is_empty(),
        count: records.len(),
        signed: records
            .iter()
            .any(|record| record.source_evidence_signature_count > 0),
        signature_verified: records
            .iter()
            .any(|record| record.verified_source_evidence_signature_count > 0),
        source_evidence_signature_count,
        verified_source_evidence_signature_count,
        external_source_signature_ref_count,
        external_source_signature_refs_present: external_source_signature_ref_count > 0,
        descriptive_field_names: descriptive_names.into_iter().collect(),
        records,
    })
}

fn signature_digest_from_value(value: &Value, field: &str) -> Result<SignatureTargetDigest> {
    let object = value
        .as_object()
        .ok_or_else(|| err(format!("Invalid {field}")))?;
    Ok(SignatureTargetDigest {
        alg: object
            .get("alg")
            .and_then(Value::as_str)
            .ok_or_else(|| err(format!("Invalid {field}.alg")))?
            .to_string(),
        value: object
            .get("value")
            .and_then(Value::as_str)
            .ok_or_else(|| err(format!("Invalid {field}.value")))?
            .to_string(),
    })
}

fn source_digest_list(evidence: &Value) -> Result<Vec<SignatureTargetDigest>> {
    array_field(evidence, "sourceDigests", "sourceEvidence.sourceDigests")?
        .iter()
        .enumerate()
        .map(|(index, digest)| {
            signature_digest_from_value(digest, &format!("sourceEvidence.sourceDigests[{index}]"))
        })
        .collect()
}

fn optional_string_array(value: Option<&Value>) -> Result<Vec<String>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let values = value
        .as_array()
        .ok_or_else(|| err("Invalid string array"))?;
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(ToString::to_string)
                .ok_or_else(|| err("Invalid string array value"))
        })
        .collect()
}

fn external_unknown_archive_approval_result(message: impl Into<String>) -> SignatureCheckResult {
    SignatureCheckResult {
        ok: false,
        family: "archive-approval".to_string(),
        self_signed: false,
        bundle_pinned: false,
        user_pinned: false,
        signer_pinned: false,
        name: String::new(),
        source: "external".to_string(),
        format: "unknown".to_string(),
        suite: Some("unknown".to_string()),
        suite_display: None,
        strong_pq: false,
        key_source: None,
        signer_fingerprint_hex: None,
        signer_label: None,
        signer: None,
        error: Some(message.into()),
        warnings: Vec::new(),
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
    let mut result = match classify_detached_archive_approval_bytes(&artifact.bytes) {
        Err(error) => {
            let mut unsupported = external_unknown_archive_approval_result(format!(
                "Unsupported signature format: {error}"
            ));
            decorate_signature_result(
                &mut unsupported,
                name.clone(),
                name,
                "external".to_string(),
                artifact.bytes.clone(),
            );
            return Ok(unsupported);
        }
        Ok(DetachedArchiveApprovalKind::Qsig) => verify_qsig_against_bytes(
            archive_state_bytes,
            &artifact.bytes,
            None,
            verification_inputs
                .pinned_pq_public_key_file_bytes
                .as_deref(),
        )?,
        Ok(DetachedArchiveApprovalKind::StellarJson) => verify_stellar_sig_against_bytes(
            archive_state_bytes,
            &artifact.bytes,
            None,
            verification_inputs.expected_ed25519_signer.as_deref(),
        )?,
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
        family: result.family.clone(),
        format: result.format.clone(),
        target_type: result.target_type.clone(),
        target_ref: result.target_ref.clone(),
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
            let computed_digest = sha256_hex(&signature.bytes);
            if computed_digest != expected {
                warnings.push(format!(
                    "Lifecycle OTS proof ignored: targetDigest does not match SHA-256(detached signature bytes) for {target_ref}"
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
            "OTS proof appears complete (heuristic)".to_string()
        } else {
            "OTS proof appears incomplete".to_string()
        },
    }
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
    transition_report: &TransitionReport,
    source_evidence_report: &SourceEvidenceReport,
    ots_evidence_linked: bool,
) -> SignatureVerificationStatus {
    SignatureVerificationStatus {
        archive_approval_signature_verified: counts.valid_archive_approval > 0,
        signature_verified: counts.valid_archive_approval > 0,
        strong_pq_signature_verified: counts.valid_archive_approval_strong_pq > 0,
        signer_pinned: counts.archive_approval_pinned_valid_total > 0,
        signer_identity_pinned: counts.archive_approval_pinned_valid_total > 0,
        bundle_pinned: counts.archive_approval_bundle_pinned_valid_total > 0,
        user_pinned: counts.archive_approval_user_pinned_valid_total > 0,
        user_pin_provided: inputs.pinned_pq_public_key_file_bytes.is_some()
            || inputs.expected_ed25519_signer.is_some(),
        transition_record_present: transition_report.present,
        transition_chain_valid: transition_report.chain_valid,
        source_evidence_present: source_evidence_report.present,
        maintenance_signature_verified: counts.valid_maintenance > 0,
        source_evidence_signature_verified: counts.valid_source_evidence > 0,
        ots_evidence_linked,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ots_completion_label_marks_complete_proofs_as_heuristic() {
        let evidence = timestamp_evidence_from_resolved(
            "complete.ots".to_string(),
            crate::auth::opentimestamps::ResolvedOpenTimestampTarget {
                target_ref: "sig-1".to_string(),
                target_name: "sig-1.qsig".to_string(),
                target_source: "bundle".to_string(),
                target_verified: true,
                linked: true,
                apparently_complete: true,
                complete_proof: true,
                stamped_digest_hex: "00".repeat(32),
            },
        );
        assert_eq!(
            evidence.completion_label,
            "OTS proof appears complete (heuristic)"
        );
        assert_eq!(
            evidence.link_label,
            "OTS evidence linked to detached signature bytes"
        );
    }
}
