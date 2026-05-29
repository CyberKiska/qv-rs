use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

use crate::auth::AuthPolicyLevel;
use crate::erasure;
use crate::error::{coded, err, QvCode, Result};
use crate::hash::{sha3_512, sha3_512_hex};
use crate::kdf::{derive_key_with_kmac, verify_key_commitment};
use crate::lifecycle::{
    build_archive_state_descriptor, build_cohort_binding, build_lifecycle_bundle,
    canonicalize_archive_state_descriptor, canonicalize_cohort_binding,
    canonicalize_lifecycle_bundle, derive_cohort_id, generate_archive_id,
    parse_archive_state_descriptor_bytes, ArchiveStateDescriptor,
    BuildArchiveStateDescriptorParams, BuildCohortBindingParams, BuildLifecycleBundleParams,
    CohortBinding, LifecycleBundle,
};
use crate::manifest::strict_json::parse_json_bytes_strict;
use crate::mlkem::decapsulate;
use crate::policy::{get_nonce_contract_for_aead_mode, DEFAULT_CRYPTO_PROFILE};
use crate::qcont::shard_v7::{
    build_qvqcont7_shard, Qvqcont7Shard, LIFECYCLE_ARTIFACT_FAMILY, LIFECYCLE_QCONT_FORMAT_VERSION,
};
use crate::qenc::{parse_qenc_header, CHUNK_SIZE};
use crate::sss::split_secret;

const RS_MAX_CODEWORD: usize = 255;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Qvqcont7BuildParams {
    pub n: u16,
    pub k: u16,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Qvqcont7BuildOptions {
    pub archive_id: Option<String>,
    pub archive_id_random_bytes: Option<[u8; 32]>,
    pub preserved_archive_state_bytes: Option<Vec<u8>>,
    pub parent_state_id: Option<String>,
    pub state_type: Option<String>,
    pub sss_random_bytes: Option<Vec<u8>>,
    pub auth_policy_level: Option<AuthPolicyLevel>,
    pub min_valid_signatures: Option<u64>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct BuiltQvqcont7Shard {
    pub bytes: Vec<u8>,
    pub index: u16,
}

impl std::fmt::Debug for BuiltQvqcont7Shard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BuiltQvqcont7Shard")
            .field("index", &self.index)
            .field("bytes_len", &self.bytes.len())
            .finish()
    }
}

impl Drop for BuiltQvqcont7Shard {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct BuiltQvqcont7Shards {
    pub shards: Vec<BuiltQvqcont7Shard>,
    pub archive_id: String,
    pub state_id: String,
    pub cohort_id: String,
    pub archive_state: ArchiveStateDescriptor,
    pub archive_state_bytes: Vec<u8>,
    pub archive_state_digest_hex: String,
    pub cohort_binding: CohortBinding,
    pub cohort_binding_bytes: Vec<u8>,
    pub cohort_binding_digest_hex: String,
    pub lifecycle_bundle: LifecycleBundle,
    pub lifecycle_bundle_bytes: Vec<u8>,
    pub lifecycle_bundle_digest_hex: String,
    pub format_version: String,
    pub container_hash_hex: String,
    pub container_id: String,
    pub private_key_hash_hex: String,
}

impl std::fmt::Debug for BuiltQvqcont7Shards {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BuiltQvqcont7Shards")
            .field("shard_count", &self.shards.len())
            .field("archive_id", &self.archive_id)
            .field("state_id", &self.state_id)
            .field("cohort_id", &self.cohort_id)
            .field("format_version", &self.format_version)
            .finish()
    }
}

pub fn build_qvqcont7_shards(
    qenc_bytes: &[u8],
    priv_key_bytes: &[u8],
    params: Qvqcont7BuildParams,
    options: &Qvqcont7BuildOptions,
) -> Result<BuiltQvqcont7Shards> {
    let n = usize::from(params.n);
    let k = usize::from(params.k);
    if k < 2 || n <= k {
        return Err(err("Invalid cohort parameters: require 2 <= k < n"));
    }
    let m = n
        .checked_sub(k)
        .ok_or_else(|| err("Invalid cohort parameters: require 2 <= k < n"))?;
    if (m % 2) != 0 {
        return Err(err(
            "Unsupported cohort parameters: parity must be even under QV-RS-ErasureCodes-v1",
        ));
    }
    let t = k + (m / 2);
    if t > n {
        return Err(err("Invalid threshold computed"));
    }

    let parsed = parse_qenc_header(qenc_bytes)?;
    let key_commitment = parsed.stored_key_commitment;
    let ciphertext = &qenc_bytes[parsed.offset..];
    let ds = &parsed.metadata.domain_strings;
    if ds.kdf.is_empty() || ds.iv.is_empty() || ds.kenc.is_empty() || ds.kiv.is_empty() {
        return Err(err("QENC metadata is missing valid domainStrings"));
    }

    {
        let trial_shared_secret = Zeroizing::new(
            decapsulate(&parsed.encapsulated_key, priv_key_bytes).map_err(|error| {
                coded(
                    QvCode::KeyRejected,
                    format!("Key verification failed: {error}"),
                )
            })?,
        );
        let derived = derive_key_with_kmac(
            &trial_shared_secret[..],
            &parsed.kdf_salt,
            &parsed.meta_bytes,
            ds,
        )
        .map_err(|error| err(format!("Key verification failed: {error}")))?;
        let key_match = verify_key_commitment(&derived.kenc, &key_commitment);
        if !key_match {
            return Err(coded(
                QvCode::KeyRejected,
                "Private key does not match this .qenc container (key commitment mismatch). Ensure you are using the correct privateKey.qkey for this container.",
            ));
        }
    }

    let effective_length = parsed
        .metadata
        .payload_length
        .ok_or_else(|| err("QENC metadata is missing payloadLength"))?;
    let container_id = sha3_512_hex(&parsed.header);
    let container_hash = sha3_512_hex(qenc_bytes);
    let private_key_hash_hex = sha3_512_hex(priv_key_bytes);
    let chunk_size = parsed.metadata.chunk_size.unwrap_or(CHUNK_SIZE as u64);
    let is_per_chunk = parsed.metadata.aead_mode == "per-chunk-aead";
    let total_chunks = if is_per_chunk {
        parsed
            .metadata
            .chunk_count
            .unwrap_or_else(|| effective_length.div_ceil(chunk_size))
    } else {
        1
    };
    let _nonce_contract = get_nonce_contract_for_aead_mode(&parsed.metadata.aead_mode)?;

    let shares = Zeroizing::new(split_secret(
        priv_key_bytes,
        n,
        t,
        options.sss_random_bytes.as_deref(),
    )?);
    let share_commitments = shares
        .iter()
        .map(|share| sha3_512_hex(share))
        .collect::<Vec<_>>();
    let shard_bodies = build_shard_bodies(
        ciphertext,
        effective_length,
        chunk_size,
        total_chunks,
        is_per_chunk,
        n,
        k,
        m,
    )?;
    let per_fragment_size = first_fragment_size(&shard_bodies)?;
    let fragment_body_hashes = shard_bodies
        .iter()
        .map(|body| sha3_512_hex(body))
        .collect::<Vec<_>>();

    let has_forbidden_archive_override = options.archive_id.is_some()
        || options.archive_id_random_bytes.is_some()
        || options.parent_state_id.is_some()
        || options.state_type.is_some();
    if options.preserved_archive_state_bytes.is_some() && has_forbidden_archive_override {
        return Err(err(
            "preserved_archive_state_bytes forbids archive-state override options",
        ));
    }
    let archive_id = match (
        &options.archive_id,
        options.archive_id_random_bytes,
        options.preserved_archive_state_bytes.as_deref(),
    ) {
        (_, _, Some(bytes)) => parse_archive_state_descriptor_bytes(bytes)?
            .archive_state
            .value
            .get("archiveId")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| err("Missing preserved archiveState.archiveId"))?,
        (Some(archive_id), None, None) => archive_id.clone(),
        (None, random_bytes, None) => generate_archive_id(random_bytes)?,
        (Some(_), Some(_), None) => {
            return Err(err(
                "archive_id and archive_id_random_bytes are mutually exclusive",
            ))
        }
    };
    let auth_policy_level = options
        .auth_policy_level
        .unwrap_or(AuthPolicyLevel::StrongPqSignature);
    let min_valid_signatures = options.min_valid_signatures.unwrap_or(1).max(1);
    let crypto_profile_id = parsed
        .metadata
        .crypto_profile_id
        .clone()
        .unwrap_or_else(|| DEFAULT_CRYPTO_PROFILE.crypto_profile_id.to_string());
    let kdf_tree_id = parsed
        .metadata
        .kdf_tree_id
        .clone()
        .unwrap_or_else(|| DEFAULT_CRYPTO_PROFILE.kdf_tree_id.to_string());
    let aad_policy_id = parsed
        .metadata
        .aad_policy_id
        .clone()
        .unwrap_or_else(|| DEFAULT_CRYPTO_PROFILE.aad_policy_id.to_string());

    let (archive_state, canonical_archive_state) = if let Some(bytes) =
        options.preserved_archive_state_bytes.as_deref()
    {
        let canonical = parse_archive_state_descriptor_bytes(bytes)?;
        assert_preserved_archive_state_matches_qenc(
            &canonical.archive_state.value,
            &parsed.metadata,
            chunk_size,
            total_chunks,
            parsed.metadata.payload_length.unwrap_or(effective_length),
            &container_hash,
            &container_id,
        )?;
        (canonical.archive_state.clone(), canonical)
    } else {
        let archive_state = build_archive_state_descriptor(&BuildArchiveStateDescriptorParams {
            archive_id: archive_id.clone(),
            parent_state_id: options.parent_state_id.clone(),
            state_type: options.state_type.clone(),
            crypto_profile_id: crypto_profile_id.clone(),
            kdf_tree_id,
            nonce_policy_id: parsed.metadata.nonce_policy_id.clone(),
            nonce_mode: parsed.metadata.nonce_mode.clone(),
            counter_bits: parsed.metadata.counter_bits,
            max_chunk_count: parsed.metadata.max_chunk_count,
            aad_policy_id: aad_policy_id.clone(),
            chunk_size,
            chunk_count: total_chunks,
            payload_length: parsed.metadata.payload_length.unwrap_or(effective_length),
            qenc_hash: container_hash.clone(),
            container_id: container_id.clone(),
            auth_policy_level,
            min_valid_signatures,
        })?;
        let canonical = canonicalize_archive_state_descriptor(&archive_state.value)?;
        (archive_state, canonical)
    };
    let archive_state_bytes = canonical_archive_state.bytes.clone();
    let archive_state_digest_hex = canonical_archive_state.digest.value.clone();
    let state_id = canonical_archive_state.state_id.clone();

    let cohort_binding = build_cohort_binding(&BuildCohortBindingParams {
        archive_id: archive_id.clone(),
        state_id: state_id.clone(),
        shamir_threshold: t as u64,
        shamir_share_count: n as u64,
        rs_n: n as u64,
        rs_k: k as u64,
        rs_parity: m as u64,
        shard_body_hashes: fragment_body_hashes,
        share_commitments,
    })?;
    let canonical_cohort_binding = canonicalize_cohort_binding(&cohort_binding.value)?;
    let cohort_binding_bytes = canonical_cohort_binding.bytes.clone();
    let cohort_binding_digest_hex = canonical_cohort_binding.digest.value.clone();
    let cohort_id = derive_cohort_id(&archive_id, &state_id, &canonical_cohort_binding.digest)?;

    let lifecycle_bundle = build_lifecycle_bundle(&BuildLifecycleBundleParams {
        archive_state: archive_state.value.clone(),
        current_cohort_binding: cohort_binding.value.clone(),
        auth_policy_level,
        min_valid_signatures,
    })?;
    let canonical_lifecycle_bundle = canonicalize_lifecycle_bundle(&lifecycle_bundle.value)?;
    let lifecycle_bundle_bytes = canonical_lifecycle_bundle.bytes.clone();
    let lifecycle_bundle_digest_hex = canonical_lifecycle_bundle.digest.value.clone();
    let qenc_meta_json = parse_json_bytes_strict(&parsed.meta_bytes)?;

    let mut shards = Vec::with_capacity(n);
    for j in 0..n {
        let meta_json = shard_metadata_json(
            &archive_id,
            &state_id,
            &cohort_id,
            &parsed,
            &crypto_profile_id,
            &aad_policy_id,
            n,
            k,
            m,
            t,
            chunk_size,
            total_chunks,
            &container_id,
            &container_hash,
            &private_key_hash_hex,
            effective_length,
            ciphertext.len(),
            per_fragment_size,
            &key_commitment,
            j,
        );
        let meta_bytes = serde_json::to_vec(&meta_json)?;
        let shard = Qvqcont7Shard {
            meta_json,
            meta_bytes,
            archive_state_bytes: archive_state_bytes.clone(),
            archive_state_digest_hex: archive_state_digest_hex.clone(),
            archive_state: canonical_archive_state.clone(),
            state_id: state_id.clone(),
            cohort_binding_bytes: cohort_binding_bytes.clone(),
            cohort_binding_digest_hex: cohort_binding_digest_hex.clone(),
            cohort_binding: canonical_cohort_binding.clone(),
            cohort_id: cohort_id.clone(),
            lifecycle_bundle_bytes: lifecycle_bundle_bytes.clone(),
            lifecycle_bundle_digest_hex: lifecycle_bundle_digest_hex.clone(),
            lifecycle_bundle: canonical_lifecycle_bundle.clone(),
            encapsulated_key: parsed.encapsulated_key.clone(),
            container_nonce: parsed.container_nonce,
            kdf_salt: parsed.kdf_salt,
            qenc_meta_bytes: parsed.meta_bytes.clone(),
            qenc_meta_json: qenc_meta_json.clone(),
            key_commitment,
            shard_index: j as u16,
            share: shares[j].clone(),
            fragments: shard_bodies[j].clone(),
        };
        shards.push(BuiltQvqcont7Shard {
            bytes: build_qvqcont7_shard(&shard)?,
            index: j as u16,
        });
    }
    drop(shares);

    Ok(BuiltQvqcont7Shards {
        shards,
        archive_id,
        state_id,
        cohort_id,
        archive_state,
        archive_state_bytes,
        archive_state_digest_hex,
        cohort_binding,
        cohort_binding_bytes,
        cohort_binding_digest_hex,
        lifecycle_bundle,
        lifecycle_bundle_bytes,
        lifecycle_bundle_digest_hex,
        format_version: LIFECYCLE_QCONT_FORMAT_VERSION.to_string(),
        container_hash_hex: container_hash,
        container_id,
        private_key_hash_hex,
    })
}

#[allow(clippy::too_many_arguments)]
fn build_shard_bodies(
    ciphertext: &[u8],
    effective_length: u64,
    chunk_size: u64,
    total_chunks: u64,
    is_per_chunk: bool,
    n: usize,
    k: usize,
    m: usize,
) -> Result<Vec<Vec<u8>>> {
    let mut ciphertext_offset = 0usize;
    let mut shard_bodies = vec![Vec::new(); n];
    for i in 0..total_chunks {
        let cipher_chunk = if is_per_chunk {
            let chunk_start = i
                .checked_mul(chunk_size)
                .ok_or_else(|| err("QENC per-chunk framing overflow"))?;
            let remaining = effective_length
                .checked_sub(chunk_start)
                .ok_or_else(|| err("QENC per-chunk framing exceeds payloadLength"))?;
            let plain_len = usize::try_from(chunk_size.min(remaining))
                .map_err(|_| err("QENC chunk length exceeds platform limits"))?;
            let enc_len = plain_len
                .checked_add(16)
                .ok_or_else(|| err("QENC encrypted chunk length overflow"))?;
            let chunk_end = ciphertext_offset
                .checked_add(enc_len)
                .ok_or_else(|| err("QENC ciphertext offset overflow"))?;
            if chunk_end > ciphertext.len() {
                return Err(err(
                    "QENC ciphertext is truncated for declared per-chunk framing",
                ));
            }
            let chunk = &ciphertext[ciphertext_offset..chunk_end];
            ciphertext_offset = chunk_end;
            chunk
        } else {
            ciphertext
        };

        let encode_size = (RS_MAX_CODEWORD / n) * n;
        if encode_size == 0 {
            return Err(err("RS parameters too large"));
        }
        let input_size = (encode_size * k) / n;
        let pad_target = cipher_chunk.len().div_ceil(input_size) * input_size;
        let mut chunk_for_rs = vec![0u8; pad_target];
        chunk_for_rs[..cipher_chunk.len()].copy_from_slice(cipher_chunk);
        let fragments = erasure::split(&chunk_for_rs, k, m / 2, RS_MAX_CODEWORD)?;
        if fragments.len() != n {
            return Err(err("RS split returned unexpected number of fragments"));
        }
        for (j, fragment) in fragments.iter().enumerate() {
            shard_bodies[j].extend_from_slice(&(fragment.len() as u32).to_be_bytes());
            shard_bodies[j].extend_from_slice(fragment);
        }
    }
    if is_per_chunk && ciphertext_offset != ciphertext.len() {
        return Err(err(
            "QENC ciphertext length does not match declared per-chunk framing",
        ));
    }
    Ok(shard_bodies)
}

fn first_fragment_size(shard_bodies: &[Vec<u8>]) -> Result<u64> {
    let first = shard_bodies
        .first()
        .ok_or_else(|| err("No shard bodies were generated"))?;
    if first.len() < 4 {
        return Err(err("Shard fragment payload is empty"));
    }
    let len = u32::from_be_bytes([first[0], first[1], first[2], first[3]]);
    Ok(u64::from(len))
}

fn assert_preserved_archive_state_matches_qenc(
    archive_state: &Value,
    metadata: &crate::qenc::QencMetadata,
    chunk_size: u64,
    chunk_count: u64,
    payload_length: u64,
    qenc_hash: &str,
    container_id: &str,
) -> Result<()> {
    let qenc = archive_state
        .get("qenc")
        .and_then(Value::as_object)
        .ok_or_else(|| err("Preserved archive-state is missing qenc object"))?;
    let qenc_u64 = |field: &str| -> Result<u64> {
        qenc.get(field)
            .and_then(Value::as_u64)
            .ok_or_else(|| err(format!("Preserved archive-state qenc.{field} mismatch")))
    };
    let qenc_str = |field: &str| -> Result<&str> {
        qenc.get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| err(format!("Preserved archive-state qenc.{field} mismatch")))
    };
    if qenc_u64("chunkSize")? != chunk_size
        || qenc_u64("chunkCount")? != chunk_count
        || qenc_u64("payloadLength")? != payload_length
        || qenc_str("qencHash")? != qenc_hash
        || qenc_str("containerId")? != container_id
    {
        return Err(err(
            "Preserved archive-state descriptor does not match reconstructed .qenc",
        ));
    }
    let state_str = |field: &str| -> Result<&str> {
        archive_state
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| err(format!("Preserved archive-state {field} mismatch")))
    };
    if state_str("cryptoProfileId")? != metadata.crypto_profile_id.as_deref().unwrap_or_default()
        || state_str("kdfTreeId")? != metadata.kdf_tree_id.as_deref().unwrap_or_default()
        || state_str("noncePolicyId")? != metadata.nonce_policy_id
        || state_str("nonceMode")? != metadata.nonce_mode
        || archive_state
            .get("counterBits")
            .and_then(Value::as_u64)
            .unwrap_or(u64::MAX)
            != u64::from(metadata.counter_bits)
        || archive_state
            .get("maxChunkCount")
            .and_then(Value::as_u64)
            .unwrap_or_default()
            != metadata.max_chunk_count
        || state_str("aadPolicyId")? != metadata.aad_policy_id.as_deref().unwrap_or_default()
    {
        return Err(err(
            "Preserved archive-state policy metadata does not match reconstructed .qenc",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn shard_metadata_json(
    archive_id: &str,
    state_id: &str,
    cohort_id: &str,
    parsed: &crate::qenc::QencHeader,
    crypto_profile_id: &str,
    aad_policy_id: &str,
    n: usize,
    k: usize,
    m: usize,
    t: usize,
    chunk_size: u64,
    total_chunks: u64,
    container_id: &str,
    container_hash: &str,
    private_key_hash_hex: &str,
    effective_length: u64,
    ciphertext_length: usize,
    per_fragment_size: u64,
    key_commitment: &[u8; 32],
    shard_index: usize,
) -> Value {
    serde_json::json!({
        "artifactFamily": LIFECYCLE_ARTIFACT_FAMILY,
        "archiveId": archive_id,
        "stateId": state_id,
        "cohortId": cohort_id,
        "alg": {
            "KEM": "ML-KEM-1024",
            "KDF": "KMAC256",
            "AEAD": "AES-256-GCM",
            "RS": "ErasureCodes",
            "fmt": LIFECYCLE_QCONT_FORMAT_VERSION,
        },
        "cryptoProfileId": crypto_profile_id,
        "noncePolicyId": parsed.metadata.nonce_policy_id,
        "nonceMode": parsed.metadata.nonce_mode,
        "counterBits": parsed.metadata.counter_bits,
        "maxChunkCount": parsed.metadata.max_chunk_count,
        "aadPolicyId": aad_policy_id,
        "n": n,
        "k": k,
        "m": m,
        "t": t,
        "rsEncodeBase": RS_MAX_CODEWORD,
        "chunkSize": chunk_size,
        "chunkCount": total_chunks,
        "containerId": container_id,
        "containerHash": container_hash,
        "encapBlobHash": hex::encode(sha3_512(&parsed.encapsulated_key)),
        "privateKeyHash": private_key_hash_hex,
        "payloadLength": parsed.metadata.payload_length,
        "originalLength": effective_length,
        "ciphertextLength": ciphertext_length,
        "domainStrings": {
            "kdf": parsed.metadata.domain_strings.kdf,
            "iv": parsed.metadata.domain_strings.iv,
            "kenc": parsed.metadata.domain_strings.kenc,
            "kiv": parsed.metadata.domain_strings.kiv,
        },
        "fragmentFormat": "len32-prefixed",
        "perFragmentSize": per_fragment_size,
        "hasKeyCommitment": true,
        "keyCommitmentHex": hex::encode(key_commitment),
        "shardIndex": shard_index
    })
}
