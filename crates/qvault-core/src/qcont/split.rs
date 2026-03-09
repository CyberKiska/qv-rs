use crate::auth::{AuthPolicy, AuthPolicyLevel};
use crate::bytes::to_hex;
use crate::erasure;
use crate::error::{err, Result};
use crate::hash::{sha3_512, sha3_512_hex};
use crate::kdf::{derive_key_with_kmac, verify_key_commitment};
use crate::manifest::{
    build_archive_manifest, build_initial_manifest_bundle, canonicalize_archive_manifest,
    canonicalize_manifest_bundle, ArchiveManifest, BuildArchiveManifestParams, ManifestBundle,
};
use crate::mlkem::decapsulate;
use crate::policy::DEFAULT_CRYPTO_PROFILE;
use crate::qcont::shard::{
    QcontShardAlgorithmMetadata, QcontShardDomainStrings, QcontShardMetadata, QCONT_FORMAT_VERSION,
};
use crate::qenc::{current_iso8601_utc_millis, parse_qenc_header, CHUNK_SIZE};
use crate::sss::split_secret;
use zeroize::Zeroize;

const QCONT_MAGIC: &[u8; 4] = b"QVC1";
const RS_MAX_CODEWORD: usize = 255;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QcontBuildParams {
    pub n: u16,
    pub k: u16,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QcontBuildOptions {
    pub timestamp: Option<String>,
    pub sss_random_bytes: Option<Vec<u8>>,
    pub auth_policy_level: Option<AuthPolicyLevel>,
    pub min_valid_signatures: Option<u64>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct BuiltQcontShard {
    pub bytes: Vec<u8>,
    pub index: u16,
}

impl std::fmt::Debug for BuiltQcontShard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BuiltQcontShard")
            .field("index", &self.index)
            .field("bytes_len", &self.bytes.len())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct BuiltQcontShards {
    pub shards: Vec<BuiltQcontShard>,
    pub manifest: ArchiveManifest,
    pub bundle: ManifestBundle,
    pub manifest_bytes: Vec<u8>,
    pub manifest_digest_hex: String,
    pub bundle_bytes: Vec<u8>,
    pub bundle_digest_hex: String,
    pub format_version: String,
}

impl std::fmt::Debug for BuiltQcontShards {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BuiltQcontShards")
            .field("shard_count", &self.shards.len())
            .field("manifest_digest_hex", &self.manifest_digest_hex)
            .field("bundle_digest_hex", &self.bundle_digest_hex)
            .field("format_version", &self.format_version)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct QcontShardBlobParams<'a> {
    pub meta_json_bytes: &'a [u8],
    pub manifest_bytes: &'a [u8],
    pub bundle_bytes: &'a [u8],
    pub encapsulated_key: &'a [u8],
    pub container_nonce: &'a [u8; 12],
    pub kdf_salt: &'a [u8; 16],
    pub qenc_meta_bytes: &'a [u8],
    pub key_commitment: &'a [u8; 32],
    pub shard_index: u16,
    pub share: &'a [u8],
    pub body_bytes: &'a [u8],
}

pub(crate) fn build_qcont_shard_blob(params: &QcontShardBlobParams<'_>) -> Vec<u8> {
    let manifest_digest_bytes = sha3_512(params.manifest_bytes);
    let bundle_digest_bytes = sha3_512(params.bundle_bytes);
    let mut shard = Vec::with_capacity(
        QCONT_MAGIC.len()
            + 2
            + params.meta_json_bytes.len()
            + 4
            + params.manifest_bytes.len()
            + manifest_digest_bytes.len()
            + 4
            + params.bundle_bytes.len()
            + bundle_digest_bytes.len()
            + 4
            + params.encapsulated_key.len()
            + 12
            + 16
            + 2
            + params.qenc_meta_bytes.len()
            + 1
            + params.key_commitment.len()
            + 2
            + 2
            + params.share.len()
            + params.body_bytes.len(),
    );

    shard.extend_from_slice(QCONT_MAGIC);
    shard.extend_from_slice(&(params.meta_json_bytes.len() as u16).to_be_bytes());
    shard.extend_from_slice(params.meta_json_bytes);
    shard.extend_from_slice(&(params.manifest_bytes.len() as u32).to_be_bytes());
    shard.extend_from_slice(params.manifest_bytes);
    shard.extend_from_slice(&manifest_digest_bytes);
    shard.extend_from_slice(&(params.bundle_bytes.len() as u32).to_be_bytes());
    shard.extend_from_slice(params.bundle_bytes);
    shard.extend_from_slice(&bundle_digest_bytes);
    shard.extend_from_slice(&(params.encapsulated_key.len() as u32).to_be_bytes());
    shard.extend_from_slice(params.encapsulated_key);
    shard.extend_from_slice(params.container_nonce);
    shard.extend_from_slice(params.kdf_salt);
    shard.extend_from_slice(&(params.qenc_meta_bytes.len() as u16).to_be_bytes());
    shard.extend_from_slice(params.qenc_meta_bytes);
    shard.push(params.key_commitment.len() as u8);
    shard.extend_from_slice(params.key_commitment);
    shard.extend_from_slice(&params.shard_index.to_be_bytes());
    shard.extend_from_slice(&(params.share.len() as u16).to_be_bytes());
    shard.extend_from_slice(params.share);
    shard.extend_from_slice(params.body_bytes);
    shard
}

pub fn build_qcont_shards(
    qenc_bytes: &[u8],
    priv_key_bytes: &[u8],
    params: QcontBuildParams,
    options: &QcontBuildOptions,
) -> Result<BuiltQcontShards> {
    let n = usize::from(params.n);
    let k = usize::from(params.k);
    if k < 2 || n <= k {
        return Err(err("Invalid RS parameters: require 2 <= k < n"));
    }
    let Some(m) = n.checked_sub(k) else {
        return Err(err("Invalid RS parameters: require 2 <= k < n"));
    };
    if (m % 2) != 0 {
        return Err(err("n-k must be even"));
    }

    let parsed = parse_qenc_header(qenc_bytes)?;
    let key_commitment = parsed.stored_key_commitment;
    let ciphertext = &qenc_bytes[parsed.offset..];
    if key_commitment.len() != 32 {
        return Err(err(
            "QENC container is missing required 32-byte key commitment.",
        ));
    }

    let ds = &parsed.metadata.domain_strings;
    if ds.kdf.is_empty() || ds.iv.is_empty() || ds.kenc.is_empty() || ds.kiv.is_empty() {
        return Err(err("QENC metadata is missing valid domainStrings"));
    }

    {
        let mut trial_shared_secret = decapsulate(&parsed.encapsulated_key, priv_key_bytes)
            .map_err(|error| err(format!("Key verification failed: {error}")))?;
        let derived = derive_key_with_kmac(
            &trial_shared_secret,
            &parsed.kdf_salt,
            &parsed.meta_bytes,
            ds,
        )
        .map_err(|error| err(format!("Key verification failed: {error}")))?;
        let key_match = verify_key_commitment(&derived.kenc, &key_commitment);
        trial_shared_secret.zeroize();
        if !key_match {
            return Err(err(
                "Secret key does not match this .qenc container (key commitment mismatch). Ensure you are using the correct secretKey.qkey for this container.",
            ));
        }
    }

    let effective_length = parsed
        .metadata
        .payload_length
        .ok_or_else(|| err("QENC metadata is missing payloadLength"))?;
    let container_id = sha3_512_hex(&parsed.header);
    let container_hash = sha3_512_hex(qenc_bytes);

    let t = k + (m / 2);
    if t > n {
        return Err(err("Invalid threshold computed"));
    }
    let shares = split_secret(priv_key_bytes, n, t, options.sss_random_bytes.as_deref())?;
    let share_commitments = shares
        .iter()
        .map(|share| sha3_512_hex(share))
        .collect::<Vec<_>>();

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
    let mut ciphertext_offset = 0usize;
    let mut per_fragment_size = 0usize;
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
        if i == 0 {
            per_fragment_size = fragments[0].len();
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

    let fragment_body_hashes = shard_bodies
        .iter()
        .map(|body| sha3_512_hex(body))
        .collect::<Vec<_>>();

    let timestamp = options
        .timestamp
        .clone()
        .unwrap_or_else(current_iso8601_utc_millis);
    let auth_policy_level = options
        .auth_policy_level
        .unwrap_or(AuthPolicyLevel::StrongPqSignature);
    let min_valid_signatures = options.min_valid_signatures.unwrap_or(1).max(1);

    let manifest = build_archive_manifest(&BuildArchiveManifestParams {
        crypto_profile_id: parsed.metadata.crypto_profile_id.clone(),
        qenc_format: parsed.metadata.fmt.clone(),
        aead_mode: parsed.metadata.aead_mode.clone(),
        iv_strategy: parsed.metadata.iv_strategy.clone(),
        nonce_policy_id: Some(parsed.metadata.nonce_policy_id.clone()),
        nonce_mode: Some(parsed.metadata.nonce_mode.clone()),
        counter_bits: Some(parsed.metadata.counter_bits),
        max_chunk_count: Some(parsed.metadata.max_chunk_count),
        chunk_size,
        chunk_count: total_chunks,
        payload_length: parsed.metadata.payload_length.unwrap_or(effective_length),
        qenc_hash: container_hash.clone(),
        container_id: container_id.clone(),
        shamir_threshold: t as u64,
        shamir_share_count: n as u64,
        rs_n: n as u64,
        rs_k: k as u64,
        rs_parity: m as u64,
        rs_codec_id: Some("QV-RS-ErasureCodes-v1".to_string()),
        shard_body_hashes: Some(fragment_body_hashes.clone()),
        share_commitments: Some(share_commitments.clone()),
        auth_policy_level,
        min_valid_signatures,
    })?;
    let canonical_manifest = canonicalize_archive_manifest(&manifest)?;
    let manifest_bytes = canonical_manifest.bytes.clone();
    let manifest_digest_hex = canonical_manifest.digest_hex.clone();

    let initial_bundle = build_initial_manifest_bundle(
        &manifest,
        &AuthPolicy {
            level: auth_policy_level,
            min_valid_signatures,
        },
    )?;
    let canonical_bundle = canonicalize_manifest_bundle(&initial_bundle)?;
    let bundle_bytes = canonical_bundle.bytes.clone();
    let bundle_digest_hex = canonical_bundle.digest_hex.clone();

    let meta_json = QcontShardMetadata {
        container_id: container_id.clone(),
        alg: QcontShardAlgorithmMetadata {
            kem: "ML-KEM-1024".to_string(),
            kdf: "KMAC256".to_string(),
            aead: "AES-256-GCM".to_string(),
            rs: "ErasureCodes".to_string(),
            fmt: QCONT_FORMAT_VERSION.to_string(),
        },
        aead_mode: if is_per_chunk {
            "per-chunk".to_string()
        } else {
            "single-container".to_string()
        },
        iv_strategy: parsed.metadata.iv_strategy.clone(),
        crypto_profile_id: parsed
            .metadata
            .crypto_profile_id
            .clone()
            .unwrap_or_else(|| DEFAULT_CRYPTO_PROFILE.crypto_profile_id.to_string()),
        nonce_policy_id: parsed.metadata.nonce_policy_id.clone(),
        nonce_mode: parsed.metadata.nonce_mode.clone(),
        counter_bits: parsed.metadata.counter_bits,
        max_chunk_count: parsed.metadata.max_chunk_count,
        aad_policy_id: parsed
            .metadata
            .aad_policy_id
            .clone()
            .unwrap_or_else(|| DEFAULT_CRYPTO_PROFILE.aad_policy_id.to_string()),
        n: n as u64,
        k: k as u64,
        m: m as u64,
        t: t as u64,
        rs_encode_base: RS_MAX_CODEWORD as u64,
        chunk_size,
        chunk_count: total_chunks,
        container_hash: container_hash.clone(),
        encap_blob_hash: sha3_512_hex(&parsed.encapsulated_key),
        private_key_hash: sha3_512_hex(priv_key_bytes),
        payload_length: parsed.metadata.payload_length,
        original_length: effective_length,
        ciphertext_length: ciphertext.len() as u64,
        domain_strings: QcontShardDomainStrings {
            kdf: ds.kdf.clone(),
            iv: ds.iv.clone(),
            kenc: ds.kenc.clone(),
            kiv: ds.kiv.clone(),
        },
        fragment_format: "len32-prefixed".to_string(),
        per_fragment_size: per_fragment_size as u64,
        has_key_commitment: true,
        key_commitment_hex: to_hex(&key_commitment),
        has_embedded_manifest: true,
        manifest_digest: manifest_digest_hex.clone(),
        has_embedded_bundle: true,
        bundle_digest: bundle_digest_hex.clone(),
        auth_policy_level: initial_bundle.auth_policy.level,
        share_commitments: Some(share_commitments.clone()),
        fragment_body_hashes: Some(fragment_body_hashes.clone()),
        timestamp,
    };
    let meta_json_bytes = serde_json::to_vec(&meta_json)?;

    let mut shards = Vec::with_capacity(n);
    for j in 0..n {
        let shard_bytes = build_qcont_shard_blob(&QcontShardBlobParams {
            meta_json_bytes: &meta_json_bytes,
            manifest_bytes: &manifest_bytes,
            bundle_bytes: &bundle_bytes,
            encapsulated_key: &parsed.encapsulated_key,
            container_nonce: &parsed.container_nonce,
            kdf_salt: &parsed.kdf_salt,
            qenc_meta_bytes: &parsed.meta_bytes,
            key_commitment: &key_commitment,
            shard_index: j as u16,
            share: &shares[j],
            body_bytes: &shard_bodies[j],
        });
        shards.push(BuiltQcontShard {
            bytes: shard_bytes,
            index: j as u16,
        });
    }

    Ok(BuiltQcontShards {
        shards,
        manifest,
        bundle: initial_bundle,
        manifest_bytes,
        manifest_digest_hex,
        bundle_bytes,
        bundle_digest_hex,
        format_version: QCONT_FORMAT_VERSION.to_string(),
    })
}
