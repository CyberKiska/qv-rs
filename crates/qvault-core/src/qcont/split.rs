use crate::bytes::to_hex;
use crate::erasure;
use crate::error::{err, Result};
use crate::hash::{sha3_512, sha3_512_hex};
use crate::kdf::{derive_key_with_kmac, verify_key_commitment};
use crate::manifest::{
    canonicalize_archive_manifest, ArchiveManifest, ArchiveManifestQenc,
    ArchiveManifestReedSolomon, ArchiveManifestShamir, ArchiveManifestShardBinding,
    ArchiveManifestShardBodyDefinition, ArchiveManifestSharding, ArchiveManifestShareCommitment,
    ArchiveManifestSigningPolicy,
};
use crate::mlkem::decapsulate;
use crate::policy::{get_crypto_profile, DEFAULT_CRYPTO_PROFILE};
use crate::qcont::shard::{
    QcontShardAlgorithmMetadata, QcontShardDomainStrings, QcontShardMetadata,
};
use crate::qenc::{current_iso8601_utc_millis, parse_qenc_header, CHUNK_SIZE};
use crate::sss::split_secret;

const QCONT_MAGIC: &[u8; 4] = b"QVC1";
const QCONT_FORMAT_VERSION: &str = "QVqcont-5";
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
    pub require_signature: Option<bool>,
    pub allow_legacy_ed25519: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltQcontShard {
    pub bytes: Vec<u8>,
    pub index: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltQcontShards {
    pub shards: Vec<BuiltQcontShard>,
    pub manifest: ArchiveManifest,
    pub manifest_bytes: Vec<u8>,
    pub manifest_digest_hex: String,
    pub format_version: String,
}

pub fn build_qcont_shards(
    qenc_bytes: &[u8],
    priv_key_bytes: &[u8],
    params: QcontBuildParams,
    options: &QcontBuildOptions,
) -> Result<BuiltQcontShards> {
    let n = usize::from(params.n);
    let k = usize::from(params.k);
    let m = n - k;
    if k < 2 || n <= k {
        return Err(err("Invalid RS parameters: require 2 <= k < n"));
    }
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

    let trial_shared_secret = decapsulate(&parsed.encapsulated_key, priv_key_bytes)
        .map_err(|error| err(format!("Key verification failed: {error}")))?;
    let derived = derive_key_with_kmac(
        &trial_shared_secret,
        &parsed.kdf_salt,
        &parsed.meta_bytes,
        ds,
    )
    .map_err(|error| err(format!("Key verification failed: {error}")))?;
    let key_match = verify_key_commitment(&derived.kenc, &key_commitment);
    if !key_match {
        return Err(err(
            "Secret key does not match this .qenc container (key commitment mismatch). Ensure you are using the correct secretKey.qkey for this container.",
        ));
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

    let mut shard_buffers = vec![Vec::new(); n];
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
    for i in 0..total_chunks {
        let cipher_chunk = if is_per_chunk {
            let plain_len = chunk_size.min(effective_length - (i * chunk_size)) as usize;
            let enc_len = plain_len + 16;
            let chunk = &ciphertext[ciphertext_offset..ciphertext_offset + enc_len];
            ciphertext_offset += enc_len;
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
            shard_buffers[j].extend_from_slice(&(fragment.len() as u32).to_be_bytes());
            shard_buffers[j].extend_from_slice(fragment);
        }
    }

    let shard_body_bytes = shard_buffers;
    let fragment_body_hashes = shard_body_bytes
        .iter()
        .map(|body| sha3_512_hex(body))
        .collect::<Vec<_>>();

    let timestamp = options
        .timestamp
        .clone()
        .unwrap_or_else(current_iso8601_utc_millis);
    let profile = get_crypto_profile(parsed.metadata.crypto_profile_id.as_deref())?;
    let require_signature = options.require_signature.unwrap_or(false);
    let allow_legacy_ed25519 = options.allow_legacy_ed25519.unwrap_or(true);
    let accepted_algorithms = vec![
        "ML-DSA".to_string(),
        "SLH-DSA-SHAKE".to_string(),
        "Ed25519".to_string(),
    ];

    let manifest = ArchiveManifest {
        schema: "quantum-vault-archive-manifest/v1".to_string(),
        version: 1,
        manifest_type: "archive".to_string(),
        crypto_profile_id: parsed
            .metadata
            .crypto_profile_id
            .clone()
            .unwrap_or_else(|| DEFAULT_CRYPTO_PROFILE.crypto_profile_id.to_string()),
        kdf_tree_id: profile.kdf_tree_id.to_string(),
        nonce_policy_id: parsed.metadata.nonce_policy_id.clone(),
        nonce_mode: parsed.metadata.nonce_mode.clone(),
        counter_bits: parsed.metadata.counter_bits,
        max_chunk_count: parsed.metadata.max_chunk_count,
        aad_policy_id: profile.aad_policy_id.to_string(),
        qenc: ArchiveManifestQenc {
            format: parsed.metadata.fmt.clone(),
            aead_mode: parsed.metadata.aead_mode.clone(),
            iv_strategy: parsed.metadata.iv_strategy.clone(),
            chunk_size,
            chunk_count: total_chunks,
            payload_length: parsed.metadata.payload_length.unwrap_or(effective_length),
            hash_alg: "SHA3-512".to_string(),
            qenc_hash: container_hash.clone(),
            primary_anchor: "qencHash".to_string(),
            container_id: container_id.clone(),
            container_id_role: "secondary-header-id".to_string(),
            container_id_alg: "SHA3-512(qenc-header-bytes)".to_string(),
        },
        sharding: ArchiveManifestSharding {
            shamir: ArchiveManifestShamir {
                threshold: t as u64,
                share_count: n as u64,
            },
            reed_solomon: ArchiveManifestReedSolomon {
                n: n as u64,
                k: k as u64,
                parity: m as u64,
                codec_id: "QV-RS-ErasureCodes-v1".to_string(),
            },
        },
        signing_policy: ArchiveManifestSigningPolicy {
            require_signature,
            accepted_algorithms,
            allow_legacy_ed25519,
        },
        shard_binding: Some(ArchiveManifestShardBinding {
            body_definition_id: "QV-QCONT-SHARDBODY-v1".to_string(),
            body_definition: ArchiveManifestShardBodyDefinition {
                includes: vec!["fragment-len32-stream".to_string()],
                excludes: vec![
                    "qcont-header".to_string(),
                    "embedded-manifest".to_string(),
                    "embedded-manifest-digest".to_string(),
                    "external-signatures".to_string(),
                ],
            },
            shard_body_hash_alg: "SHA3-512".to_string(),
            shard_body_hashes: Some(fragment_body_hashes.clone()),
            share_commitment: Some(ArchiveManifestShareCommitment {
                hash_alg: "SHA3-512".to_string(),
                input: "raw-shamir-share-bytes".to_string(),
            }),
            share_commitments: Some(share_commitments.clone()),
        }),
    };
    let canonical_manifest = canonicalize_archive_manifest(&manifest)?;
    let manifest_bytes = canonical_manifest.bytes;
    let manifest_digest_hex = canonical_manifest.digest_hex;
    let manifest_digest_bytes = sha3_512(&manifest_bytes);

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
        share_commitments: Some(share_commitments),
        fragment_body_hashes: Some(fragment_body_hashes),
        timestamp,
    };
    let meta_json_bytes = serde_json::to_vec(&meta_json)?;

    let mut shards = Vec::with_capacity(n);
    for j in 0..n {
        let share = &shares[j];
        let body_bytes = &shard_body_bytes[j];
        let mut shard = Vec::with_capacity(
            QCONT_MAGIC.len()
                + 2
                + meta_json_bytes.len()
                + 4
                + manifest_bytes.len()
                + manifest_digest_bytes.len()
                + 4
                + parsed.encapsulated_key.len()
                + 12
                + 16
                + 2
                + parsed.meta_bytes.len()
                + 1
                + key_commitment.len()
                + 2
                + 2
                + share.len()
                + body_bytes.len(),
        );
        shard.extend_from_slice(QCONT_MAGIC);
        shard.extend_from_slice(&(meta_json_bytes.len() as u16).to_be_bytes());
        shard.extend_from_slice(&meta_json_bytes);
        shard.extend_from_slice(&(manifest_bytes.len() as u32).to_be_bytes());
        shard.extend_from_slice(&manifest_bytes);
        shard.extend_from_slice(&manifest_digest_bytes);
        shard.extend_from_slice(&(parsed.encapsulated_key.len() as u32).to_be_bytes());
        shard.extend_from_slice(&parsed.encapsulated_key);
        shard.extend_from_slice(&parsed.container_nonce);
        shard.extend_from_slice(&parsed.kdf_salt);
        shard.extend_from_slice(&(parsed.meta_bytes.len() as u16).to_be_bytes());
        shard.extend_from_slice(&parsed.meta_bytes);
        shard.push(key_commitment.len() as u8);
        shard.extend_from_slice(&key_commitment);
        shard.extend_from_slice(&(j as u16).to_be_bytes());
        shard.extend_from_slice(&(share.len() as u16).to_be_bytes());
        shard.extend_from_slice(share);
        shard.extend_from_slice(body_bytes);
        shards.push(BuiltQcontShard {
            bytes: shard,
            index: j as u16,
        });
    }

    Ok(BuiltQcontShards {
        shards,
        manifest,
        manifest_bytes,
        manifest_digest_hex,
        format_version: QCONT_FORMAT_VERSION.to_string(),
    })
}
