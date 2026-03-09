use serde::{Deserialize, Serialize};

use crate::auth::{AuthPolicy, AuthPolicyLevel};
use crate::bytes::bytes_equal;
use crate::error::{err, Result};
use crate::hash::sha3_512_hex;
use crate::manifest::bundle::compute_auth_policy_commitment;
use crate::manifest::jcs::{canonicalize_json, canonicalize_json_to_bytes};
use crate::policy::{
    assert_chunk_count_within_policy, get_crypto_profile, get_nonce_contract_for_aead_mode,
    CryptoProfile, CRYPTO_PROFILE_ID_V2,
};

pub const ARCHIVE_MANIFEST_SCHEMA: &str = "quantum-vault-archive-manifest/v2";
pub const ARCHIVE_MANIFEST_VERSION: u64 = 2;
pub const LEGACY_ARCHIVE_MANIFEST_SCHEMA: &str = "quantum-vault-archive-manifest/v1";
pub const LEGACY_ARCHIVE_MANIFEST_VERSION: u64 = 1;
pub const QV_CANONICALIZATION_LABEL: &str = "QV-C14N-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthPolicyCommitment {
    pub alg: String,
    pub canonicalization: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveManifest {
    pub schema: String,
    pub version: u64,
    #[serde(rename = "manifestType")]
    pub manifest_type: String,
    pub canonicalization: String,
    #[serde(rename = "cryptoProfileId")]
    pub crypto_profile_id: String,
    #[serde(rename = "kdfTreeId")]
    pub kdf_tree_id: String,
    #[serde(rename = "noncePolicyId")]
    pub nonce_policy_id: String,
    #[serde(rename = "nonceMode")]
    pub nonce_mode: String,
    #[serde(rename = "counterBits")]
    pub counter_bits: u32,
    #[serde(rename = "maxChunkCount")]
    pub max_chunk_count: u64,
    #[serde(rename = "aadPolicyId")]
    pub aad_policy_id: String,
    pub qenc: ArchiveManifestQenc,
    pub sharding: ArchiveManifestSharding,
    #[serde(rename = "authPolicyCommitment")]
    pub auth_policy_commitment: AuthPolicyCommitment,
    #[serde(
        rename = "shardBinding",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub shard_binding: Option<ArchiveManifestShardBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveManifestQenc {
    pub format: String,
    #[serde(rename = "aeadMode")]
    pub aead_mode: String,
    #[serde(rename = "ivStrategy")]
    pub iv_strategy: String,
    #[serde(rename = "chunkSize")]
    pub chunk_size: u64,
    #[serde(rename = "chunkCount")]
    pub chunk_count: u64,
    #[serde(rename = "payloadLength")]
    pub payload_length: u64,
    #[serde(rename = "hashAlg")]
    pub hash_alg: String,
    #[serde(rename = "qencHash")]
    pub qenc_hash: String,
    #[serde(rename = "primaryAnchor")]
    pub primary_anchor: String,
    #[serde(rename = "containerId")]
    pub container_id: String,
    #[serde(rename = "containerIdRole")]
    pub container_id_role: String,
    #[serde(rename = "containerIdAlg")]
    pub container_id_alg: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveManifestSharding {
    pub shamir: ArchiveManifestShamir,
    #[serde(rename = "reedSolomon")]
    pub reed_solomon: ArchiveManifestReedSolomon,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveManifestShamir {
    pub threshold: u64,
    #[serde(rename = "shareCount")]
    pub share_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveManifestReedSolomon {
    pub n: u64,
    pub k: u64,
    pub parity: u64,
    #[serde(rename = "codecId")]
    pub codec_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveManifestShardBinding {
    #[serde(rename = "bodyDefinitionId")]
    pub body_definition_id: String,
    #[serde(rename = "bodyDefinition")]
    pub body_definition: ArchiveManifestShardBodyDefinition,
    #[serde(rename = "shardBodyHashAlg")]
    pub shard_body_hash_alg: String,
    #[serde(
        rename = "shardBodyHashes",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub shard_body_hashes: Option<Vec<String>>,
    #[serde(
        rename = "shareCommitment",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub share_commitment: Option<ArchiveManifestShareCommitment>,
    #[serde(
        rename = "shareCommitments",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub share_commitments: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveManifestShardBodyDefinition {
    pub includes: Vec<String>,
    pub excludes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveManifestShareCommitment {
    #[serde(rename = "hashAlg")]
    pub hash_alg: String,
    pub input: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveManifestCanonicalized {
    pub canonical: String,
    pub bytes: Vec<u8>,
    pub digest_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedArchiveManifest {
    pub manifest: ArchiveManifest,
    pub canonical: String,
    pub bytes: Vec<u8>,
    pub digest_hex: String,
    pub profile: CryptoProfile,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildArchiveManifestParams {
    pub crypto_profile_id: Option<String>,
    pub qenc_format: String,
    pub aead_mode: String,
    pub iv_strategy: String,
    pub nonce_policy_id: Option<String>,
    pub nonce_mode: Option<String>,
    pub counter_bits: Option<u32>,
    pub max_chunk_count: Option<u64>,
    pub chunk_size: u64,
    pub chunk_count: u64,
    pub payload_length: u64,
    pub qenc_hash: String,
    pub container_id: String,
    pub shamir_threshold: u64,
    pub shamir_share_count: u64,
    pub rs_n: u64,
    pub rs_k: u64,
    pub rs_parity: u64,
    pub rs_codec_id: Option<String>,
    pub shard_body_hashes: Option<Vec<String>>,
    pub share_commitments: Option<Vec<String>>,
    pub auth_policy_level: AuthPolicyLevel,
    pub min_valid_signatures: u64,
}

pub fn build_archive_manifest(params: &BuildArchiveManifestParams) -> Result<ArchiveManifest> {
    let profile = get_crypto_profile(
        params
            .crypto_profile_id
            .as_deref()
            .or(Some(CRYPTO_PROFILE_ID_V2)),
    )?;
    let nonce_contract = get_nonce_contract_for_aead_mode(&params.aead_mode)?;

    let nonce_policy_id = params
        .nonce_policy_id
        .clone()
        .unwrap_or_else(|| nonce_contract.nonce_policy_id.to_string());
    let nonce_mode = params
        .nonce_mode
        .clone()
        .unwrap_or_else(|| nonce_contract.nonce_mode.to_string());
    let counter_bits = params.counter_bits.unwrap_or(nonce_contract.counter_bits);
    let max_chunk_count = params
        .max_chunk_count
        .unwrap_or(nonce_contract.max_chunk_count);

    if nonce_policy_id != nonce_contract.nonce_policy_id {
        return Err(err(format!(
            "noncePolicyId does not match AEAD mode {}",
            params.aead_mode
        )));
    }
    if nonce_mode != nonce_contract.nonce_mode {
        return Err(err(format!(
            "nonceMode does not match AEAD mode {}",
            params.aead_mode
        )));
    }
    if counter_bits != nonce_contract.counter_bits {
        return Err(err(format!(
            "counterBits does not match AEAD mode {}",
            params.aead_mode
        )));
    }
    if max_chunk_count != nonce_contract.max_chunk_count {
        return Err(err(format!(
            "maxChunkCount does not match AEAD mode {}",
            params.aead_mode
        )));
    }

    assert_chunk_count_within_policy(params.chunk_count, &params.aead_mode)?;
    let auth_policy = AuthPolicy {
        level: params.auth_policy_level,
        min_valid_signatures: params.min_valid_signatures.max(1),
    };

    let mut manifest = ArchiveManifest {
        schema: ARCHIVE_MANIFEST_SCHEMA.to_string(),
        version: ARCHIVE_MANIFEST_VERSION,
        manifest_type: "archive".to_string(),
        canonicalization: QV_CANONICALIZATION_LABEL.to_string(),
        crypto_profile_id: profile.crypto_profile_id.to_string(),
        kdf_tree_id: profile.kdf_tree_id.to_string(),
        nonce_policy_id,
        nonce_mode,
        counter_bits,
        max_chunk_count,
        aad_policy_id: profile.aad_policy_id.to_string(),
        qenc: ArchiveManifestQenc {
            format: params.qenc_format.clone(),
            aead_mode: params.aead_mode.clone(),
            iv_strategy: params.iv_strategy.clone(),
            chunk_size: params.chunk_size,
            chunk_count: params.chunk_count,
            payload_length: params.payload_length,
            hash_alg: "SHA3-512".to_string(),
            qenc_hash: params.qenc_hash.clone(),
            primary_anchor: "qencHash".to_string(),
            container_id: params.container_id.clone(),
            container_id_role: "secondary-header-id".to_string(),
            container_id_alg: "SHA3-512(qenc-header-bytes)".to_string(),
        },
        sharding: ArchiveManifestSharding {
            shamir: ArchiveManifestShamir {
                threshold: params.shamir_threshold,
                share_count: params.shamir_share_count,
            },
            reed_solomon: ArchiveManifestReedSolomon {
                n: params.rs_n,
                k: params.rs_k,
                parity: params.rs_parity,
                codec_id: params
                    .rs_codec_id
                    .clone()
                    .unwrap_or_else(|| "QV-RS-ErasureCodes-v1".to_string()),
            },
        },
        auth_policy_commitment: compute_auth_policy_commitment(&auth_policy)?,
        shard_binding: None,
    };

    let has_shard_hashes = params
        .shard_body_hashes
        .as_ref()
        .map(|values| !values.is_empty())
        .unwrap_or(false);
    let has_share_commitments = params
        .share_commitments
        .as_ref()
        .map(|values| !values.is_empty())
        .unwrap_or(false);
    if has_shard_hashes || has_share_commitments {
        manifest.shard_binding = Some(ArchiveManifestShardBinding {
            body_definition_id: "QV-QCONT-SHARDBODY-v1".to_string(),
            body_definition: ArchiveManifestShardBodyDefinition {
                includes: vec!["fragment-len32-stream".to_string()],
                excludes: vec![
                    "qcont-header".to_string(),
                    "embedded-manifest".to_string(),
                    "embedded-manifest-digest".to_string(),
                    "embedded-bundle".to_string(),
                    "embedded-bundle-digest".to_string(),
                    "external-signatures".to_string(),
                ],
            },
            shard_body_hash_alg: "SHA3-512".to_string(),
            shard_body_hashes: params.shard_body_hashes.clone(),
            share_commitment: if has_share_commitments {
                Some(ArchiveManifestShareCommitment {
                    hash_alg: "SHA3-512".to_string(),
                    input: "raw-shamir-share-bytes".to_string(),
                })
            } else {
                None
            },
            share_commitments: params.share_commitments.clone(),
        });
    }

    Ok(manifest)
}

pub fn canonicalize_archive_manifest(
    manifest: &ArchiveManifest,
) -> Result<ArchiveManifestCanonicalized> {
    let canonical = canonicalize_json(manifest)?;
    let bytes = canonicalize_json_to_bytes(manifest)?;
    let digest_hex = sha3_512_hex(&bytes);
    Ok(ArchiveManifestCanonicalized {
        canonical,
        bytes,
        digest_hex,
    })
}

fn ensure_hash_list(values: &[String], field: &str) -> Result<Vec<String>> {
    if values.is_empty() {
        return Err(err(format!("Invalid {field}")));
    }
    let mut out = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        if value.is_empty() || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return Err(err(format!("Invalid {field}[{index}]")));
        }
        out.push(value.to_ascii_lowercase());
    }
    Ok(out)
}

pub fn parse_archive_manifest_bytes(manifest_bytes: &[u8]) -> Result<ParsedArchiveManifest> {
    let manifest: ArchiveManifest = serde_json::from_slice(manifest_bytes)
        .map_err(|error| err(format!("Invalid manifest JSON: {error}")))?;

    let canonicalized = canonicalize_archive_manifest(&manifest)?;
    if !bytes_equal(manifest_bytes, &canonicalized.bytes) {
        return Err(err(format!(
            "Manifest is not {QV_CANONICALIZATION_LABEL} canonical JSON"
        )));
    }

    if manifest.schema == LEGACY_ARCHIVE_MANIFEST_SCHEMA
        && manifest.version == LEGACY_ARCHIVE_MANIFEST_VERSION
    {
        return Err(err(
            "Legacy archive manifest format is not supported. Rebuild the archive with the new manifest bundle format.",
        ));
    }
    if manifest.schema != ARCHIVE_MANIFEST_SCHEMA
        || manifest.version != ARCHIVE_MANIFEST_VERSION
        || manifest.manifest_type != "archive"
    {
        return Err(err("Unsupported archive manifest schema/version"));
    }
    if manifest.canonicalization != QV_CANONICALIZATION_LABEL {
        return Err(err("Unsupported manifest canonicalization"));
    }

    let profile = get_crypto_profile(Some(&manifest.crypto_profile_id))?;
    if manifest.kdf_tree_id != profile.kdf_tree_id {
        return Err(err(format!(
            "Manifest kdfTreeId does not match profile ({})",
            profile.kdf_tree_id
        )));
    }
    if manifest.aad_policy_id != profile.aad_policy_id {
        return Err(err(format!(
            "Manifest aadPolicyId does not match profile ({})",
            profile.aad_policy_id
        )));
    }

    let nonce_contract = get_nonce_contract_for_aead_mode(&manifest.qenc.aead_mode)?;
    if manifest.nonce_policy_id != nonce_contract.nonce_policy_id {
        return Err(err(format!(
            "Manifest noncePolicyId does not match AEAD mode {}",
            manifest.qenc.aead_mode
        )));
    }
    if manifest.nonce_mode != nonce_contract.nonce_mode {
        return Err(err(format!(
            "Manifest nonceMode does not match AEAD mode {}",
            manifest.qenc.aead_mode
        )));
    }
    if manifest.counter_bits != nonce_contract.counter_bits {
        return Err(err(format!(
            "Manifest counterBits does not match AEAD mode {}",
            manifest.qenc.aead_mode
        )));
    }
    if manifest.max_chunk_count != nonce_contract.max_chunk_count {
        return Err(err(format!(
            "Manifest maxChunkCount does not match AEAD mode {}",
            manifest.qenc.aead_mode
        )));
    }

    assert_chunk_count_within_policy(manifest.qenc.chunk_count, &manifest.qenc.aead_mode)?;
    if manifest.qenc.qenc_hash.is_empty() {
        return Err(err("Invalid qenc.qencHash"));
    }
    if manifest.qenc.container_id.is_empty() {
        return Err(err("Invalid qenc.containerId"));
    }
    if manifest.qenc.hash_alg != "SHA3-512" {
        return Err(err("Unsupported qenc.hashAlg"));
    }
    if manifest.qenc.primary_anchor != "qencHash" {
        return Err(err("Unsupported qenc.primaryAnchor"));
    }
    if manifest.qenc.container_id_role != "secondary-header-id" {
        return Err(err("Unsupported qenc.containerIdRole"));
    }
    if manifest.qenc.container_id_alg != "SHA3-512(qenc-header-bytes)" {
        return Err(err("Unsupported qenc.containerIdAlg"));
    }

    let _ =
        crate::manifest::validate_auth_policy_commitment_shape(&manifest.auth_policy_commitment)?;

    if let Some(shard_binding) = &manifest.shard_binding {
        if shard_binding.body_definition_id != "QV-QCONT-SHARDBODY-v1" {
            return Err(err("Unsupported shardBinding.bodyDefinitionId"));
        }
        if shard_binding.shard_body_hash_alg != "SHA3-512" {
            return Err(err("Unsupported shardBinding.shardBodyHashAlg"));
        }
        if shard_binding.body_definition.includes.is_empty()
            || shard_binding.body_definition.excludes.is_empty()
        {
            return Err(err("Invalid shardBinding.bodyDefinition"));
        }
        if let Some(values) = &shard_binding.shard_body_hashes {
            let _ = ensure_hash_list(values, "shardBinding.shardBodyHashes")?;
        }
        if let Some(values) = &shard_binding.share_commitments {
            let _ = ensure_hash_list(values, "shardBinding.shareCommitments")?;
            if shard_binding.share_commitment.as_ref().map(|value| {
                value.hash_alg.as_str() == "SHA3-512"
                    && value.input.as_str() == "raw-shamir-share-bytes"
            }) != Some(true)
            {
                return Err(err("Invalid shardBinding.shareCommitment descriptor"));
            }
        }
        if shard_binding.shard_body_hashes.is_none() && shard_binding.share_commitments.is_none() {
            return Err(err(
                "Invalid shardBinding: expected shardBodyHashes or shareCommitments",
            ));
        }
    }

    Ok(ParsedArchiveManifest {
        manifest,
        canonical: canonicalized.canonical,
        bytes: canonicalized.bytes,
        digest_hex: canonicalized.digest_hex,
        profile,
    })
}
