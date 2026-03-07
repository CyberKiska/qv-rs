use serde::{Deserialize, Serialize};

use crate::bytes::bytes_equal;
use crate::error::{err, Result};
use crate::hash::sha3_512_hex;
use crate::manifest::jcs::{canonicalize_json, canonicalize_json_to_bytes};
use crate::policy::{
    get_crypto_profile, get_nonce_contract_for_aead_mode, AAD_POLICY_ID_V1, CRYPTO_PROFILE_ID_V2,
    KDF_TREE_ID_V2, NONCE_POLICY_PER_CHUNK_V3,
};

const MANIFEST_SCHEMA: &str = "quantum-vault-archive-manifest/v1";
const MANIFEST_VERSION: u64 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveManifest {
    pub schema: String,
    pub version: u64,
    #[serde(rename = "manifestType")]
    pub manifest_type: String,
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
    #[serde(rename = "signingPolicy")]
    pub signing_policy: ArchiveManifestSigningPolicy,
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
pub struct ArchiveManifestSigningPolicy {
    #[serde(rename = "requireSignature")]
    pub require_signature: bool,
    #[serde(rename = "acceptedAlgorithms")]
    pub accepted_algorithms: Vec<String>,
    #[serde(rename = "allowLegacyEd25519")]
    pub allow_legacy_ed25519: bool,
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

pub fn parse_archive_manifest_bytes(manifest_bytes: &[u8]) -> Result<ParsedArchiveManifest> {
    let manifest: ArchiveManifest = serde_json::from_slice(manifest_bytes)
        .map_err(|error| err(format!("Invalid manifest JSON: {error}")))?;

    let canonicalized = canonicalize_archive_manifest(&manifest)?;
    if !bytes_equal(manifest_bytes, &canonicalized.bytes) {
        return Err(err("Manifest is not RFC-8785 canonical JSON"));
    }

    if manifest.schema != MANIFEST_SCHEMA
        || manifest.version != MANIFEST_VERSION
        || manifest.manifest_type != "archive"
    {
        return Err(err("Unsupported archive manifest schema/version"));
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

    if let Some(shard_binding) = &manifest.shard_binding {
        if shard_binding.body_definition_id != "QV-QCONT-SHARDBODY-v1" {
            return Err(err("Unsupported shardBinding.bodyDefinitionId"));
        }
        if shard_binding.shard_body_hash_alg != "SHA3-512" {
            return Err(err("Unsupported shardBinding.shardBodyHashAlg"));
        }
        let has_shard_hashes = shard_binding
            .shard_body_hashes
            .as_ref()
            .map(|hashes| !hashes.is_empty())
            .unwrap_or(false);
        let has_share_commitments = shard_binding
            .share_commitments
            .as_ref()
            .map(|hashes| !hashes.is_empty())
            .unwrap_or(false);
        if !has_shard_hashes && !has_share_commitments {
            return Err(err(
                "Invalid shardBinding: expected shardBodyHashes or shareCommitments",
            ));
        }
        if let Some(share_commitment) = &shard_binding.share_commitment {
            if share_commitment.hash_alg != "SHA3-512"
                || share_commitment.input != "raw-shamir-share-bytes"
            {
                return Err(err("Invalid shardBinding.shareCommitment descriptor"));
            }
        } else if has_share_commitments {
            return Err(err("Invalid shardBinding.shareCommitment descriptor"));
        }
    }

    Ok(ParsedArchiveManifest {
        manifest,
        canonical: canonicalized.canonical,
        bytes: canonicalized.bytes,
        digest_hex: canonicalized.digest_hex,
    })
}

pub const ARCHIVE_MANIFEST_DEFAULT_CRYPTO_PROFILE_ID: &str = CRYPTO_PROFILE_ID_V2;
pub const ARCHIVE_MANIFEST_DEFAULT_KDF_TREE_ID: &str = KDF_TREE_ID_V2;
pub const ARCHIVE_MANIFEST_DEFAULT_NONCE_POLICY_ID: &str = NONCE_POLICY_PER_CHUNK_V3;
pub const ARCHIVE_MANIFEST_DEFAULT_AAD_POLICY_ID: &str = AAD_POLICY_ID_V1;
