use serde::{Deserialize, Serialize};

use crate::aead::{NONCE_COUNTER_BITS_U32, NONCE_MAX_CHUNK_COUNT_U32};
use crate::error::{err, Result};
use crate::qenc::metadata::{DomainStrings, QencMetadata};

pub const CRYPTO_PROFILE_ID_V2: &str = "QV-MLKEM1024-KMAC256-AES256GCM-SHA3_512-v2";
pub const KDF_TREE_ID_V2: &str = "QV-KDF-TREE-v2";
pub const NONCE_POLICY_SINGLE_CONTAINER_V1: &str = "QV-GCM-RAND96-v1";
pub const NONCE_POLICY_PER_CHUNK_V3: &str = "QV-GCM-KMACPFX64-CTR32-v3";
pub const AAD_POLICY_ID_V1: &str = "QV-AAD-HEADER-CHUNK-v1";
pub const NONCE_MODE_RANDOM96: &str = "random96";
pub const NONCE_MODE_KMAC_CTR32: &str = "kmac-prefix64-ctr32";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonceContract {
    pub nonce_policy_id: &'static str,
    pub nonce_mode: &'static str,
    pub counter_bits: u32,
    pub max_chunk_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoProfile {
    pub crypto_profile_id: &'static str,
    pub kdf_tree_id: &'static str,
    pub aad_policy_id: &'static str,
    pub domain_strings: PolicyDomainStrings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyDomainStrings {
    pub kdf: &'static str,
    pub iv: &'static str,
    pub kenc: &'static str,
    pub kiv: &'static str,
}

pub const DEFAULT_CRYPTO_PROFILE: CryptoProfile = CryptoProfile {
    crypto_profile_id: CRYPTO_PROFILE_ID_V2,
    kdf_tree_id: KDF_TREE_ID_V2,
    aad_policy_id: AAD_POLICY_ID_V1,
    domain_strings: PolicyDomainStrings {
        kdf: "quantum-vault:kdf:v2",
        iv: "quantum-vault:chunk-iv:v2",
        kenc: "quantum-vault:kenc:v2",
        kiv: "quantum-vault:kiv:v2",
    },
};

pub const SINGLE_CONTAINER_NONCE_CONTRACT: NonceContract = NonceContract {
    nonce_policy_id: NONCE_POLICY_SINGLE_CONTAINER_V1,
    nonce_mode: NONCE_MODE_RANDOM96,
    counter_bits: 0,
    max_chunk_count: 1,
};

pub const PER_CHUNK_NONCE_CONTRACT: NonceContract = NonceContract {
    nonce_policy_id: NONCE_POLICY_PER_CHUNK_V3,
    nonce_mode: NONCE_MODE_KMAC_CTR32,
    counter_bits: NONCE_COUNTER_BITS_U32,
    max_chunk_count: NONCE_MAX_CHUNK_COUNT_U32,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyMetadataFields {
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
    #[serde(rename = "domainStrings")]
    pub domain_strings: DomainStrings,
}

pub fn get_crypto_profile(profile_id: Option<&str>) -> Result<CryptoProfile> {
    match profile_id.unwrap_or(CRYPTO_PROFILE_ID_V2) {
        CRYPTO_PROFILE_ID_V2 => Ok(DEFAULT_CRYPTO_PROFILE),
        other => Err(err(format!("Unsupported cryptoProfileId: {other}"))),
    }
}

pub fn get_nonce_contract_for_aead_mode(aead_mode: &str) -> Result<NonceContract> {
    match aead_mode {
        "single-container-aead" => Ok(SINGLE_CONTAINER_NONCE_CONTRACT),
        "per-chunk-aead" => Ok(PER_CHUNK_NONCE_CONTRACT),
        other => Err(err(format!(
            "Unsupported AEAD mode for nonce policy: {other}"
        ))),
    }
}

pub fn assert_chunk_count_within_policy(chunk_count: u64, aead_mode: &str) -> Result<()> {
    if chunk_count == 0 {
        return Err(err("chunkCount must be a positive integer"));
    }
    let nonce_contract = get_nonce_contract_for_aead_mode(aead_mode)?;
    if chunk_count > nonce_contract.max_chunk_count {
        return Err(err(format!(
            "chunkCount exceeds nonce policy bound ({})",
            nonce_contract.max_chunk_count
        )));
    }
    Ok(())
}

pub fn build_policy_metadata_fields(aead_mode: &str) -> Result<PolicyMetadataFields> {
    let nonce_contract = get_nonce_contract_for_aead_mode(aead_mode)?;
    Ok(PolicyMetadataFields {
        crypto_profile_id: DEFAULT_CRYPTO_PROFILE.crypto_profile_id.to_string(),
        kdf_tree_id: DEFAULT_CRYPTO_PROFILE.kdf_tree_id.to_string(),
        nonce_policy_id: nonce_contract.nonce_policy_id.to_string(),
        nonce_mode: nonce_contract.nonce_mode.to_string(),
        counter_bits: nonce_contract.counter_bits,
        max_chunk_count: nonce_contract.max_chunk_count,
        aad_policy_id: DEFAULT_CRYPTO_PROFILE.aad_policy_id.to_string(),
        domain_strings: DomainStrings {
            kdf: DEFAULT_CRYPTO_PROFILE.domain_strings.kdf.to_string(),
            iv: DEFAULT_CRYPTO_PROFILE.domain_strings.iv.to_string(),
            kenc: DEFAULT_CRYPTO_PROFILE.domain_strings.kenc.to_string(),
            kiv: DEFAULT_CRYPTO_PROFILE.domain_strings.kiv.to_string(),
        },
    })
}

pub fn validate_container_policy_metadata(
    metadata: &QencMetadata,
    allow_legacy_without_profile: bool,
) -> Result<NonceContract> {
    let profile = get_crypto_profile(metadata.crypto_profile_id.as_deref())?;
    if metadata.crypto_profile_id.is_none() && !allow_legacy_without_profile {
        return Err(err("Container metadata is missing cryptoProfileId"));
    }

    let nonce_contract = get_nonce_contract_for_aead_mode(&metadata.aead_mode)?;
    if metadata.nonce_policy_id != nonce_contract.nonce_policy_id {
        return Err(err(format!(
            "Unsupported noncePolicyId for {}: {}",
            metadata.aead_mode, metadata.nonce_policy_id
        )));
    }
    if metadata.nonce_mode != nonce_contract.nonce_mode {
        return Err(err(format!(
            "Unsupported nonceMode for {}: {}",
            metadata.aead_mode, metadata.nonce_mode
        )));
    }
    if metadata.counter_bits != nonce_contract.counter_bits {
        return Err(err(format!(
            "Unsupported counterBits for {}: {}",
            metadata.aead_mode, metadata.counter_bits
        )));
    }
    if metadata.max_chunk_count != nonce_contract.max_chunk_count {
        return Err(err(format!(
            "Unsupported maxChunkCount for {}: {}",
            metadata.aead_mode, metadata.max_chunk_count
        )));
    }
    if let Some(aad_policy_id) = &metadata.aad_policy_id {
        if aad_policy_id != profile.aad_policy_id {
            return Err(err(format!("Unsupported aadPolicyId: {aad_policy_id}")));
        }
    }
    if let Some(kdf_tree_id) = &metadata.kdf_tree_id {
        if kdf_tree_id != profile.kdf_tree_id {
            return Err(err(format!("Unsupported kdfTreeId: {kdf_tree_id}")));
        }
    }
    if metadata.domain_strings.kdf != profile.domain_strings.kdf
        || metadata.domain_strings.iv != profile.domain_strings.iv
        || metadata.domain_strings.kenc != profile.domain_strings.kenc
        || metadata.domain_strings.kiv != profile.domain_strings.kiv
    {
        return Err(err(
            "Container domainStrings do not match allowed crypto profile",
        ));
    }
    if let Some(chunk_count) = metadata.chunk_count {
        assert_chunk_count_within_policy(chunk_count, &metadata.aead_mode)?;
    }

    Ok(nonce_contract)
}
