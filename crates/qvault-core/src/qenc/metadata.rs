use serde::{Deserialize, Serialize};

use crate::aead::{
    IV_STRATEGY_KMAC_PREFIX64_CTR32_V3, IV_STRATEGY_SINGLE_IV, NONCE_COUNTER_BITS_U32,
    NONCE_MAX_CHUNK_COUNT_U32,
};
use crate::error::{err, Result};
use crate::policy::build_policy_metadata_fields;

pub const FORMAT_VERSION: &str = "QVv1-5-0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainStrings {
    pub kdf: String,
    pub iv: String,
    pub kenc: String,
    pub kiv: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QencMetadata {
    #[serde(rename = "KEM", skip_serializing_if = "Option::is_none")]
    pub kem: Option<String>,
    #[serde(rename = "KDF", skip_serializing_if = "Option::is_none")]
    pub kdf: Option<String>,
    #[serde(rename = "AEAD", skip_serializing_if = "Option::is_none")]
    pub aead: Option<String>,
    #[serde(rename = "aead_mode")]
    pub aead_mode: String,
    #[serde(rename = "iv_strategy")]
    pub iv_strategy: String,
    pub fmt: String,
    #[serde(rename = "hasKeyCommitment")]
    pub has_key_commitment: bool,
    #[serde(rename = "payloadFormat", skip_serializing_if = "Option::is_none")]
    pub payload_format: Option<String>,
    #[serde(rename = "payloadLength", skip_serializing_if = "Option::is_none")]
    pub payload_length: Option<u64>,
    #[serde(rename = "chunkSize", skip_serializing_if = "Option::is_none")]
    pub chunk_size: Option<u64>,
    #[serde(rename = "chunkCount", skip_serializing_if = "Option::is_none")]
    pub chunk_count: Option<u64>,
    #[serde(rename = "cryptoProfileId", skip_serializing_if = "Option::is_none")]
    pub crypto_profile_id: Option<String>,
    #[serde(rename = "kdfTreeId", skip_serializing_if = "Option::is_none")]
    pub kdf_tree_id: Option<String>,
    #[serde(rename = "noncePolicyId")]
    pub nonce_policy_id: String,
    #[serde(rename = "nonceMode")]
    pub nonce_mode: String,
    #[serde(rename = "counterBits")]
    pub counter_bits: u32,
    #[serde(rename = "maxChunkCount")]
    pub max_chunk_count: u64,
    #[serde(rename = "aadPolicyId", skip_serializing_if = "Option::is_none")]
    pub aad_policy_id: Option<String>,
    #[serde(rename = "domainStrings")]
    pub domain_strings: DomainStrings,
}

pub fn parse_qenc_metadata_bytes(bytes: &[u8]) -> Result<QencMetadata> {
    let metadata: QencMetadata = serde_json::from_slice(bytes)
        .map_err(|error| err(format!("Invalid metadata JSON: {error}")))?;
    validate_qenc_metadata(&metadata)?;
    Ok(metadata)
}

pub fn build_qenc_metadata(
    aead_mode: &str,
    payload_length: u64,
    chunk_size: u64,
    chunk_count: u64,
) -> Result<QencMetadata> {
    if payload_length == 0 {
        return Err(err("payloadLength must be a positive integer"));
    }
    if chunk_size == 0 {
        return Err(err("chunkSize must be a positive integer"));
    }
    if chunk_count == 0 {
        return Err(err("chunkCount must be a positive integer"));
    }

    let policy_fields = build_policy_metadata_fields(aead_mode)?;
    let iv_strategy = match aead_mode {
        "single-container-aead" => IV_STRATEGY_SINGLE_IV,
        "per-chunk-aead" => IV_STRATEGY_KMAC_PREFIX64_CTR32_V3,
        other => return Err(err(format!("Unsupported AEAD mode: {other}"))),
    };

    let metadata = QencMetadata {
        kem: Some("ML-KEM-1024".to_string()),
        kdf: Some("KMAC256".to_string()),
        aead: Some("AES-256-GCM".to_string()),
        aead_mode: aead_mode.to_string(),
        iv_strategy: iv_strategy.to_string(),
        fmt: FORMAT_VERSION.to_string(),
        has_key_commitment: true,
        payload_format: Some("wrapped-v1".to_string()),
        payload_length: Some(payload_length),
        chunk_size: Some(chunk_size),
        chunk_count: Some(chunk_count),
        crypto_profile_id: Some(policy_fields.crypto_profile_id),
        kdf_tree_id: Some(policy_fields.kdf_tree_id),
        nonce_policy_id: policy_fields.nonce_policy_id,
        nonce_mode: policy_fields.nonce_mode,
        counter_bits: policy_fields.counter_bits,
        max_chunk_count: policy_fields.max_chunk_count,
        aad_policy_id: Some(policy_fields.aad_policy_id),
        domain_strings: policy_fields.domain_strings,
    };
    validate_qenc_metadata(&metadata)?;
    Ok(metadata)
}

pub fn serialize_qenc_metadata(metadata: &QencMetadata) -> Result<Vec<u8>> {
    validate_qenc_metadata(metadata)?;
    serde_json::to_vec(metadata).map_err(Into::into)
}

pub fn validate_qenc_metadata(metadata: &QencMetadata) -> Result<()> {
    if metadata.fmt != FORMAT_VERSION {
        return Err(err(format!(
            "Unsupported container format: expected {FORMAT_VERSION}, got {}",
            metadata.fmt
        )));
    }
    if metadata.aead_mode.is_empty() {
        return Err(err("Invalid metadata: missing aead_mode"));
    }
    if metadata.iv_strategy.is_empty() {
        return Err(err("Invalid metadata: missing iv_strategy"));
    }
    if metadata.domain_strings.kdf.is_empty()
        || metadata.domain_strings.iv.is_empty()
        || metadata.domain_strings.kenc.is_empty()
        || metadata.domain_strings.kiv.is_empty()
    {
        return Err(err(
            "Invalid metadata: missing domainStrings.kdf/domainStrings.iv/domainStrings.kenc/domainStrings.kiv",
        ));
    }
    if metadata.nonce_policy_id.is_empty() {
        return Err(err("Invalid metadata: missing noncePolicyId"));
    }
    if metadata.nonce_mode.is_empty() {
        return Err(err("Invalid metadata: missing nonceMode"));
    }
    if metadata.max_chunk_count == 0 {
        return Err(err(
            "Invalid metadata: maxChunkCount must be a positive integer",
        ));
    }
    if metadata.max_chunk_count > NONCE_MAX_CHUNK_COUNT_U32 {
        return Err(err(format!(
            "Invalid metadata: maxChunkCount exceeds uint32 counter capacity ({NONCE_MAX_CHUNK_COUNT_U32})"
        )));
    }
    if let Some(payload_length) = metadata.payload_length {
        if payload_length == 0 {
            return Err(err(
                "Invalid metadata: payloadLength must be a positive integer",
            ));
        }
    }
    if let Some(chunk_count) = metadata.chunk_count {
        if chunk_count == 0 {
            return Err(err(
                "Invalid metadata: chunkCount must be a positive integer",
            ));
        }
        if chunk_count > metadata.max_chunk_count {
            return Err(err("Invalid metadata: chunkCount exceeds maxChunkCount"));
        }
    }
    if let Some(chunk_size) = metadata.chunk_size {
        if chunk_size == 0 {
            return Err(err(
                "Invalid metadata: chunkSize must be a positive integer",
            ));
        }
    }
    match metadata.aead_mode.as_str() {
        "single-container-aead" => {
            if metadata.iv_strategy != IV_STRATEGY_SINGLE_IV {
                return Err(err(format!(
                    "Invalid metadata: single-container-aead requires iv_strategy=\"{IV_STRATEGY_SINGLE_IV}\""
                )));
            }
            if metadata.counter_bits != 0 {
                return Err(err(
                    "Invalid metadata: single-container-aead requires counterBits=0",
                ));
            }
            if metadata.max_chunk_count != 1 {
                return Err(err(
                    "Invalid metadata: single-container-aead requires maxChunkCount=1",
                ));
            }
        }
        "per-chunk-aead" => {
            if metadata.iv_strategy != IV_STRATEGY_KMAC_PREFIX64_CTR32_V3 {
                return Err(err(format!(
                    "Invalid metadata: per-chunk-aead requires iv_strategy=\"{IV_STRATEGY_KMAC_PREFIX64_CTR32_V3}\""
                )));
            }
            if metadata.counter_bits != NONCE_COUNTER_BITS_U32 {
                return Err(err(format!(
                    "Invalid metadata: per-chunk-aead requires counterBits={NONCE_COUNTER_BITS_U32}"
                )));
            }
            if metadata.chunk_count.is_none() {
                return Err(err("Invalid metadata: per-chunk-aead requires chunkCount"));
            }
        }
        other => return Err(err(format!("Unsupported AEAD mode: {other}"))),
    }
    if metadata.has_key_commitment != true {
        return Err(err("Invalid metadata: hasKeyCommitment must be true"));
    }
    Ok(())
}
