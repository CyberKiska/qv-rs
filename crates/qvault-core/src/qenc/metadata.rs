use serde::{Deserialize, Serialize};

use crate::aead::{
    IV_STRATEGY_KMAC_PREFIX64_CTR32_V3, IV_STRATEGY_SINGLE_IV, NONCE_COUNTER_BITS_U32,
    NONCE_MAX_CHUNK_COUNT_U32,
};
use crate::error::{err, Result};
use crate::policy::build_policy_metadata_fields;

pub const FORMAT_VERSION: &str = "QVv1-5-0";
pub const KEM_ALG_ID_ML_KEM_1024: &str = "ML-KEM-1024";
pub const KDF_ALG_ID_KMAC256: &str = "KMAC256";
pub const AEAD_ALG_ID_AES_256_GCM: &str = "AES-256-GCM";
const QENC_CHUNK_SIZE: u64 = 8 * 1024 * 1024;
const JS_MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const AES_GCM_TAG_SIZE: u64 = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuthenticatedGeometry {
    pub payload_length: u64,
    pub chunk_size: u64,
    pub chunk_count: u64,
    pub ciphertext_length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainStrings {
    pub kdf: String,
    pub iv: String,
    pub kenc: String,
    pub kiv: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    let value = crate::manifest::strict_json::parse_json_bytes_strict(bytes)?;
    let metadata: QencMetadata = serde_json::from_value(value)
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
        kem: Some(KEM_ALG_ID_ML_KEM_1024.to_string()),
        kdf: Some(KDF_ALG_ID_KMAC256.to_string()),
        aead: Some(AEAD_ALG_ID_AES_256_GCM.to_string()),
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
    reject_unsupported_optional_alg("KEM", metadata.kem.as_deref(), KEM_ALG_ID_ML_KEM_1024)?;
    reject_unsupported_optional_alg("KDF", metadata.kdf.as_deref(), KDF_ALG_ID_KMAC256)?;
    reject_unsupported_optional_alg("AEAD", metadata.aead.as_deref(), AEAD_ALG_ID_AES_256_GCM)?;
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
    let payload_length = required_safe_positive_integer(metadata.payload_length, "payloadLength")?;
    let chunk_count = required_safe_positive_integer(metadata.chunk_count, "chunkCount")?;
    let chunk_size = required_safe_positive_integer(metadata.chunk_size, "chunkSize")?;
    if chunk_size != QENC_CHUNK_SIZE {
        return Err(err(format!(
            "Invalid metadata: unsupported chunkSize {chunk_size}; expected {QENC_CHUNK_SIZE}"
        )));
    }
    if chunk_count > metadata.max_chunk_count {
        return Err(err("Invalid metadata: chunkCount exceeds maxChunkCount"));
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
            if chunk_count != 1 {
                return Err(err(
                    "Invalid metadata: single-container-aead requires chunkCount=1",
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
            let expected_chunk_count = checked_chunk_count(payload_length, chunk_size)?;
            if chunk_count != expected_chunk_count {
                return Err(err(format!(
                    "Invalid metadata: chunkCount does not match payloadLength/chunkSize geometry (expected {expected_chunk_count})"
                )));
            }
        }
        other => return Err(err(format!("Unsupported AEAD mode: {other}"))),
    }
    if !metadata.has_key_commitment {
        return Err(err("Invalid metadata: hasKeyCommitment must be true"));
    }
    Ok(())
}

pub(crate) fn authenticated_geometry(metadata: &QencMetadata) -> Result<AuthenticatedGeometry> {
    validate_qenc_metadata(metadata)?;

    let payload_length = required_safe_positive_integer(metadata.payload_length, "payloadLength")?;
    let chunk_size = required_safe_positive_integer(metadata.chunk_size, "chunkSize")?;
    let chunk_count = required_safe_positive_integer(metadata.chunk_count, "chunkCount")?;
    let tag_length = AES_GCM_TAG_SIZE
        .checked_mul(chunk_count)
        .ok_or_else(|| err("Invalid metadata: ciphertext length overflows uint64"))?;
    let ciphertext_length = payload_length
        .checked_add(tag_length)
        .ok_or_else(|| err("Invalid metadata: ciphertext length overflows uint64"))?;

    Ok(AuthenticatedGeometry {
        payload_length,
        chunk_size,
        chunk_count,
        ciphertext_length,
    })
}

fn required_safe_positive_integer(value: Option<u64>, field: &str) -> Result<u64> {
    match value {
        Some(value) if (1..=JS_MAX_SAFE_INTEGER).contains(&value) => Ok(value),
        _ => Err(err(format!(
            "Invalid metadata: {field} must be a positive integer"
        ))),
    }
}

fn checked_chunk_count(payload_length: u64, chunk_size: u64) -> Result<u64> {
    let rounded_length = payload_length.checked_add(chunk_size - 1).ok_or_else(|| {
        err("Invalid metadata: payloadLength/chunkSize geometry overflows uint64")
    })?;
    Ok(rounded_length / chunk_size)
}

fn reject_unsupported_optional_alg(field: &str, value: Option<&str>, expected: &str) -> Result<()> {
    if let Some(value) = value {
        if value != expected {
            return Err(err(format!(
                "Unsupported {field}: expected {expected}, got {value}"
            )));
        }
    }
    Ok(())
}
