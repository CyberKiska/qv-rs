use serde_json::Value;

use crate::error::{err, Result};
use crate::manifest::jcs::{
    canonicalize_json, canonicalize_json_to_bytes, MANIFEST_CANONICALIZATION_LABEL,
};
use crate::manifest::strict_json::{assert_canonical_bytes, parse_json_bytes_strict};
use crate::policy::{get_crypto_profile, get_nonce_contract_for_aead_mode};

use super::digests::{
    sha3_512_digest, validate_auth_policy_commitment_shape, DigestObject, SHA3_512_ALG,
};
use super::validation::{
    exact_keys, exact_string, hex_string, integer, nullable_hex, number, object_from_pairs,
    safe_integer, string, value_object,
};

pub const ARCHIVE_STATE_SCHEMA: &str = "quantum-vault-archive-state-descriptor/v1";
pub const ARCHIVE_STATE_VERSION: u64 = 1;
pub const ARCHIVE_STATE_CANONICALIZATION: &str = MANIFEST_CANONICALIZATION_LABEL;
pub const ARCHIVE_STATE_TYPE_DEFAULT: &str = "archive-state";
pub const PRIMARY_ANCHOR: &str = "qencHash";
pub const CONTAINER_ID_ROLE: &str = "secondary-header-id";
pub const CONTAINER_ID_ALG: &str = "SHA3-512(qenc-header-bytes)";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveStateDescriptor {
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalArchiveStateDescriptor {
    pub archive_state: ArchiveStateDescriptor,
    pub canonical: String,
    pub bytes: Vec<u8>,
    pub digest: DigestObject,
    pub state_id: String,
    pub canonicalization_label: String,
}

pub fn validate_archive_state_descriptor_value(value: &Value) -> Result<ArchiveStateDescriptor> {
    let source = value_object(value, "archiveState")?;
    if source.contains_key("stateId") {
        return Err(err("archiveState.stateId MUST NOT be present"));
    }
    exact_keys(
        source,
        &[
            "schema",
            "version",
            "stateType",
            "canonicalization",
            "archiveId",
            "parentStateId",
            "cryptoProfileId",
            "kdfTreeId",
            "noncePolicyId",
            "nonceMode",
            "counterBits",
            "maxChunkCount",
            "aadPolicyId",
            "qenc",
            "authPolicyCommitment",
        ],
        &[],
        "archiveState",
    )?;
    let qenc = value_object(
        source
            .get("qenc")
            .ok_or_else(|| err("Missing archiveState.qenc"))?,
        "archiveState.qenc",
    )?;
    exact_keys(
        qenc,
        &[
            "chunkSize",
            "chunkCount",
            "payloadLength",
            "hashAlg",
            "primaryAnchor",
            "qencHash",
            "containerId",
            "containerIdRole",
            "containerIdAlg",
        ],
        &[],
        "archiveState.qenc",
    )?;

    let schema = exact_string(
        source.get("schema"),
        "archiveState.schema",
        ARCHIVE_STATE_SCHEMA,
    )?;
    let version = integer(source.get("version"), "archiveState.version", 1, u64::MAX)?;
    if version != ARCHIVE_STATE_VERSION {
        return Err(err("Unsupported archiveState.version"));
    }
    let state_type = string(source.get("stateType"), "archiveState.stateType")?;
    let canonicalization = exact_string(
        source.get("canonicalization"),
        "archiveState.canonicalization",
        ARCHIVE_STATE_CANONICALIZATION,
    )?;
    let archive_id = hex_string(source.get("archiveId"), "archiveState.archiveId", Some(64))?;
    let parent_state_id = nullable_hex(
        source.get("parentStateId"),
        "archiveState.parentStateId",
        128,
    )?;
    let crypto_profile_id = string(
        source.get("cryptoProfileId"),
        "archiveState.cryptoProfileId",
    )?;
    let kdf_tree_id = string(source.get("kdfTreeId"), "archiveState.kdfTreeId")?;
    let nonce_policy_id = string(source.get("noncePolicyId"), "archiveState.noncePolicyId")?;
    let nonce_mode = string(source.get("nonceMode"), "archiveState.nonceMode")?;
    let counter_bits = integer(
        source.get("counterBits"),
        "archiveState.counterBits",
        0,
        0xffff_ffff,
    )?;
    let max_chunk_count = integer(
        source.get("maxChunkCount"),
        "archiveState.maxChunkCount",
        1,
        0xffff_ffff,
    )?;
    let aad_policy_id = string(source.get("aadPolicyId"), "archiveState.aadPolicyId")?;

    let profile = get_crypto_profile(Some(&crypto_profile_id))?;
    if kdf_tree_id != profile.kdf_tree_id {
        return Err(err(format!(
            "archiveState.kdfTreeId does not match profile ({})",
            profile.kdf_tree_id
        )));
    }
    if aad_policy_id != profile.aad_policy_id {
        return Err(err(format!(
            "archiveState.aadPolicyId does not match profile ({})",
            profile.aad_policy_id
        )));
    }
    let implied_aead_mode = if counter_bits == 0 && max_chunk_count == 1 {
        "single-container-aead"
    } else {
        "per-chunk-aead"
    };
    let nonce_contract = get_nonce_contract_for_aead_mode(implied_aead_mode)?;
    if nonce_policy_id != nonce_contract.nonce_policy_id {
        return Err(err(
            "archiveState.noncePolicyId does not match implied AEAD mode",
        ));
    }
    if nonce_mode != nonce_contract.nonce_mode {
        return Err(err(
            "archiveState.nonceMode does not match implied AEAD mode",
        ));
    }
    if counter_bits != u64::from(nonce_contract.counter_bits) {
        return Err(err(
            "archiveState.counterBits does not match implied AEAD mode",
        ));
    }
    if max_chunk_count != nonce_contract.max_chunk_count {
        return Err(err(
            "archiveState.maxChunkCount does not match implied AEAD mode",
        ));
    }

    let qenc_value = object_from_pairs(vec![
        (
            "chunkSize",
            number(safe_integer(
                qenc.get("chunkSize"),
                "archiveState.qenc.chunkSize",
                1,
            )?),
        ),
        (
            "chunkCount",
            number(integer(
                qenc.get("chunkCount"),
                "archiveState.qenc.chunkCount",
                1,
                0xffff_ffff,
            )?),
        ),
        (
            "payloadLength",
            number(safe_integer(
                qenc.get("payloadLength"),
                "archiveState.qenc.payloadLength",
                1,
            )?),
        ),
        (
            "hashAlg",
            Value::String(exact_string(
                qenc.get("hashAlg"),
                "archiveState.qenc.hashAlg",
                SHA3_512_ALG,
            )?),
        ),
        (
            "primaryAnchor",
            Value::String(exact_string(
                qenc.get("primaryAnchor"),
                "archiveState.qenc.primaryAnchor",
                PRIMARY_ANCHOR,
            )?),
        ),
        (
            "qencHash",
            Value::String(hex_string(
                qenc.get("qencHash"),
                "archiveState.qenc.qencHash",
                Some(128),
            )?),
        ),
        (
            "containerId",
            Value::String(hex_string(
                qenc.get("containerId"),
                "archiveState.qenc.containerId",
                Some(128),
            )?),
        ),
        (
            "containerIdRole",
            Value::String(exact_string(
                qenc.get("containerIdRole"),
                "archiveState.qenc.containerIdRole",
                CONTAINER_ID_ROLE,
            )?),
        ),
        (
            "containerIdAlg",
            Value::String(exact_string(
                qenc.get("containerIdAlg"),
                "archiveState.qenc.containerIdAlg",
                CONTAINER_ID_ALG,
            )?),
        ),
    ]);

    let auth_policy_commitment = validate_auth_policy_commitment_shape(
        source
            .get("authPolicyCommitment")
            .ok_or_else(|| err("Missing archiveState.authPolicyCommitment"))?,
    )?;
    let auth_policy_commitment_value = serde_json::to_value(auth_policy_commitment)?;

    Ok(ArchiveStateDescriptor {
        value: object_from_pairs(vec![
            ("schema", Value::String(schema)),
            ("version", number(version)),
            ("stateType", Value::String(state_type)),
            ("canonicalization", Value::String(canonicalization)),
            ("archiveId", Value::String(archive_id)),
            ("parentStateId", parent_state_id),
            ("cryptoProfileId", Value::String(crypto_profile_id)),
            ("kdfTreeId", Value::String(kdf_tree_id)),
            ("noncePolicyId", Value::String(nonce_policy_id)),
            ("nonceMode", Value::String(nonce_mode)),
            ("counterBits", number(counter_bits)),
            ("maxChunkCount", number(max_chunk_count)),
            ("aadPolicyId", Value::String(aad_policy_id)),
            ("qenc", qenc_value),
            ("authPolicyCommitment", auth_policy_commitment_value),
        ]),
    })
}

pub fn canonicalize_archive_state_descriptor(
    value: &Value,
) -> Result<CanonicalArchiveStateDescriptor> {
    let archive_state = validate_archive_state_descriptor_value(value)?;
    let canonical = canonicalize_json(&archive_state.value)?;
    let bytes = canonicalize_json_to_bytes(&archive_state.value)?;
    let digest = sha3_512_digest(&bytes);
    Ok(CanonicalArchiveStateDescriptor {
        archive_state,
        canonical,
        bytes,
        state_id: digest.value.clone(),
        digest,
        canonicalization_label: ARCHIVE_STATE_CANONICALIZATION.to_string(),
    })
}

pub fn parse_archive_state_descriptor_bytes(
    bytes: &[u8],
) -> Result<CanonicalArchiveStateDescriptor> {
    let parsed = parse_json_bytes_strict(bytes)?;
    let canonicalized = canonicalize_archive_state_descriptor(&parsed)?;
    assert_canonical_bytes(bytes, &canonicalized.bytes, "Archive state descriptor")?;
    Ok(canonicalized)
}

pub fn derive_state_id(value: &Value) -> Result<String> {
    Ok(canonicalize_archive_state_descriptor(value)?.state_id)
}
