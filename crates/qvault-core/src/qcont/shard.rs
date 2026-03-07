use serde::{Deserialize, Serialize};

use crate::bytes::to_hex;
use crate::error::{err, Result};
use crate::hash::sha3_512;
use crate::manifest::{parse_archive_manifest_bytes, ParsedArchiveManifest};
use crate::qenc::{parse_qenc_metadata_bytes, QencMetadata};

const QCONT_MAGIC: &[u8; 4] = b"QVC1";
const QCONT_FORMAT_VERSION: &str = "QVqcont-5";
const KEY_COMMITMENT_MAX_LEN: usize = 32;
const MANIFEST_DIGEST_LEN: usize = 64;
const MAX_META_LEN: usize = 16 * 1024;
const MAX_MANIFEST_LEN: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QcontShardAlgorithmMetadata {
    #[serde(rename = "KEM")]
    pub kem: String,
    #[serde(rename = "KDF")]
    pub kdf: String,
    #[serde(rename = "AEAD")]
    pub aead: String,
    #[serde(rename = "RS")]
    pub rs: String,
    pub fmt: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QcontShardDomainStrings {
    pub kdf: String,
    pub iv: String,
    pub kenc: String,
    pub kiv: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QcontShardMetadata {
    #[serde(rename = "containerId")]
    pub container_id: String,
    pub alg: QcontShardAlgorithmMetadata,
    #[serde(rename = "aead_mode")]
    pub aead_mode: String,
    #[serde(rename = "iv_strategy")]
    pub iv_strategy: String,
    #[serde(rename = "cryptoProfileId")]
    pub crypto_profile_id: String,
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
    pub n: u64,
    pub k: u64,
    pub m: u64,
    pub t: u64,
    #[serde(rename = "rsEncodeBase")]
    pub rs_encode_base: u64,
    #[serde(rename = "chunkSize")]
    pub chunk_size: u64,
    #[serde(rename = "chunkCount")]
    pub chunk_count: u64,
    #[serde(rename = "containerHash")]
    pub container_hash: String,
    #[serde(rename = "encapBlobHash")]
    pub encap_blob_hash: String,
    #[serde(rename = "privateKeyHash")]
    pub private_key_hash: String,
    #[serde(rename = "payloadLength", skip_serializing_if = "Option::is_none")]
    pub payload_length: Option<u64>,
    #[serde(rename = "originalLength")]
    pub original_length: u64,
    #[serde(rename = "ciphertextLength")]
    pub ciphertext_length: u64,
    #[serde(rename = "domainStrings")]
    pub domain_strings: QcontShardDomainStrings,
    #[serde(rename = "fragmentFormat")]
    pub fragment_format: String,
    #[serde(rename = "perFragmentSize")]
    pub per_fragment_size: u64,
    #[serde(rename = "hasKeyCommitment")]
    pub has_key_commitment: bool,
    #[serde(rename = "keyCommitmentHex")]
    pub key_commitment_hex: String,
    #[serde(rename = "hasEmbeddedManifest")]
    pub has_embedded_manifest: bool,
    #[serde(rename = "manifestDigest")]
    pub manifest_digest: String,
    #[serde(
        rename = "shareCommitments",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub share_commitments: Option<Vec<String>>,
    #[serde(
        rename = "fragmentBodyHashes",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub fragment_body_hashes: Option<Vec<String>>,
    pub timestamp: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseDiagnostics {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct QcontShard {
    pub meta_json: QcontShardMetadata,
    pub meta_bytes: Vec<u8>,
    pub manifest_bytes: Vec<u8>,
    pub manifest_digest_hex: String,
    pub parsed_manifest: ParsedArchiveManifest,
    pub encapsulated_key: Vec<u8>,
    pub iv: [u8; 12],
    pub salt: [u8; 16],
    pub qenc_meta_bytes: Vec<u8>,
    pub qenc_meta_json: QencMetadata,
    pub key_commit: [u8; 32],
    pub shard_index: u16,
    pub share: Vec<u8>,
    pub fragments: Vec<u8>,
    pub diagnostics: ParseDiagnostics,
}

impl std::fmt::Debug for QcontShard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QcontShard")
            .field("shard_index", &self.shard_index)
            .field("container_id", &self.meta_json.container_id)
            .field("manifest_digest_hex", &self.manifest_digest_hex)
            .field("share_len", &self.share.len())
            .field("fragments_len", &self.fragments.len())
            .field("diagnostics", &self.diagnostics)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct QcontShardParseReport {
    pub shard: Option<QcontShard>,
    pub diagnostics: ParseDiagnostics,
}

impl std::fmt::Debug for QcontShardParseReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QcontShardParseReport")
            .field("has_shard", &self.shard.is_some())
            .field("diagnostics", &self.diagnostics)
            .finish()
    }
}

pub fn parse_qcont_shard(bytes: &[u8]) -> Result<QcontShard> {
    parse_qcont_shard_unsafe(bytes)
}

pub fn parse_qcont_shard_non_strict(bytes: &[u8]) -> QcontShardParseReport {
    match parse_qcont_shard_unsafe(bytes) {
        Ok(shard) => QcontShardParseReport {
            shard: Some(shard),
            diagnostics: ParseDiagnostics {
                errors: Vec::new(),
                warnings: Vec::new(),
            },
        },
        Err(error) => QcontShardParseReport {
            shard: None,
            diagnostics: ParseDiagnostics {
                errors: vec![error.to_string()],
                warnings: Vec::new(),
            },
        },
    }
}

fn parse_qcont_shard_unsafe(bytes: &[u8]) -> Result<QcontShard> {
    let mut offset = 0usize;

    let magic = read_bytes(bytes, &mut offset, 4, "magic")?;
    if magic != QCONT_MAGIC {
        return Err(err("Invalid .qcont magic"));
    }

    let meta_len = read_u16(bytes, &mut offset, "metaLen")? as usize;
    if meta_len == 0 || meta_len > MAX_META_LEN {
        return Err(err("Invalid shard metadata length"));
    }
    let meta_bytes = read_bytes(bytes, &mut offset, meta_len, "metaJSON")?.to_vec();
    let meta_json: QcontShardMetadata = serde_json::from_slice(&meta_bytes)
        .map_err(|error| err(format!("Invalid shard metadata JSON: {error}")))?;
    if meta_json.alg.fmt != QCONT_FORMAT_VERSION {
        return Err(err(format!(
            "Unsupported shard format: expected {QCONT_FORMAT_VERSION}, got {}",
            meta_json.alg.fmt
        )));
    }

    let manifest_len = read_u32(bytes, &mut offset, "manifest length")? as usize;
    if manifest_len == 0 || manifest_len > MAX_MANIFEST_LEN {
        return Err(err("Invalid embedded manifest length"));
    }
    let manifest_bytes = read_bytes(bytes, &mut offset, manifest_len, "manifest bytes")?.to_vec();
    let manifest_digest_bytes =
        read_bytes(bytes, &mut offset, MANIFEST_DIGEST_LEN, "manifest digest")?;
    let computed_manifest_digest = sha3_512(&manifest_bytes);
    if manifest_digest_bytes != computed_manifest_digest {
        return Err(err("Embedded manifest digest mismatch"));
    }
    let manifest_digest_hex = to_hex(&manifest_digest_bytes);
    let parsed_manifest = parse_archive_manifest_bytes(&manifest_bytes)?;

    let encap_len = read_u32(bytes, &mut offset, "encapsulatedKey length")? as usize;
    if encap_len == 0 {
        return Err(err("Invalid encapsulated key length"));
    }
    let encapsulated_key = read_bytes(bytes, &mut offset, encap_len, "encapsulatedKey")?.to_vec();

    let mut iv = [0u8; 12];
    iv.copy_from_slice(read_bytes(bytes, &mut offset, 12, "container nonce")?);

    let mut salt = [0u8; 16];
    salt.copy_from_slice(read_bytes(bytes, &mut offset, 16, "kdf salt")?);

    let qenc_meta_len = read_u16(bytes, &mut offset, "qenc metadata length")? as usize;
    if qenc_meta_len == 0 || qenc_meta_len > MAX_META_LEN {
        return Err(err("Invalid qenc metadata length"));
    }
    let qenc_meta_bytes = read_bytes(bytes, &mut offset, qenc_meta_len, "qenc metadata")?.to_vec();
    let qenc_meta_json = parse_qenc_metadata_bytes(&qenc_meta_bytes)?;

    if meta_json.has_key_commitment != true {
        return Err(err("Shard metadata must indicate hasKeyCommitment=true"));
    }
    let key_commitment_len = read_u8(bytes, &mut offset, "key commitment length")? as usize;
    if key_commitment_len != KEY_COMMITMENT_MAX_LEN {
        return Err(err(format!(
            "Invalid key commitment length: expected {KEY_COMMITMENT_MAX_LEN}, got {key_commitment_len}"
        )));
    }
    let key_commit_bytes = read_bytes(bytes, &mut offset, key_commitment_len, "key commitment")?;
    let mut key_commit = [0u8; 32];
    key_commit.copy_from_slice(&key_commit_bytes);
    if meta_json.key_commitment_hex.is_empty() {
        return Err(err("Shard metadata is missing keyCommitmentHex"));
    }
    if meta_json.key_commitment_hex.to_lowercase() != to_hex(&key_commit) {
        return Err(err("Shard metadata keyCommitmentHex mismatch"));
    }

    let shard_index = read_u16(bytes, &mut offset, "shard index")?;
    let share_len = read_u16(bytes, &mut offset, "share length")? as usize;
    if share_len == 0 {
        return Err(err("Invalid Shamir share length"));
    }
    let share = read_bytes(bytes, &mut offset, share_len, "Shamir share")?.to_vec();

    if offset >= bytes.len() {
        return Err(err("Shard fragment payload is empty"));
    }
    let fragments = bytes[offset..].to_vec();

    Ok(QcontShard {
        meta_json,
        meta_bytes,
        manifest_bytes,
        manifest_digest_hex,
        parsed_manifest,
        encapsulated_key,
        iv,
        salt,
        qenc_meta_bytes,
        qenc_meta_json,
        key_commit,
        shard_index,
        share,
        fragments,
        diagnostics: ParseDiagnostics {
            errors: Vec::new(),
            warnings: Vec::new(),
        },
    })
}

fn read_u8(bytes: &[u8], offset: &mut usize, field: &str) -> Result<u8> {
    if *offset + 1 > bytes.len() {
        return Err(err(format!("{field} is truncated")));
    }
    let value = bytes[*offset];
    *offset += 1;
    Ok(value)
}

fn read_u16(bytes: &[u8], offset: &mut usize, field: &str) -> Result<u16> {
    let raw = read_bytes(bytes, offset, 2, field)?;
    Ok(u16::from_be_bytes([raw[0], raw[1]]))
}

fn read_u32(bytes: &[u8], offset: &mut usize, field: &str) -> Result<u32> {
    let raw = read_bytes(bytes, offset, 4, field)?;
    Ok(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn read_bytes<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    length: usize,
    field: &str,
) -> Result<&'a [u8]> {
    if *offset + length > bytes.len() {
        return Err(err(format!("{field} is truncated")));
    }
    let output = &bytes[*offset..*offset + length];
    *offset += length;
    Ok(output)
}
