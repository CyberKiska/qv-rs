use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{err, Result};
use crate::hash::sha3_512;
use crate::lifecycle::{
    derive_cohort_id, parse_archive_state_descriptor_bytes, parse_cohort_binding_bytes,
    parse_lifecycle_bundle_bytes, CanonicalArchiveStateDescriptor, CanonicalCohortBinding,
    CanonicalLifecycleBundle,
};
use crate::manifest::strict_json::parse_json_bytes_strict;

pub const LIFECYCLE_QCONT_MAGIC: &[u8; 4] = b"QVC1";
pub const LIFECYCLE_QCONT_FORMAT_VERSION: &str = "QVqcont-7";
pub const LIFECYCLE_ARTIFACT_FAMILY: &str = "successor-lifecycle-v1";

const DIGEST_LEN: usize = 64;
const KEY_COMMITMENT_LEN: usize = 32;
pub const MAX_META_LEN: usize = 65_535;
/// Oracle `MAX_QENC_METADATA_BYTES`: the embedded `.qenc` metadata cap the JS
/// cohort reader enforces (`lifecycle-cohort-shared.js`).
pub const MAX_QENC_META_LEN: usize = 4096;
pub const MAX_ARTIFACT_LEN: usize = 16 * 1024 * 1024;
pub const LIFECYCLE_QCONT_MIN_HEADER_BYTES: usize =
    4 + 2 + 4 + DIGEST_LEN + 4 + DIGEST_LEN + 4 + DIGEST_LEN + 4 + 12 + 16 + 2 + 1 + 2 + 2;

#[derive(Clone, PartialEq, Eq)]
pub struct Qvqcont7Shard {
    pub meta_json: Value,
    pub meta_bytes: Vec<u8>,
    pub archive_state_bytes: Vec<u8>,
    pub archive_state_digest_hex: String,
    pub archive_state: CanonicalArchiveStateDescriptor,
    pub state_id: String,
    pub cohort_binding_bytes: Vec<u8>,
    pub cohort_binding_digest_hex: String,
    pub cohort_binding: CanonicalCohortBinding,
    pub cohort_id: String,
    pub lifecycle_bundle_bytes: Vec<u8>,
    pub lifecycle_bundle_digest_hex: String,
    pub lifecycle_bundle: CanonicalLifecycleBundle,
    pub encapsulated_key: Vec<u8>,
    pub container_nonce: [u8; 12],
    pub kdf_salt: [u8; 16],
    pub qenc_meta_bytes: Vec<u8>,
    pub qenc_meta_json: Value,
    pub key_commitment: [u8; KEY_COMMITMENT_LEN],
    pub shard_index: u16,
    pub share: Vec<u8>,
    pub fragments: Vec<u8>,
}

impl std::fmt::Debug for Qvqcont7Shard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Qvqcont7Shard")
            .field("archive_id", &archive_id_from_state(&self.archive_state))
            .field("state_id", &self.state_id)
            .field("cohort_id", &self.cohort_id)
            .field(
                "lifecycle_bundle_digest_hex",
                &self.lifecycle_bundle_digest_hex,
            )
            .field("shard_index", &self.shard_index)
            .field("share_len", &self.share.len())
            .field("fragments_len", &self.fragments.len())
            .finish()
    }
}

impl Drop for Qvqcont7Shard {
    fn drop(&mut self) {
        self.share.zeroize();
        self.fragments.zeroize();
    }
}

pub fn parse_qvqcont7_shard(bytes: &[u8]) -> Result<Qvqcont7Shard> {
    if bytes.len() < LIFECYCLE_QCONT_MIN_HEADER_BYTES {
        return Err(err("Shard is too small to contain a valid header"));
    }

    let mut offset = 0usize;
    let magic = read_bytes(bytes, &mut offset, 4, "magic")?;
    if magic != LIFECYCLE_QCONT_MAGIC {
        return Err(err("Invalid .qcont magic"));
    }

    let meta_len = read_u16(bytes, &mut offset, "metaLen")? as usize;
    if meta_len == 0 || meta_len > MAX_META_LEN {
        return Err(err("Invalid shard metadata length"));
    }
    let meta_bytes = read_bytes(bytes, &mut offset, meta_len, "metaJSON")?.to_vec();
    let meta_json = parse_json_bytes_strict(&meta_bytes)
        .map_err(|error| err(format!("Invalid shard metadata JSON: {error}")))?;
    validate_shard_format(&meta_json)?;

    let archive_state_bytes =
        read_artifact(bytes, &mut offset, "archive-state", "archive-state bytes")?;
    let archive_state_digest = read_digest(bytes, &mut offset, "archive-state digest")?;
    let computed_archive_state_digest = sha3_512(&archive_state_bytes);
    if archive_state_digest != computed_archive_state_digest {
        return Err(err("Embedded archive-state digest mismatch"));
    }
    let archive_state_digest_hex = hex::encode(archive_state_digest);
    let archive_state = parse_archive_state_descriptor_bytes(&archive_state_bytes)?;

    let cohort_binding_bytes =
        read_artifact(bytes, &mut offset, "cohort-binding", "cohort-binding bytes")?;
    let cohort_binding_digest = read_digest(bytes, &mut offset, "cohort-binding digest")?;
    let computed_cohort_binding_digest = sha3_512(&cohort_binding_bytes);
    if cohort_binding_digest != computed_cohort_binding_digest {
        return Err(err("Embedded cohort-binding digest mismatch"));
    }
    let cohort_binding_digest_hex = hex::encode(cohort_binding_digest);
    let cohort_binding = parse_cohort_binding_bytes(&cohort_binding_bytes)?;

    let lifecycle_bundle_bytes = read_artifact(
        bytes,
        &mut offset,
        "lifecycle-bundle",
        "lifecycle-bundle bytes",
    )?;
    let lifecycle_bundle_digest = read_digest(bytes, &mut offset, "lifecycle-bundle digest")?;
    let computed_lifecycle_bundle_digest = sha3_512(&lifecycle_bundle_bytes);
    if lifecycle_bundle_digest != computed_lifecycle_bundle_digest {
        return Err(err("Embedded lifecycle-bundle digest mismatch"));
    }
    let lifecycle_bundle_digest_hex = hex::encode(lifecycle_bundle_digest);
    let lifecycle_bundle = parse_lifecycle_bundle_bytes(&lifecycle_bundle_bytes)?;

    let encap_len = read_u32(bytes, &mut offset, "encapsulatedKey length")? as usize;
    if encap_len == 0 {
        return Err(err("Invalid encapsulated key length"));
    }
    let encapsulated_key = read_bytes(bytes, &mut offset, encap_len, "encapsulatedKey")?.to_vec();

    let mut container_nonce = [0u8; 12];
    container_nonce.copy_from_slice(read_bytes(bytes, &mut offset, 12, "container nonce")?);
    let mut kdf_salt = [0u8; 16];
    kdf_salt.copy_from_slice(read_bytes(bytes, &mut offset, 16, "kdf salt")?);

    let qenc_meta_len = read_u16(bytes, &mut offset, "qenc metadata length")? as usize;
    if qenc_meta_len == 0 || qenc_meta_len > MAX_QENC_META_LEN {
        return Err(err("Invalid qenc metadata length"));
    }
    let qenc_meta_bytes = read_bytes(bytes, &mut offset, qenc_meta_len, "qenc metadata")?.to_vec();
    let qenc_meta_json = parse_json_bytes_strict(&qenc_meta_bytes)
        .map_err(|error| err(format!("Invalid qenc metadata JSON: {error}")))?;

    if meta_json.get("hasKeyCommitment").and_then(Value::as_bool) != Some(true) {
        return Err(err("Shard metadata must indicate hasKeyCommitment=true"));
    }
    let key_commitment_len = read_u8(bytes, &mut offset, "key commitment length")? as usize;
    if key_commitment_len != KEY_COMMITMENT_LEN {
        return Err(err(format!(
            "Invalid key commitment length: expected {KEY_COMMITMENT_LEN}, got {key_commitment_len}"
        )));
    }
    let mut key_commitment = [0u8; KEY_COMMITMENT_LEN];
    key_commitment.copy_from_slice(read_bytes(
        bytes,
        &mut offset,
        key_commitment_len,
        "key commitment",
    )?);
    let metadata_key_commitment = meta_json
        .get("keyCommitmentHex")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    if metadata_key_commitment != hex::encode(key_commitment) {
        return Err(err("Shard metadata keyCommitmentHex mismatch"));
    }

    let shard_index = read_u16(bytes, &mut offset, "shard index")?;
    let share_len = read_u16(bytes, &mut offset, "share length")? as usize;
    if share_len == 0 {
        return Err(err("Invalid Shamir share length"));
    }
    // Hold the raw Shamir share in a Zeroizing buffer so the ~14 validation
    // error returns before struct construction do not leak it in cleared memory.
    let mut share =
        Zeroizing::new(read_bytes(bytes, &mut offset, share_len, "Shamir share")?.to_vec());
    if offset >= bytes.len() {
        return Err(err("Shard fragment payload is empty"));
    }
    let fragments = bytes[offset..].to_vec();

    let state_id = archive_state.state_id.clone();
    if archive_state_digest_hex != state_id {
        return Err(err("archive-state stateId/digest mismatch"));
    }
    let archive_id = archive_id_from_state_result(&archive_state)?;
    if cohort_archive_id(&cohort_binding)? != archive_id {
        return Err(err(
            "Embedded archive-state/cohort-binding archiveId mismatch",
        ));
    }
    if cohort_state_id(&cohort_binding)? != state_id {
        return Err(err(
            "Embedded archive-state/cohort-binding stateId mismatch",
        ));
    }
    let cohort_id = derive_cohort_id(&archive_id, &state_id, &cohort_binding.digest)?;

    let metadata_archive_id = require_lowercase_hex_metadata(&meta_json, "archiveId", 64)?;
    let metadata_state_id = require_lowercase_hex_metadata(&meta_json, "stateId", 128)?;
    let metadata_cohort_id = require_lowercase_hex_metadata(&meta_json, "cohortId", 64)?;
    if metadata_archive_id != archive_id {
        return Err(err("Shard metadata archiveId mismatch"));
    }
    if metadata_state_id != state_id {
        return Err(err("Shard metadata stateId mismatch"));
    }
    if metadata_cohort_id != cohort_id {
        return Err(err("Shard metadata cohortId mismatch"));
    }
    if meta_json.get("shardIndex").and_then(Value::as_u64) != Some(u64::from(shard_index)) {
        return Err(err("Shard metadata shardIndex mismatch"));
    }

    let bundle_archive_digest = lifecycle_bundle
        .lifecycle_bundle
        .value
        .get("archiveStateDigest")
        .and_then(|digest| digest.get("value"))
        .and_then(Value::as_str)
        .ok_or_else(|| err("Missing lifecycleBundle.archiveStateDigest.value"))?;
    if bundle_archive_digest != archive_state_digest_hex {
        return Err(err("Embedded lifecycle-bundle archiveStateDigest mismatch"));
    }
    let bundle_cohort_digest = lifecycle_bundle
        .lifecycle_bundle
        .value
        .get("currentCohortBindingDigest")
        .and_then(|digest| digest.get("value"))
        .and_then(Value::as_str)
        .ok_or_else(|| err("Missing lifecycleBundle.currentCohortBindingDigest.value"))?;
    if bundle_cohort_digest != cohort_binding_digest_hex {
        return Err(err(
            "Embedded lifecycle-bundle currentCohortBindingDigest mismatch",
        ));
    }
    if lifecycle_bundle.bytes != lifecycle_bundle_bytes {
        return Err(err("Embedded lifecycle-bundle canonical bytes mismatch"));
    }

    Ok(Qvqcont7Shard {
        meta_json,
        meta_bytes,
        archive_state_bytes,
        archive_state_digest_hex,
        archive_state,
        state_id,
        cohort_binding_bytes,
        cohort_binding_digest_hex,
        cohort_binding,
        cohort_id,
        lifecycle_bundle_bytes,
        lifecycle_bundle_digest_hex,
        lifecycle_bundle,
        encapsulated_key,
        container_nonce,
        kdf_salt,
        qenc_meta_bytes,
        qenc_meta_json,
        key_commitment,
        shard_index,
        share: std::mem::take(&mut *share),
        fragments,
    })
}

pub fn build_qvqcont7_shard(shard: &Qvqcont7Shard) -> Result<Vec<u8>> {
    validate_component_len(&shard.meta_bytes, MAX_META_LEN, "shard metadata")?;
    validate_component_len(
        &shard.archive_state_bytes,
        MAX_ARTIFACT_LEN,
        "embedded archive-state",
    )?;
    validate_component_len(
        &shard.cohort_binding_bytes,
        MAX_ARTIFACT_LEN,
        "embedded cohort-binding",
    )?;
    validate_component_len(
        &shard.lifecycle_bundle_bytes,
        MAX_ARTIFACT_LEN,
        "embedded lifecycle-bundle",
    )?;
    validate_component_len(
        &shard.encapsulated_key,
        u32::MAX as usize,
        "encapsulated key",
    )?;
    validate_component_len(&shard.qenc_meta_bytes, MAX_QENC_META_LEN, "qenc metadata")?;
    validate_component_len(&shard.share, u16::MAX as usize, "Shamir share")?;
    if shard.fragments.is_empty() {
        return Err(err("Shard fragment payload is empty"));
    }

    let mut out = Zeroizing::new(Vec::with_capacity(
        LIFECYCLE_QCONT_MIN_HEADER_BYTES
            + shard.meta_bytes.len()
            + shard.archive_state_bytes.len()
            + shard.cohort_binding_bytes.len()
            + shard.lifecycle_bundle_bytes.len()
            + shard.encapsulated_key.len()
            + shard.qenc_meta_bytes.len()
            + shard.key_commitment.len()
            + shard.share.len()
            + shard.fragments.len(),
    ));
    out.extend_from_slice(LIFECYCLE_QCONT_MAGIC);
    write_u16(&mut out, shard.meta_bytes.len())?;
    out.extend_from_slice(&shard.meta_bytes);
    write_artifact(&mut out, &shard.archive_state_bytes)?;
    write_artifact(&mut out, &shard.cohort_binding_bytes)?;
    write_artifact(&mut out, &shard.lifecycle_bundle_bytes)?;
    write_u32(&mut out, shard.encapsulated_key.len())?;
    out.extend_from_slice(&shard.encapsulated_key);
    out.extend_from_slice(&shard.container_nonce);
    out.extend_from_slice(&shard.kdf_salt);
    write_u16(&mut out, shard.qenc_meta_bytes.len())?;
    out.extend_from_slice(&shard.qenc_meta_bytes);
    out.push(KEY_COMMITMENT_LEN as u8);
    out.extend_from_slice(&shard.key_commitment);
    out.extend_from_slice(&shard.shard_index.to_be_bytes());
    write_u16(&mut out, shard.share.len())?;
    out.extend_from_slice(&shard.share);
    out.extend_from_slice(&shard.fragments);

    parse_qvqcont7_shard(&out)?;
    Ok(std::mem::take(&mut *out))
}

fn validate_shard_format(meta_json: &Value) -> Result<()> {
    let fmt = meta_json
        .get("alg")
        .and_then(|alg| alg.get("fmt"))
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    if fmt != LIFECYCLE_QCONT_FORMAT_VERSION {
        return Err(err(format!(
            "Unsupported shard format: expected {LIFECYCLE_QCONT_FORMAT_VERSION}, got {fmt}"
        )));
    }
    let artifact_family = meta_json
        .get("artifactFamily")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    if artifact_family != LIFECYCLE_ARTIFACT_FAMILY {
        return Err(err(format!(
            "Unsupported shard artifactFamily: {artifact_family}"
        )));
    }
    Ok(())
}

fn read_artifact(
    bytes: &[u8],
    offset: &mut usize,
    label: &str,
    body_label: &str,
) -> Result<Vec<u8>> {
    let length = read_u32(bytes, offset, &format!("{label} length"))? as usize;
    if length == 0 || length > MAX_ARTIFACT_LEN {
        return Err(err(format!("Invalid embedded {label} length")));
    }
    Ok(read_bytes(bytes, offset, length, body_label)?.to_vec())
}

fn read_digest(bytes: &[u8], offset: &mut usize, field: &str) -> Result<[u8; DIGEST_LEN]> {
    let raw = read_bytes(bytes, offset, DIGEST_LEN, field)?;
    let mut out = [0u8; DIGEST_LEN];
    out.copy_from_slice(raw);
    Ok(out)
}

fn read_u8(bytes: &[u8], offset: &mut usize, field: &str) -> Result<u8> {
    Ok(read_bytes(bytes, offset, 1, field)?[0])
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
    let end = offset
        .checked_add(length)
        .ok_or_else(|| err(format!("Shard offset overflow: {field}")))?;
    if end > bytes.len() {
        return Err(err(format!("Shard is truncated: {field}")));
    }
    let out = &bytes[*offset..end];
    *offset = end;
    Ok(out)
}

fn write_artifact(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    write_u32(out, bytes.len())?;
    out.extend_from_slice(bytes);
    out.extend_from_slice(&sha3_512(bytes));
    Ok(())
}

fn write_u16(out: &mut Vec<u8>, value: usize) -> Result<()> {
    let value = u16::try_from(value).map_err(|_| err("Value does not fit in u16"))?;
    out.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

fn write_u32(out: &mut Vec<u8>, value: usize) -> Result<()> {
    let value = u32::try_from(value).map_err(|_| err("Value does not fit in u32"))?;
    out.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

fn validate_component_len(bytes: &[u8], max: usize, field: &str) -> Result<()> {
    if bytes.is_empty() || bytes.len() > max {
        return Err(err(format!("Invalid {field} length")));
    }
    Ok(())
}

fn require_lowercase_hex_metadata(
    meta_json: &Value,
    field: &str,
    expected_len: usize,
) -> Result<String> {
    let Some(value) = meta_json.get(field).and_then(Value::as_str) else {
        return Err(err(format!("Invalid shard metadata {field}")));
    };
    if value.len() != expected_len
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(err(format!("Invalid shard metadata {field}")));
    }
    Ok(value.to_string())
}

fn archive_id_from_state(archive_state: &CanonicalArchiveStateDescriptor) -> Option<&str> {
    archive_state
        .archive_state
        .value
        .get("archiveId")
        .and_then(Value::as_str)
}

fn archive_id_from_state_result(archive_state: &CanonicalArchiveStateDescriptor) -> Result<String> {
    archive_id_from_state(archive_state)
        .map(str::to_string)
        .ok_or_else(|| err("Missing archiveState.archiveId"))
}

fn cohort_archive_id(cohort_binding: &CanonicalCohortBinding) -> Result<String> {
    cohort_binding
        .cohort_binding
        .value
        .get("archiveId")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| err("Missing cohortBinding.archiveId"))
}

fn cohort_state_id(cohort_binding: &CanonicalCohortBinding) -> Result<String> {
    cohort_binding
        .cohort_binding
        .value
        .get("stateId")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| err("Missing cohortBinding.stateId"))
}
