use crate::bytes::bytes_equal;
use crate::error::{err, Result};
use crate::kdf::KDF_SALT_SIZE;
use crate::mlkem::ML_KEM_1024_ENCAPSULATED_KEY_SIZE;
use crate::qenc::metadata::{authenticated_geometry, parse_qenc_metadata_bytes, QencMetadata};

pub const MAGIC: &[u8; 4] = b"QVv1";
pub const KEY_COMMITMENT_SIZE: usize = 32;
pub const MINIMAL_CONTAINER_SIZE: usize = 73;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QencHeader {
    pub header: Vec<u8>,
    pub offset: usize,
    pub encapsulated_key: Vec<u8>,
    pub container_nonce: [u8; 12],
    pub kdf_salt: [u8; KDF_SALT_SIZE],
    pub meta_bytes: Vec<u8>,
    pub metadata: QencMetadata,
    pub stored_key_commitment: [u8; 32],
}

pub fn build_qenc_header(
    encapsulated_key: &[u8],
    container_nonce: &[u8; 12],
    kdf_salt: &[u8; KDF_SALT_SIZE],
    meta_bytes: &[u8],
    key_commitment: &[u8; 32],
) -> Result<Vec<u8>> {
    // Oracle pins keyLen to the ML-KEM-1024 profile size at both write and parse.
    if encapsulated_key.len() != ML_KEM_1024_ENCAPSULATED_KEY_SIZE {
        return Err(err(format!(
            "Invalid encapsulatedKey length: expected {ML_KEM_1024_ENCAPSULATED_KEY_SIZE}, got {}",
            encapsulated_key.len()
        )));
    }
    if meta_bytes.is_empty() || meta_bytes.len() > u16::MAX as usize {
        return Err(err(format!(
            "Invalid metaBytes length: {}",
            meta_bytes.len()
        )));
    }

    let header_len = MAGIC
        .len()
        .checked_add(4)
        .and_then(|length| length.checked_add(encapsulated_key.len()))
        .and_then(|length| length.checked_add(12 + KDF_SALT_SIZE + 2))
        .and_then(|length| length.checked_add(meta_bytes.len()))
        .and_then(|length| length.checked_add(KEY_COMMITMENT_SIZE))
        .ok_or_else(|| err("QENC header length overflow"))?;
    let mut header = Vec::new();
    header
        .try_reserve_exact(header_len)
        .map_err(|_| err("Unable to allocate QENC header"))?;
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&(encapsulated_key.len() as u32).to_be_bytes());
    header.extend_from_slice(encapsulated_key);
    header.extend_from_slice(container_nonce);
    header.extend_from_slice(kdf_salt);
    header.extend_from_slice(&(meta_bytes.len() as u16).to_be_bytes());
    header.extend_from_slice(meta_bytes);
    header.extend_from_slice(key_commitment);
    Ok(header)
}

pub fn parse_qenc_header(container_bytes: &[u8]) -> Result<QencHeader> {
    if container_bytes.len() < MINIMAL_CONTAINER_SIZE {
        return Err(err(format!(
            "File is too small to be a valid container (size: {} B).",
            container_bytes.len()
        )));
    }

    let mut offset = 0usize;
    let magic = &container_bytes[offset..offset + MAGIC.len()];
    if !bytes_equal(magic, MAGIC) {
        return Err(err("Invalid file format (magic bytes mismatch)."));
    }
    offset += MAGIC.len();

    let key_len = read_u32(container_bytes, &mut offset, "encapsulated key length")? as usize;
    if key_len != ML_KEM_1024_ENCAPSULATED_KEY_SIZE {
        return Err(err(format!(
            "Invalid encapsulated key length {key_len}. Expected {ML_KEM_1024_ENCAPSULATED_KEY_SIZE} for the ML-KEM-1024 profile."
        )));
    }
    let key_end = offset
        .checked_add(key_len)
        .ok_or_else(|| err("Invalid encapsulated key length overflow"))?;
    if key_end > container_bytes.len() {
        return Err(err(
            "Incomplete container: encapsulated key length exceeds file size.",
        ));
    }
    let encapsulated_key = container_bytes[offset..key_end].to_vec();
    offset = key_end;

    let fixed_fields_end = offset
        .checked_add(12 + KDF_SALT_SIZE + 2)
        .ok_or_else(|| err("Incomplete container: header length overflow."))?;
    if fixed_fields_end > container_bytes.len() {
        return Err(err("Incomplete container: header is truncated."));
    }

    let mut container_nonce = [0u8; 12];
    container_nonce.copy_from_slice(&container_bytes[offset..offset + 12]);
    offset += 12;

    let mut kdf_salt = [0u8; KDF_SALT_SIZE];
    kdf_salt.copy_from_slice(&container_bytes[offset..offset + KDF_SALT_SIZE]);
    offset += KDF_SALT_SIZE;

    let meta_len = read_u16(container_bytes, &mut offset, "metadata length")? as usize;
    if meta_len == 0 || meta_len > 4096 {
        return Err(err(format!(
            "Invalid metadata length: {meta_len}. Must be between 1 and 4096."
        )));
    }
    let meta_end = offset
        .checked_add(meta_len)
        .ok_or_else(|| err("Incomplete container: metadata length overflow."))?;
    if meta_end > container_bytes.len() {
        return Err(err(
            "Incomplete container: metadata length exceeds file size.",
        ));
    }
    let meta_bytes = container_bytes[offset..meta_end].to_vec();
    let metadata = parse_qenc_metadata_bytes(&meta_bytes)?;
    offset = meta_end;

    let commitment_end = offset
        .checked_add(KEY_COMMITMENT_SIZE)
        .ok_or_else(|| err("Incomplete container: key commitment length overflow."))?;
    if commitment_end > container_bytes.len() {
        return Err(err("Incomplete container: key commitment missing."));
    }
    let mut stored_key_commitment = [0u8; 32];
    stored_key_commitment.copy_from_slice(&container_bytes[offset..commitment_end]);
    offset = commitment_end;

    if offset >= container_bytes.len() {
        return Err(err("Invalid container: ciphertext is missing"));
    }

    let geometry = authenticated_geometry(&metadata)?;
    let ciphertext_length = container_bytes.len() - offset;
    let expected_ciphertext_length = usize::try_from(geometry.ciphertext_length).map_err(|_| {
        err("Invalid container: authenticated ciphertext geometry exceeds platform limits")
    })?;
    if ciphertext_length != expected_ciphertext_length {
        return Err(err(format!(
            "Invalid container: ciphertext length does not match authenticated geometry (expected {expected_ciphertext_length}, got {ciphertext_length})"
        )));
    }

    Ok(QencHeader {
        header: container_bytes[..offset].to_vec(),
        offset,
        encapsulated_key,
        container_nonce,
        kdf_salt,
        meta_bytes,
        metadata,
        stored_key_commitment,
    })
}

fn read_u16(bytes: &[u8], offset: &mut usize, field: &str) -> Result<u16> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| err(format!("Incomplete container: {field} offset overflow.")))?;
    if end > bytes.len() {
        return Err(err(format!("Incomplete container: {field} is truncated.")));
    }
    let value = u16::from_be_bytes([bytes[*offset], bytes[*offset + 1]]);
    *offset = end;
    Ok(value)
}

fn read_u32(bytes: &[u8], offset: &mut usize, field: &str) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| err(format!("Incomplete container: {field} offset overflow.")))?;
    if end > bytes.len() {
        return Err(err(format!("Incomplete container: {field} is truncated.")));
    }
    let value = u32::from_be_bytes([
        bytes[*offset],
        bytes[*offset + 1],
        bytes[*offset + 2],
        bytes[*offset + 3],
    ]);
    *offset = end;
    Ok(value)
}
