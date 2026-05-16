use crate::bytes::bytes_equal;
use crate::error::{err, Result};
use crate::kdf::KDF_SALT_SIZE;
use crate::qenc::metadata::{parse_qenc_metadata_bytes, QencMetadata};

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
    if meta_bytes.is_empty() || meta_bytes.len() > u16::MAX as usize {
        return Err(err(format!(
            "Invalid metaBytes length: {}",
            meta_bytes.len()
        )));
    }

    let mut header = Vec::with_capacity(
        MAGIC.len() + 4 + encapsulated_key.len() + 12 + KDF_SALT_SIZE + 2 + meta_bytes.len() + 32,
    );
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
    if key_len == 0 {
        return Err(err(format!("Invalid encapsulated key length {key_len}.")));
    }
    if key_len > container_bytes.len() {
        return Err(err(format!(
            "Invalid encapsulated key length {key_len}: exceeds container size."
        )));
    }
    if offset + key_len > container_bytes.len() {
        return Err(err(
            "Incomplete container: encapsulated key length exceeds file size.",
        ));
    }
    let encapsulated_key = container_bytes[offset..offset + key_len].to_vec();
    offset += key_len;

    if offset + 12 + KDF_SALT_SIZE + 2 > container_bytes.len() {
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
    if offset + meta_len > container_bytes.len() {
        return Err(err(
            "Incomplete container: metadata length exceeds file size.",
        ));
    }
    let meta_bytes = container_bytes[offset..offset + meta_len].to_vec();
    let metadata = parse_qenc_metadata_bytes(&meta_bytes)?;
    offset += meta_len;

    if offset + KEY_COMMITMENT_SIZE > container_bytes.len() {
        return Err(err("Incomplete container: key commitment missing."));
    }
    let mut stored_key_commitment = [0u8; 32];
    stored_key_commitment.copy_from_slice(&container_bytes[offset..offset + 32]);
    offset += 32;

    if offset >= container_bytes.len() {
        return Err(err("Invalid container: ciphertext is missing"));
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
    if *offset + 2 > bytes.len() {
        return Err(err(format!("Incomplete container: {field} is truncated.")));
    }
    let value = u16::from_be_bytes([bytes[*offset], bytes[*offset + 1]]);
    *offset += 2;
    Ok(value)
}

fn read_u32(bytes: &[u8], offset: &mut usize, field: &str) -> Result<u32> {
    if *offset + 4 > bytes.len() {
        return Err(err(format!("Incomplete container: {field} is truncated.")));
    }
    let value = u32::from_be_bytes([
        bytes[*offset],
        bytes[*offset + 1],
        bytes[*offset + 2],
        bytes[*offset + 3],
    ]);
    *offset += 4;
    Ok(value)
}
