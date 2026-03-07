use serde::{Deserialize, Serialize};

use crate::error::{err, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedPayloadPrivateMetadata {
    #[serde(rename = "originalFilename")]
    pub original_filename: Option<String>,
    pub timestamp: String,
    #[serde(rename = "fileHash")]
    pub file_hash: String,
    #[serde(rename = "originalLength")]
    pub original_length: u64,
}

pub fn serialize_wrapped_private_metadata(
    private_metadata: &WrappedPayloadPrivateMetadata,
) -> Result<Vec<u8>> {
    serde_json::to_vec(private_metadata).map_err(Into::into)
}

pub fn wrap_wrapped_payload(
    private_metadata: &WrappedPayloadPrivateMetadata,
    file_bytes: &[u8],
) -> Result<Vec<u8>> {
    if file_bytes.is_empty() {
        return Err(err("fileBytes must be a non-empty Uint8Array"));
    }

    let private_meta_bytes = serialize_wrapped_private_metadata(private_metadata)?;
    let private_meta_len = u32::try_from(private_meta_bytes.len())
        .map_err(|_| err("Private metadata is too large for wrapped-v1 payload"))?;
    let mut payload = Vec::with_capacity(4 + private_meta_bytes.len() + file_bytes.len());
    payload.extend_from_slice(&private_meta_len.to_be_bytes());
    payload.extend_from_slice(&private_meta_bytes);
    payload.extend_from_slice(file_bytes);
    Ok(payload)
}

pub fn unwrap_wrapped_payload(payload: &[u8]) -> Result<(WrappedPayloadPrivateMetadata, Vec<u8>)> {
    if payload.len() < 4 {
        return Err(err("Invalid private metadata length in decrypted payload"));
    }

    let private_meta_len =
        u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
    if private_meta_len < 1 || private_meta_len > payload.len() - 4 {
        return Err(err("Invalid private metadata length in decrypted payload"));
    }

    let private_meta_bytes = &payload[4..4 + private_meta_len];
    let private_meta: WrappedPayloadPrivateMetadata = serde_json::from_slice(private_meta_bytes)
        .map_err(|error| err(format!("Invalid private metadata JSON: {error}")))?;
    let file_bytes = payload[4 + private_meta_len..].to_vec();
    Ok((private_meta, file_bytes))
}
