use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{err, Result};
use crate::manifest::strict_json::parse_json_bytes_strict;

pub const MAX_QENC_PRIVATE_METADATA_BYTES: usize = 4096;

const PRIVATE_METADATA_FIELDS: [&str; 4] = [
    "originalFilename",
    "timestamp",
    "fileHash",
    "originalLength",
];

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

fn private_metadata_error(message: &str) -> crate::error::QvError {
    err(format!("Invalid private metadata: {message}"))
}

/// Mirrors the oracle's canonical UTC ISO-8601 millisecond regex plus the
/// `Date.parse` round-trip, which rejects shape-valid but non-existent dates.
fn is_canonical_utc_millis(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 24 {
        return false;
    }
    let digits = |range: std::ops::Range<usize>| bytes[range].iter().all(u8::is_ascii_digit);
    if !(digits(0..4)
        && bytes[4] == b'-'
        && digits(5..7)
        && bytes[7] == b'-'
        && digits(8..10)
        && bytes[10] == b'T'
        && digits(11..13)
        && bytes[13] == b':'
        && digits(14..16)
        && bytes[16] == b':'
        && digits(17..19)
        && bytes[19] == b'.'
        && digits(20..23)
        && bytes[23] == b'Z')
    {
        return false;
    }
    let number =
        |range: std::ops::Range<usize>| -> u32 { value[range].parse::<u32>().unwrap_or(u32::MAX) };
    let (year, month, day) = (number(0..4), number(5..7), number(8..10));
    let (hour, minute, second) = (number(11..13), number(14..16), number(17..19));
    if !(1..=12).contains(&month) || day < 1 || hour > 23 || minute > 59 || second > 59 {
        return false;
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    day <= max_day
}

fn is_lowercase_sha3_512_hex(value: &str) -> bool {
    value.len() == 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Oracle `validateWrappedPrivateMetadata` (`index.js`): closed four-member
/// object, bounded encoding, canonical timestamp, lowercase SHA3-512 hex,
/// positive in-range length — enforced after AEAD authentication and before
/// plaintext is returned.
fn validate_wrapped_private_metadata(
    metadata: &Value,
    encoded_length: usize,
) -> Result<WrappedPayloadPrivateMetadata> {
    let object = metadata
        .as_object()
        .ok_or_else(|| private_metadata_error("expected a four-field object"))?;
    if !(1..=MAX_QENC_PRIVATE_METADATA_BYTES).contains(&encoded_length) {
        return Err(private_metadata_error(
            "encoded object exceeds the private metadata byte limit",
        ));
    }
    for field in object.keys() {
        if !PRIVATE_METADATA_FIELDS.contains(&field.as_str()) {
            return Err(private_metadata_error("object contains an unknown field"));
        }
    }
    for field in PRIVATE_METADATA_FIELDS {
        if !object.contains_key(field) {
            return Err(private_metadata_error("object is missing a required field"));
        }
    }
    if object.len() != PRIVATE_METADATA_FIELDS.len() {
        return Err(private_metadata_error("expected exactly four fields"));
    }

    let original_filename = match object.get("originalFilename") {
        Some(Value::Null) => None,
        Some(Value::String(name)) => {
            if name.len() > MAX_QENC_PRIVATE_METADATA_BYTES {
                return Err(private_metadata_error(
                    "originalFilename exceeds the private metadata byte limit",
                ));
            }
            Some(name.clone())
        }
        _ => {
            return Err(private_metadata_error(
                "originalFilename must be null or a string",
            ))
        }
    };
    let timestamp = object
        .get("timestamp")
        .and_then(Value::as_str)
        .ok_or_else(|| private_metadata_error("timestamp must be a string"))?;
    if !is_canonical_utc_millis(timestamp) {
        return Err(private_metadata_error(
            "timestamp must use canonical UTC ISO-8601 millisecond form",
        ));
    }
    let file_hash = object
        .get("fileHash")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            private_metadata_error("fileHash must be a 128-character lowercase SHA3-512 hex digest")
        })?;
    if !is_lowercase_sha3_512_hex(file_hash) {
        return Err(private_metadata_error(
            "fileHash must be a 128-character lowercase SHA3-512 hex digest",
        ));
    }
    let original_length = object
        .get("originalLength")
        .and_then(Value::as_u64)
        // MAX_FILE_SIZE (1 GiB) sits far below 2^53-1, so the range check also
        // guarantees the JSON-safe-integer bound the oracle requires.
        .filter(|length| (1..=crate::qenc::crypto::MAX_FILE_SIZE as u64).contains(length))
        .ok_or_else(|| {
            private_metadata_error(
                "originalLength must be a positive safe integer within the file-size limit",
            )
        })?;

    Ok(WrappedPayloadPrivateMetadata {
        original_filename,
        timestamp: timestamp.to_string(),
        file_hash: file_hash.to_string(),
        original_length,
    })
}

pub fn wrap_wrapped_payload(
    private_metadata: &WrappedPayloadPrivateMetadata,
    file_bytes: &[u8],
) -> Result<Vec<u8>> {
    if file_bytes.is_empty() {
        return Err(err("fileBytes must be a non-empty Uint8Array"));
    }

    let private_meta_bytes = serialize_wrapped_private_metadata(private_metadata)?;
    // Validate what we are about to emit so Rust never writes a container the
    // oracle refuses to decrypt (non-canonical timestamp, oversized metadata).
    let reparsed = parse_json_bytes_strict(&private_meta_bytes)
        .map_err(|_| err("Invalid private metadata JSON in wrapped payload"))?;
    validate_wrapped_private_metadata(&reparsed, private_meta_bytes.len())?;
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
    if !(1..=MAX_QENC_PRIVATE_METADATA_BYTES).contains(&private_meta_len)
        || private_meta_len > payload.len() - 4
    {
        return Err(err("Invalid private metadata length in decrypted payload"));
    }

    let private_meta_bytes = &payload[4..4 + private_meta_len];
    // Decrypted metadata may hold a sensitive filename/timestamp; never relay
    // parser details or content through the error (oracle behavior).
    let private_meta_value = parse_json_bytes_strict(private_meta_bytes)
        .map_err(|_| err("Invalid private metadata JSON in decrypted payload"))?;
    let private_meta = validate_wrapped_private_metadata(&private_meta_value, private_meta_len)?;
    let file_bytes = payload[4 + private_meta_len..].to_vec();
    Ok((private_meta, file_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata() -> WrappedPayloadPrivateMetadata {
        WrappedPayloadPrivateMetadata {
            original_filename: Some("file.bin".to_string()),
            timestamp: "2026-05-28T10:34:56.000Z".to_string(),
            file_hash: "ab".repeat(64),
            original_length: 4,
        }
    }

    #[test]
    fn roundtrip_preserves_metadata_and_bytes() {
        let payload = wrap_wrapped_payload(&metadata(), b"data").expect("wrap");
        let (recovered, file_bytes) = unwrap_wrapped_payload(&payload).expect("unwrap");
        assert_eq!(recovered, metadata());
        assert_eq!(file_bytes, b"data");
    }

    #[test]
    fn unknown_field_is_rejected() {
        let mut payload = wrap_wrapped_payload(&metadata(), b"data").expect("wrap");
        let meta_len = u32::from_be_bytes(payload[..4].try_into().unwrap()) as usize;
        let mut json: Value = serde_json::from_slice(&payload[4..4 + meta_len]).unwrap();
        json.as_object_mut()
            .unwrap()
            .insert("extra".to_string(), Value::Bool(true));
        let tampered_meta = serde_json::to_vec(&json).unwrap();
        let mut tampered = (tampered_meta.len() as u32).to_be_bytes().to_vec();
        tampered.extend_from_slice(&tampered_meta);
        tampered.extend_from_slice(&payload[4 + meta_len..]);
        payload = tampered;
        let error = unwrap_wrapped_payload(&payload).expect_err("unknown field must fail");
        assert!(error.to_string().contains("unknown field"), "{error}");
    }

    #[test]
    fn non_canonical_timestamp_is_rejected() {
        for timestamp in [
            "2026-05-28T10:34:56Z",
            "2026-05-28T10:34:56.000+00:00",
            "2026-02-30T10:34:56.000Z",
            "2026-13-01T10:34:56.000Z",
        ] {
            let mut invalid = metadata();
            invalid.timestamp = timestamp.to_string();
            assert!(
                wrap_wrapped_payload(&invalid, b"data").is_err(),
                "timestamp {timestamp} must fail closed"
            );
        }
    }

    #[test]
    fn uppercase_file_hash_is_rejected() {
        let mut invalid = metadata();
        invalid.file_hash = "AB".repeat(64);
        assert!(wrap_wrapped_payload(&invalid, b"data").is_err());
    }

    #[test]
    fn oversized_private_metadata_is_rejected() {
        let mut invalid = metadata();
        invalid.original_filename = Some("x".repeat(MAX_QENC_PRIVATE_METADATA_BYTES));
        assert!(wrap_wrapped_payload(&invalid, b"data").is_err());
    }

    #[test]
    fn leap_day_timestamp_is_accepted() {
        let mut leap = metadata();
        leap.timestamp = "2024-02-29T23:59:59.999Z".to_string();
        assert!(wrap_wrapped_payload(&leap, b"data").is_ok());
    }
}
