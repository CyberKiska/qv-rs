use crate::aead::{
    assert_per_chunk_nonce_contract, build_chunk_aad, decrypt_chunk, derive_chunk_iv_from_k,
    encrypt_chunk,
};
use crate::error::{coded, err, QvCode, Result};
use crate::hash::sha3_512_hex;
use crate::kdf::{
    compute_key_commitment, derive_key_with_kmac, verify_key_commitment, KDF_SALT_SIZE,
};
use crate::mlkem::{decapsulate, encapsulate};
use crate::policy::validate_container_policy_metadata;
use crate::qenc::header::{build_qenc_header, parse_qenc_header};
use crate::qenc::metadata::{build_qenc_metadata, serialize_qenc_metadata};
use crate::qenc::payload::{
    unwrap_wrapped_payload, wrap_wrapped_payload, WrappedPayloadPrivateMetadata,
};
use crate::qenc::QencHeader;
use crate::rng::fill_random;
use time::macros::format_description;
use time::OffsetDateTime;
use zeroize::Zeroize;

pub const CHUNK_SIZE: usize = 8 * 1024 * 1024;
pub const MAX_FILE_SIZE: usize = 1024 * 1024 * 1024;

#[derive(Clone, PartialEq, Eq)]
pub struct DecryptedQenc {
    pub file_bytes: Vec<u8>,
    pub private_metadata: WrappedPayloadPrivateMetadata,
    pub warnings: Vec<String>,
}

impl std::fmt::Debug for DecryptedQenc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecryptedQenc")
            .field("file_bytes_len", &self.file_bytes.len())
            .field("private_metadata", &self.private_metadata)
            .field("warnings", &self.warnings)
            .finish()
    }
}

#[derive(Clone, Default)]
pub struct EncryptQencOptions {
    pub original_filename: Option<String>,
    pub timestamp: Option<String>,
    pub encapsulation_seed: Option<[u8; 32]>,
    pub container_nonce: Option<[u8; 12]>,
    pub kdf_salt: Option<[u8; KDF_SALT_SIZE]>,
}

pub fn encrypt_qenc(
    file_bytes: &[u8],
    public_key: &[u8],
    options: &EncryptQencOptions,
) -> Result<Vec<u8>> {
    if file_bytes.is_empty() {
        return Err(err("fileBytes must be a non-empty Uint8Array"));
    }
    if file_bytes.len() > MAX_FILE_SIZE {
        return Err(err(format!(
            "File size {} exceeds maximum allowed size ({MAX_FILE_SIZE} bytes)",
            file_bytes.len()
        )));
    }

    let (encapsulated_key, mut shared_secret) =
        encapsulate(public_key, options.encapsulation_seed)?;
    let container_nonce = match options.container_nonce {
        Some(container_nonce) => container_nonce,
        None => random_array()?,
    };
    let kdf_salt = match options.kdf_salt {
        Some(kdf_salt) => kdf_salt,
        None => random_array()?,
    };

    let private_metadata = WrappedPayloadPrivateMetadata {
        original_filename: options.original_filename.clone(),
        timestamp: options
            .timestamp
            .clone()
            .unwrap_or_else(current_iso8601_utc_millis),
        file_hash: sha3_512_hex(file_bytes),
        original_length: file_bytes.len() as u64,
    };
    let mut payload = wrap_wrapped_payload(&private_metadata, file_bytes)?;
    let payload_length = payload.len() as u64;
    let is_per_chunk = payload.len() > CHUNK_SIZE;
    let aead_mode = if is_per_chunk {
        "per-chunk-aead"
    } else {
        "single-container-aead"
    };
    let chunk_count = payload.len().div_ceil(CHUNK_SIZE) as u64;
    let result = (|| {
        let metadata =
            build_qenc_metadata(aead_mode, payload_length, CHUNK_SIZE as u64, chunk_count)?;
        let meta_bytes = serialize_qenc_metadata(&metadata)?;
        let mut derived = derive_key_with_kmac(
            &shared_secret,
            &kdf_salt,
            &meta_bytes,
            &metadata.domain_strings,
        )?;
        let key_commitment = compute_key_commitment(&derived.kenc);
        let header = build_qenc_header(
            &encapsulated_key,
            &container_nonce,
            &kdf_salt,
            &meta_bytes,
            &key_commitment,
        )?;

        let inner = match metadata.aead_mode.as_str() {
            "single-container-aead" => {
                let encrypted_payload =
                    encrypt_chunk(&derived.kenc, &payload, &container_nonce, &header)?;
                let mut container = Vec::with_capacity(header.len() + encrypted_payload.len());
                container.extend_from_slice(&header);
                container.extend_from_slice(&encrypted_payload);
                Ok(container)
            }
            "per-chunk-aead" => {
                let encrypted_payload = encrypt_per_chunk(
                    &payload,
                    &header,
                    &metadata,
                    &container_nonce,
                    &derived.kenc,
                    &derived.kiv,
                )?;
                let mut container = Vec::with_capacity(header.len() + encrypted_payload.len());
                container.extend_from_slice(&header);
                container.extend_from_slice(&encrypted_payload);
                Ok(container)
            }
            other => return Err(err(format!("Unsupported AEAD mode: {other}"))),
        };

        derived.kraw.zeroize();
        derived.kenc.zeroize();
        derived.kiv.zeroize();
        inner
    })();

    shared_secret.zeroize();
    payload.zeroize();
    result
}

pub fn decrypt_qenc(container_bytes: &[u8], secret_key: &[u8]) -> Result<DecryptedQenc> {
    let parsed = parse_qenc_header(container_bytes)?;
    let _nonce_contract = validate_container_policy_metadata(&parsed.metadata, false)?;
    let mut shared_secret = decapsulate(&parsed.encapsulated_key, secret_key)?;
    let mut derived = derive_key_with_kmac(
        &shared_secret,
        &parsed.kdf_salt,
        &parsed.meta_bytes,
        &parsed.metadata.domain_strings,
    )?;

    let result = (|| {
        if !verify_key_commitment(&derived.kenc, &parsed.stored_key_commitment) {
            return Err(coded(
                QvCode::AeadFailed,
                "Key commitment verification failed. Container may be corrupted or tampered with.",
            ));
        }

        let encrypted_data = &container_bytes[parsed.offset..];
        let mut decrypted_payload = match parsed.metadata.aead_mode.as_str() {
            "single-container-aead" => decrypt_chunk(
                &derived.kenc,
                encrypted_data,
                &parsed.container_nonce,
                &parsed.header,
            )?,
            "per-chunk-aead" => {
                decrypt_per_chunk(&parsed, encrypted_data, &derived.kenc, &derived.kiv)?
            }
            other => return Err(err(format!("Unsupported AEAD mode: {other}"))),
        };

        let payload_format = parsed.metadata.payload_format.clone().unwrap_or_default();
        if payload_format != "wrapped-v1" {
            decrypted_payload.zeroize();
            return Err(err(format!(
                "Unsupported payload format: {}",
                if payload_format.is_empty() {
                    "unknown"
                } else {
                    &payload_format
                }
            )));
        }

        let (private_metadata, file_bytes) = match unwrap_wrapped_payload(&decrypted_payload) {
            Ok(value) => value,
            Err(error) => {
                decrypted_payload.zeroize();
                return Err(error);
            }
        };
        decrypted_payload.zeroize();

        let recovered_file_hash = sha3_512_hex(&file_bytes);
        if !private_metadata
            .file_hash
            .eq_ignore_ascii_case(&recovered_file_hash)
        {
            return Err(err(
                "Wrapped payload fileHash does not match decrypted payload",
            ));
        }

        Ok(DecryptedQenc {
            file_bytes,
            private_metadata,
            warnings: Vec::new(),
        })
    })();

    shared_secret.zeroize();
    derived.zeroize();
    result
}

pub fn current_iso8601_utc_millis() -> String {
    OffsetDateTime::now_utc()
        .format(&format_description!(
            "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
        ))
        .expect("valid JS-compatible timestamp format")
}

fn decrypt_per_chunk(
    parsed: &QencHeader,
    encrypted_data: &[u8],
    kenc: &[u8; 32],
    kiv: &[u8; 32],
) -> Result<Vec<u8>> {
    let payload_length = parsed
        .metadata
        .payload_length
        .ok_or_else(|| err("Invalid metadata: payloadLength must be a positive integer"))?;
    let chunk_count = parsed
        .metadata
        .chunk_count
        .ok_or_else(|| err("Invalid metadata: per-chunk-aead requires chunkCount"))?;
    let chunk_size = parsed
        .metadata
        .chunk_size
        .ok_or_else(|| err("Invalid metadata: chunkSize must be a positive integer"))?;

    assert_per_chunk_nonce_contract(
        chunk_count,
        parsed.metadata.max_chunk_count,
        parsed.metadata.counter_bits,
        &parsed.metadata.iv_strategy,
    )?;

    let mut plaintext = Vec::with_capacity(payload_length as usize);
    let mut encrypted_offset = 0usize;

    for index in 0..chunk_count {
        let plain_len = chunk_size.min(payload_length - (index * chunk_size));
        let enc_len = plain_len + 16;
        let enc_end = encrypted_offset + enc_len as usize;
        if enc_end > encrypted_data.len() {
            plaintext.zeroize();
            return Err(err(
                "Encrypted payload has trailing or truncated chunk data",
            ));
        }
        let chunk_ciphertext = &encrypted_data[encrypted_offset..enc_end];
        let iv = derive_chunk_iv_from_k(
            kiv,
            &parsed.container_nonce,
            index as u32,
            &parsed.metadata.domain_strings.iv,
            Some(chunk_count),
            parsed.metadata.max_chunk_count,
            parsed.metadata.counter_bits,
            &parsed.metadata.iv_strategy,
        )?;
        let aad = build_chunk_aad(&parsed.header, index as u32, plain_len as u32);
        let mut chunk_plaintext = match decrypt_chunk(kenc, chunk_ciphertext, &iv, &aad) {
            Ok(chunk_plaintext) => chunk_plaintext,
            Err(error) => {
                plaintext.zeroize();
                return Err(error);
            }
        };
        plaintext.extend_from_slice(&chunk_plaintext);
        chunk_plaintext.zeroize();
        encrypted_offset = enc_end;
    }

    if encrypted_offset != encrypted_data.len() {
        plaintext.zeroize();
        return Err(err(
            "Encrypted payload has trailing or truncated chunk data",
        ));
    }

    Ok(plaintext)
}

fn encrypt_per_chunk(
    payload: &[u8],
    header: &[u8],
    metadata: &crate::qenc::metadata::QencMetadata,
    container_nonce: &[u8; 12],
    kenc: &[u8; 32],
    kiv: &[u8; 32],
) -> Result<Vec<u8>> {
    let chunk_count = metadata
        .chunk_count
        .ok_or_else(|| err("Invalid metadata: per-chunk-aead requires chunkCount"))?;
    let chunk_size = metadata
        .chunk_size
        .ok_or_else(|| err("Invalid metadata: chunkSize must be a positive integer"))?;

    assert_per_chunk_nonce_contract(
        chunk_count,
        metadata.max_chunk_count,
        metadata.counter_bits,
        &metadata.iv_strategy,
    )?;

    let mut encrypted = Vec::new();
    for index in 0..chunk_count {
        let plain_offset = (index * chunk_size) as usize;
        let plain_len = chunk_size.min((payload.len() - plain_offset) as u64) as usize;
        let plain_chunk = &payload[plain_offset..plain_offset + plain_len];
        let iv = derive_chunk_iv_from_k(
            kiv,
            container_nonce,
            index as u32,
            &metadata.domain_strings.iv,
            Some(chunk_count),
            metadata.max_chunk_count,
            metadata.counter_bits,
            &metadata.iv_strategy,
        )?;
        let aad = build_chunk_aad(header, index as u32, plain_len as u32);
        let cipher_chunk = encrypt_chunk(kenc, plain_chunk, &iv, &aad)?;
        encrypted.extend_from_slice(&cipher_chunk);
    }
    Ok(encrypted)
}

fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    fill_random(&mut bytes)?;
    Ok(bytes)
}
