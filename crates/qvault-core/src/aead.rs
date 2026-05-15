use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};

use crate::error::{coded, err, QvCode, Result};
use crate::kdf::kmac256;

pub const AES_IV_SIZE: usize = 12;
pub const AES_TAG_SIZE: usize = 16;
pub const NONCE_COUNTER_BITS_U32: u32 = 32;
pub const NONCE_MAX_CHUNK_COUNT_U32: u64 = 0xffff_ffff;
pub const IV_STRATEGY_SINGLE_IV: &str = "single-iv";
pub const IV_STRATEGY_KMAC_PREFIX64_CTR32_V3: &str = "kmac-prefix64-ctr32-v3";

pub fn assert_per_chunk_nonce_contract(
    chunk_count: u64,
    max_chunk_count: u64,
    counter_bits: u32,
    iv_strategy: &str,
) -> Result<()> {
    if iv_strategy != IV_STRATEGY_KMAC_PREFIX64_CTR32_V3 {
        return Err(err(format!(
            "Unsupported per-chunk iv_strategy: {iv_strategy}"
        )));
    }
    if counter_bits != NONCE_COUNTER_BITS_U32 {
        return Err(err(format!(
            "Unsupported counterBits for per-chunk AES-GCM: {counter_bits}"
        )));
    }
    if chunk_count == 0 {
        return Err(err("chunkCount must be a positive integer"));
    }
    if chunk_count > max_chunk_count {
        return Err(err(format!(
            "chunkCount exceeds nonce policy bound ({max_chunk_count})"
        )));
    }
    Ok(())
}

pub fn build_chunk_aad(header_bytes: &[u8], chunk_index: u32, plain_len: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(header_bytes.len() + 8);
    aad.extend_from_slice(header_bytes);
    aad.extend_from_slice(&chunk_index.to_be_bytes());
    aad.extend_from_slice(&plain_len.to_be_bytes());
    aad
}

pub fn derive_chunk_iv_from_k(
    kiv: &[u8; 32],
    container_nonce: &[u8; 12],
    chunk_index: u32,
    iv_customization: &str,
    chunk_count: Option<u64>,
    max_chunk_count: u64,
    counter_bits: u32,
    iv_strategy: &str,
) -> Result<[u8; 12]> {
    if iv_customization.is_empty() {
        return Err(err("IV customization domain is required"));
    }

    if let Some(chunk_count) = chunk_count {
        assert_per_chunk_nonce_contract(chunk_count, max_chunk_count, counter_bits, iv_strategy)?;
        if u64::from(chunk_index) >= chunk_count {
            return Err(err(format!(
                "chunkIndex {chunk_index} out of bounds for chunkCount {chunk_count}"
            )));
        }
    } else if iv_strategy != IV_STRATEGY_KMAC_PREFIX64_CTR32_V3 {
        return Err(err(format!(
            "Unsupported per-chunk iv_strategy: {iv_strategy}"
        )));
    }

    if iv_strategy != IV_STRATEGY_KMAC_PREFIX64_CTR32_V3 {
        return Err(err(format!(
            "Unsupported per-chunk iv_strategy: {iv_strategy}"
        )));
    }

    let prefix = kmac256(kiv, container_nonce, 8, iv_customization)?;
    let mut iv = [0u8; 12];
    iv[..8].copy_from_slice(&prefix);
    iv[8..].copy_from_slice(&chunk_index.to_be_bytes());
    Ok(iv)
}

pub fn decrypt_chunk(
    kenc: &[u8; 32],
    ciphertext: &[u8],
    iv: &[u8; 12],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(kenc)
        .map_err(|error| err(format!("Invalid AES-256-GCM key: {error}")))?;
    let nonce = Nonce::from_slice(iv);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| coded(QvCode::AeadFailed, "AES-GCM decryption failed"))
}

pub fn encrypt_chunk(
    kenc: &[u8; 32],
    plaintext: &[u8],
    iv: &[u8; 12],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(kenc)
        .map_err(|error| err(format!("Invalid AES-256-GCM key: {error}")))?;
    let nonce = Nonce::from_slice(iv);
    cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| err("AES-GCM encryption failed"))
}
