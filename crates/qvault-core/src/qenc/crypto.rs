use std::collections::{HashSet, VecDeque};
use std::sync::{Mutex, OnceLock};

use crate::aead::{
    assert_per_chunk_nonce_contract, build_chunk_aad, decrypt_chunk, derive_chunk_iv_from_k,
    encrypt_chunk, PerChunkIvParams,
};
use crate::error::{coded, err, QvCode, Result};
use crate::hash::{sha3_256, sha3_512_hex};
use crate::kdf::KDF_SALT_SIZE;
use crate::kdf::{compute_key_commitment, derive_key_with_kmac, verify_key_commitment};
#[cfg(feature = "deterministic-test-vectors")]
use crate::mlkem::encapsulate_deterministic;
use crate::mlkem::{decapsulate, encapsulate};
use crate::policy::validate_container_policy_metadata;
use crate::qenc::header::{build_qenc_header, parse_qenc_header};
use crate::qenc::metadata::{
    authenticated_geometry, build_qenc_metadata, serialize_qenc_metadata, AuthenticatedGeometry,
};
use crate::qenc::payload::{
    unwrap_wrapped_payload, wrap_wrapped_payload, WrappedPayloadPrivateMetadata,
};
use crate::qenc::QencHeader;
use crate::rng::fill_random;
use time::OffsetDateTime;
#[cfg(feature = "deterministic-test-vectors")]
use zeroize::ZeroizeOnDrop;
use zeroize::{Zeroize, Zeroizing};

pub const CHUNK_SIZE: usize = 8 * 1024 * 1024;
pub const MAX_FILE_SIZE: usize = 1024 * 1024 * 1024;
/// Maximum complete QENC container size, including wrapped metadata, header,
/// and per-chunk authentication tags.
pub const MAX_QENC_CONTAINER_SIZE: usize = MAX_FILE_SIZE + (1024 * 1024);
const RECENT_ENCRYPTION_TUPLE_LIMIT: usize = 4096;

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

impl Drop for DecryptedQenc {
    fn drop(&mut self) {
        self.file_bytes.zeroize();
    }
}

#[derive(Clone, Default)]
pub struct EncryptQencOptions {
    pub original_filename: Option<String>,
    pub timestamp: Option<String>,
}

/// Exact randomness for pinned interoperability vectors.
///
/// Enabling this type in a production build permits catastrophic AES-GCM nonce
/// and key reuse. It is therefore available only through the non-default
/// `deterministic-test-vectors` feature.
#[cfg(feature = "deterministic-test-vectors")]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DeterministicQencTestVectorOptions {
    pub original_filename: Option<String>,
    pub timestamp: Option<String>,
    pub encapsulation_seed: [u8; 32],
    pub container_nonce: [u8; 12],
    pub kdf_salt: [u8; KDF_SALT_SIZE],
}

pub fn encrypt_qenc(
    file_bytes: &[u8],
    public_key: &[u8],
    options: &EncryptQencOptions,
) -> Result<Vec<u8>> {
    encrypt_qenc_inner(file_bytes, public_key, options, None)
}

#[cfg(feature = "deterministic-test-vectors")]
pub fn encrypt_qenc_deterministic(
    file_bytes: &[u8],
    public_key: &[u8],
    options: &DeterministicQencTestVectorOptions,
) -> Result<Vec<u8>> {
    let ordinary_options = EncryptQencOptions {
        original_filename: options.original_filename.clone(),
        timestamp: options.timestamp.clone(),
    };
    let randomness = DeterministicQencRandomness {
        encapsulation_seed: options.encapsulation_seed,
        container_nonce: options.container_nonce,
        kdf_salt: options.kdf_salt,
    };
    encrypt_qenc_inner(file_bytes, public_key, &ordinary_options, Some(&randomness))
}

#[cfg(feature = "deterministic-test-vectors")]
#[derive(Zeroize, ZeroizeOnDrop)]
struct DeterministicQencRandomness {
    encapsulation_seed: [u8; 32],
    container_nonce: [u8; 12],
    kdf_salt: [u8; KDF_SALT_SIZE],
}

fn encrypt_qenc_inner(
    file_bytes: &[u8],
    public_key: &[u8],
    options: &EncryptQencOptions,
    #[cfg(feature = "deterministic-test-vectors")] deterministic: Option<
        &DeterministicQencRandomness,
    >,
    #[cfg(not(feature = "deterministic-test-vectors"))] _deterministic: Option<&()>,
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

    #[cfg(feature = "deterministic-test-vectors")]
    let (encapsulated_key, shared_secret) = match deterministic {
        Some(randomness) => encapsulate_deterministic(public_key, randomness.encapsulation_seed)?,
        None => encapsulate(public_key)?,
    };
    #[cfg(not(feature = "deterministic-test-vectors"))]
    let (encapsulated_key, shared_secret) = encapsulate(public_key)?;
    let shared_secret = Zeroizing::new(shared_secret);
    #[cfg(feature = "deterministic-test-vectors")]
    let (container_nonce, kdf_salt, enforce_tuple_uniqueness) = match deterministic {
        Some(randomness) => (randomness.container_nonce, randomness.kdf_salt, false),
        None => {
            let (nonce, salt) = random_qenc_fields()?;
            (nonce, salt, true)
        }
    };
    #[cfg(not(feature = "deterministic-test-vectors"))]
    let (container_nonce, kdf_salt, enforce_tuple_uniqueness) = {
        let (nonce, salt) = random_qenc_fields()?;
        (nonce, salt, true)
    };
    if enforce_tuple_uniqueness {
        remember_encryption_tuple(&encapsulated_key, &container_nonce, &kdf_salt)?;
    }

    let private_metadata = WrappedPayloadPrivateMetadata {
        original_filename: options.original_filename.clone(),
        timestamp: options
            .timestamp
            .clone()
            .unwrap_or_else(current_iso8601_utc_millis),
        file_hash: sha3_512_hex(file_bytes),
        original_length: file_bytes.len() as u64,
    };
    let payload = Zeroizing::new(wrap_wrapped_payload(&private_metadata, file_bytes)?);
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
            &shared_secret[..],
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

    result
}

pub fn decrypt_qenc(container_bytes: &[u8], secret_key: &[u8]) -> Result<DecryptedQenc> {
    let parsed = parse_qenc_header(container_bytes)?;
    let geometry = authenticated_geometry(&parsed.metadata)?;
    let expected_payload_length = usize::try_from(geometry.payload_length)
        .map_err(|_| err("Invalid metadata: payloadLength exceeds platform limits"))?;
    let _nonce_contract = validate_container_policy_metadata(&parsed.metadata, false)?;
    let shared_secret = Zeroizing::new(decapsulate(&parsed.encapsulated_key, secret_key)?);
    let mut derived = derive_key_with_kmac(
        &shared_secret[..],
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
        let decrypted_payload = Zeroizing::new(match parsed.metadata.aead_mode.as_str() {
            "single-container-aead" => decrypt_chunk(
                &derived.kenc,
                encrypted_data,
                &parsed.container_nonce,
                &parsed.header,
            )?,
            "per-chunk-aead" => decrypt_per_chunk(
                &parsed,
                encrypted_data,
                &geometry,
                &derived.kenc,
                &derived.kiv,
            )?,
            other => return Err(err(format!("Unsupported AEAD mode: {other}"))),
        });
        if decrypted_payload.len() != expected_payload_length {
            return Err(coded(
                QvCode::RestoredIntegrityFailed,
                format!(
                    "Decrypted payload length mismatch: expected {expected_payload_length}, got {}",
                    decrypted_payload.len()
                ),
            ));
        }

        let payload_format = parsed.metadata.payload_format.clone().unwrap_or_default();
        if payload_format != "wrapped-v1" {
            return Err(err(format!(
                "Unsupported payload format: {}",
                if payload_format.is_empty() {
                    "unknown"
                } else {
                    &payload_format
                }
            )));
        }

        let (private_metadata, file_bytes) = unwrap_wrapped_payload(&decrypted_payload)?;
        let mut file_bytes = Zeroizing::new(file_bytes);
        drop(decrypted_payload);

        let recovered_file_length = u64::try_from(file_bytes.len()).map_err(|_| {
            err("Decrypted file length exceeds the supported metadata integer range")
        })?;
        if private_metadata.original_length != recovered_file_length {
            return Err(coded(
                QvCode::RestoredIntegrityFailed,
                format!(
                    "Decrypted file length mismatch: expected {}, got {recovered_file_length}",
                    private_metadata.original_length
                ),
            ));
        }

        let recovered_file_hash = sha3_512_hex(&file_bytes);
        if private_metadata.file_hash != recovered_file_hash {
            return Err(coded(
                QvCode::RestoredIntegrityFailed,
                "Wrapped payload fileHash does not match decrypted payload",
            ));
        }

        Ok(DecryptedQenc {
            file_bytes: std::mem::take(&mut *file_bytes),
            private_metadata,
            warnings: Vec::new(),
        })
    })();

    derived.zeroize();
    result
}

pub fn current_iso8601_utc_millis() -> String {
    let time = OffsetDateTime::now_utc();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        time.year(),
        u8::from(time.month()),
        time.day(),
        time.hour(),
        time.minute(),
        time.second(),
        time.millisecond()
    )
}

fn decrypt_per_chunk(
    parsed: &QencHeader,
    encrypted_data: &[u8],
    geometry: &AuthenticatedGeometry,
    kenc: &[u8; 32],
    kiv: &[u8; 32],
) -> Result<Vec<u8>> {
    let payload_length = usize::try_from(geometry.payload_length)
        .map_err(|_| err("Invalid metadata: payloadLength exceeds platform limits"))?;
    let chunk_count = usize::try_from(geometry.chunk_count)
        .map_err(|_| err("Invalid metadata: chunkCount exceeds platform limits"))?;
    let chunk_size = usize::try_from(geometry.chunk_size)
        .map_err(|_| err("Invalid metadata: chunkSize exceeds platform limits"))?;

    assert_per_chunk_nonce_contract(
        geometry.chunk_count,
        parsed.metadata.max_chunk_count,
        parsed.metadata.counter_bits,
        &parsed.metadata.iv_strategy,
    )?;

    let mut plaintext = Zeroizing::new(Vec::new());
    plaintext
        .try_reserve_exact(payload_length)
        .map_err(|_| err("Unable to allocate authenticated payloadLength"))?;
    let mut encrypted_offset = 0usize;

    for index in 0..chunk_count {
        let plain_offset = index
            .checked_mul(chunk_size)
            .ok_or_else(|| err("Invalid metadata: chunk plaintext offset overflow"))?;
        let remaining = payload_length
            .checked_sub(plain_offset)
            .ok_or_else(|| err("Invalid metadata: chunk geometry exceeds payloadLength"))?;
        let plain_len = chunk_size.min(remaining);
        let enc_len = plain_len
            .checked_add(16)
            .ok_or_else(|| err("Invalid metadata: encrypted chunk length overflow"))?;
        let enc_end = encrypted_offset
            .checked_add(enc_len)
            .ok_or_else(|| err("Invalid metadata: encrypted payload offset overflow"))?;
        if enc_end > encrypted_data.len() {
            return Err(err(
                "Encrypted payload has trailing or truncated chunk data",
            ));
        }
        let chunk_ciphertext = &encrypted_data[encrypted_offset..enc_end];
        let index_u32 = u32::try_from(index)
            .map_err(|_| err("Invalid metadata: chunk index exceeds uint32 capacity"))?;
        let plain_len_u32 = u32::try_from(plain_len)
            .map_err(|_| err("Invalid metadata: chunk length exceeds uint32 capacity"))?;
        let iv = derive_chunk_iv_from_k(
            kiv,
            &parsed.container_nonce,
            index_u32,
            &parsed.metadata.domain_strings.iv,
            PerChunkIvParams {
                chunk_count: Some(geometry.chunk_count),
                max_chunk_count: parsed.metadata.max_chunk_count,
                counter_bits: parsed.metadata.counter_bits,
                iv_strategy: &parsed.metadata.iv_strategy,
            },
        )?;
        let aad = build_chunk_aad(&parsed.header, index_u32, plain_len_u32);
        let chunk_plaintext = match decrypt_chunk(kenc, chunk_ciphertext, &iv, &aad) {
            Ok(chunk_plaintext) => Zeroizing::new(chunk_plaintext),
            Err(error) => {
                return Err(error);
            }
        };
        if chunk_plaintext.len() != plain_len {
            return Err(coded(
                QvCode::RestoredIntegrityFailed,
                format!(
                    "Decrypted chunk length mismatch: expected {plain_len}, got {}",
                    chunk_plaintext.len()
                ),
            ));
        }
        plaintext.extend_from_slice(&chunk_plaintext);
        encrypted_offset = enc_end;
    }

    if encrypted_offset != encrypted_data.len() {
        return Err(err(
            "Encrypted payload has trailing or truncated chunk data",
        ));
    }
    if plaintext.len() != payload_length {
        return Err(coded(
            QvCode::RestoredIntegrityFailed,
            format!(
                "Decrypted payload length mismatch: expected {payload_length}, got {}",
                plaintext.len()
            ),
        ));
    }

    Ok(std::mem::take(&mut *plaintext))
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
            PerChunkIvParams {
                chunk_count: Some(chunk_count),
                max_chunk_count: metadata.max_chunk_count,
                counter_bits: metadata.counter_bits,
                iv_strategy: &metadata.iv_strategy,
            },
        )?;
        let aad = build_chunk_aad(header, index as u32, plain_len as u32);
        let cipher_chunk = encrypt_chunk(kenc, plain_chunk, &iv, &aad)?;
        encrypted.extend_from_slice(&cipher_chunk);
    }
    Ok(encrypted)
}

fn random_qenc_fields() -> Result<([u8; 12], [u8; KDF_SALT_SIZE])> {
    let mut bytes = [0u8; 12 + KDF_SALT_SIZE];
    fill_random(&mut bytes)?;
    let mut container_nonce = [0u8; 12];
    container_nonce.copy_from_slice(&bytes[..12]);
    let mut kdf_salt = [0u8; KDF_SALT_SIZE];
    kdf_salt.copy_from_slice(&bytes[12..]);
    Ok((container_nonce, kdf_salt))
}

#[derive(Default)]
struct RecentEncryptionTuples {
    insertion_order: VecDeque<[u8; 32]>,
    fingerprints: HashSet<[u8; 32]>,
}

impl RecentEncryptionTuples {
    fn insert_unique(&mut self, fingerprint: [u8; 32]) -> bool {
        if !self.fingerprints.insert(fingerprint) {
            return false;
        }
        self.insertion_order.push_back(fingerprint);
        if self.insertion_order.len() > RECENT_ENCRYPTION_TUPLE_LIMIT {
            if let Some(expired) = self.insertion_order.pop_front() {
                self.fingerprints.remove(&expired);
            }
        }
        true
    }
}

fn remember_encryption_tuple(
    encapsulated_key: &[u8],
    container_nonce: &[u8; 12],
    kdf_salt: &[u8; KDF_SALT_SIZE],
) -> Result<()> {
    static RECENT: OnceLock<Mutex<RecentEncryptionTuples>> = OnceLock::new();
    let mut preimage = Vec::with_capacity(
        b"qvault:qenc:encryption-randomness:v1".len()
            + encapsulated_key.len()
            + container_nonce.len()
            + kdf_salt.len(),
    );
    preimage.extend_from_slice(b"qvault:qenc:encryption-randomness:v1");
    preimage.extend_from_slice(encapsulated_key);
    preimage.extend_from_slice(container_nonce);
    preimage.extend_from_slice(kdf_salt);
    let fingerprint = sha3_256(&preimage);
    let mut recent = RECENT
        .get_or_init(|| Mutex::new(RecentEncryptionTuples::default()))
        .lock()
        .map_err(|_| {
            coded(
                QvCode::EntropyFailed,
                "Encryption randomness replay guard is unavailable",
            )
        })?;
    if !recent.insert_unique(fingerprint) {
        return Err(coded(
            QvCode::EntropyFailed,
            "Repeated encryption randomness detected; refusing potential AES-GCM key/nonce reuse",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recent_encryption_tuple_guard_rejects_duplicates_and_stays_bounded() {
        let mut recent = RecentEncryptionTuples::default();
        let first = [0x42; 32];
        assert!(recent.insert_unique(first));
        assert!(!recent.insert_unique(first));

        for value in 0..=RECENT_ENCRYPTION_TUPLE_LIMIT {
            let mut fingerprint = [0u8; 32];
            fingerprint[..8].copy_from_slice(&(value as u64).to_be_bytes());
            recent.insert_unique(fingerprint);
        }
        assert_eq!(recent.insertion_order.len(), RECENT_ENCRYPTION_TUPLE_LIMIT);
        assert_eq!(recent.fingerprints.len(), RECENT_ENCRYPTION_TUPLE_LIMIT);
    }
}
