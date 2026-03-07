use anyhow::Result;

use qvault_core::aead::encrypt_chunk;
use qvault_core::kdf::{compute_key_commitment, derive_key_with_kmac};
use qvault_core::qenc::payload::{wrap_wrapped_payload, WrappedPayloadPrivateMetadata};
use qvault_core::qenc::{build_qenc_metadata, serialize_qenc_metadata, CHUNK_SIZE};
use qvault_core::{build_qenc_header, decrypt_qenc, encapsulate, generate_key_pair};

#[test]
fn decrypt_qenc_rejects_wrapped_payload_hash_mismatch() -> Result<()> {
    let payload = b"payload-with-mismatched-inner-hash";
    let keygen_seed = [0x55u8; 64];
    let encapsulation_seed = [0x77u8; 32];
    let container_nonce = [0x13u8; 12];
    let kdf_salt = [0x24u8; 16];
    let timestamp = "2026-03-07T12:00:00.000Z";

    let (public_key, secret_key) = generate_key_pair(Some(keygen_seed))?;
    let (encapsulated_key, shared_secret) = encapsulate(&public_key, Some(encapsulation_seed))?;
    let private_metadata = WrappedPayloadPrivateMetadata {
        original_filename: Some("mismatch.bin".to_string()),
        timestamp: timestamp.to_string(),
        file_hash: "00".repeat(64),
        original_length: payload.len() as u64,
    };
    let wrapped_payload = wrap_wrapped_payload(&private_metadata, payload)?;
    let metadata = build_qenc_metadata(
        "single-container-aead",
        wrapped_payload.len() as u64,
        CHUNK_SIZE as u64,
        1,
    )?;
    let meta_bytes = serialize_qenc_metadata(&metadata)?;
    let derived = derive_key_with_kmac(
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
    let ciphertext = encrypt_chunk(&derived.kenc, &wrapped_payload, &container_nonce, &header)?;
    let mut container = header;
    container.extend_from_slice(&ciphertext);

    let error = decrypt_qenc(&container, &secret_key).unwrap_err();
    assert_eq!(
        error.to_string(),
        "Wrapped payload fileHash does not match decrypted payload"
    );
    Ok(())
}
