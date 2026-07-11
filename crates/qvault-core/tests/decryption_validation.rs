use anyhow::Result;
use serde_json::Value;

mod common;

use common::fixtures::{fixture_path, read_fixture_bytes};
use qvault_core::aead::encrypt_chunk;
use qvault_core::error::QvCode;
use qvault_core::hash::sha3_512_hex;
use qvault_core::kdf::{compute_key_commitment, derive_key_with_kmac};
use qvault_core::qenc::payload::{wrap_wrapped_payload, WrappedPayloadPrivateMetadata};
use qvault_core::qenc::{build_qenc_metadata, serialize_qenc_metadata, CHUNK_SIZE};
use qvault_core::{
    build_qenc_header, decrypt_qenc, encapsulate, generate_key_pair, parse_qenc_header,
};

#[test]
fn decrypt_qenc_rejects_wrapped_payload_hash_mismatch() -> Result<()> {
    let payload = b"payload-with-mismatched-inner-hash";
    let private_metadata = WrappedPayloadPrivateMetadata {
        original_filename: Some("mismatch.bin".to_string()),
        timestamp: "2026-03-07T12:00:00.000Z".to_string(),
        file_hash: "00".repeat(64),
        original_length: payload.len() as u64,
    };
    let (container, secret_key) = build_test_wrapped_container(payload, &private_metadata)?;

    let error = decrypt_qenc(&container, &secret_key).unwrap_err();
    assert_eq!(error.qv_code(), Some(QvCode::RestoredIntegrityFailed));
    assert_eq!(
        error.to_string(),
        "Wrapped payload fileHash does not match decrypted payload"
    );
    Ok(())
}

#[test]
fn decrypt_qenc_rejects_wrapped_payload_original_length_mismatch() -> Result<()> {
    let payload = b"payload-with-mismatched-inner-length";
    let private_metadata = WrappedPayloadPrivateMetadata {
        original_filename: Some("length-mismatch.bin".to_string()),
        timestamp: "2026-03-07T12:00:00.000Z".to_string(),
        file_hash: sha3_512_hex(payload),
        original_length: payload.len() as u64 + 1,
    };
    let (container, secret_key) = build_test_wrapped_container(payload, &private_metadata)?;

    let error = decrypt_qenc(&container, &secret_key).unwrap_err();
    assert_eq!(error.qv_code(), Some(QvCode::RestoredIntegrityFailed));
    assert_eq!(
        error.to_string(),
        format!(
            "Decrypted file length mismatch: expected {}, got {}",
            payload.len() + 1,
            payload.len()
        )
    );
    Ok(())
}

#[test]
fn parse_qenc_header_rejects_authenticated_ciphertext_length_mismatch() -> Result<()> {
    let qenc_bytes = read_fixture_bytes(fixture_path("single-small").join("container.qenc"))?;

    let truncated = &qenc_bytes[..qenc_bytes.len() - 1];
    let error = parse_qenc_header(truncated).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("ciphertext length does not match authenticated geometry"),
        "unexpected truncated-ciphertext error: {error}"
    );

    let mut trailing = qenc_bytes;
    trailing.push(0);
    let error = parse_qenc_header(&trailing).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("ciphertext length does not match authenticated geometry"),
        "unexpected trailing-ciphertext error: {error}"
    );
    Ok(())
}

#[test]
fn decrypt_qenc_rejects_underflowing_chunk_geometry_before_crypto() -> Result<()> {
    let fixture = read_fixture_bytes(fixture_path("single-small").join("container.qenc"))?;
    let parsed = parse_qenc_header(&fixture)?;
    let mut metadata = build_qenc_metadata(
        "per-chunk-aead",
        CHUNK_SIZE as u64 + 1,
        CHUNK_SIZE as u64,
        2,
    )?;
    metadata.payload_length = Some(1);
    let malformed_meta_bytes = serde_json::to_vec(&metadata)?;
    let mut malformed = build_qenc_header(
        &parsed.encapsulated_key,
        &parsed.container_nonce,
        &parsed.kdf_salt,
        &malformed_meta_bytes,
        &parsed.stored_key_commitment,
    )?;
    malformed.extend_from_slice(&[0u8; 33]);

    let error = decrypt_qenc(&malformed, &[0u8; 1]).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("chunkCount does not match payloadLength/chunkSize geometry"),
        "unexpected malformed-geometry error: {error}"
    );
    Ok(())
}

#[test]
fn decrypt_qenc_rejects_policy_metadata_mismatch() -> Result<()> {
    let fixture_dir = fixture_path("single-small");
    let qenc_bytes = read_fixture_bytes(fixture_dir.join("container.qenc"))?;
    let secret_key = read_fixture_bytes(fixture_dir.join("secret.qkey"))?;
    let parsed = parse_qenc_header(&qenc_bytes)?;

    let mut metadata: Value = serde_json::from_slice(&parsed.meta_bytes)?;
    metadata["noncePolicyId"] = Value::String("QV-GCM-BAD-POLICY".to_string());
    let tampered_meta_bytes = serde_json::to_vec(&metadata)?;

    let header = build_qenc_header(
        &parsed.encapsulated_key,
        &parsed.container_nonce,
        &parsed.kdf_salt,
        &tampered_meta_bytes,
        &parsed.stored_key_commitment,
    )?;
    let mut tampered_container = header;
    tampered_container.extend_from_slice(&qenc_bytes[parsed.offset..]);

    let error = decrypt_qenc(&tampered_container, &secret_key).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("Unsupported noncePolicyId for single-container-aead"),
        "unexpected error: {error}"
    );
    Ok(())
}

fn build_test_wrapped_container(
    payload: &[u8],
    private_metadata: &WrappedPayloadPrivateMetadata,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let keygen_seed = [0x55u8; 64];
    let encapsulation_seed = [0x77u8; 32];
    let container_nonce = [0x13u8; 12];
    let kdf_salt = [0x24u8; 16];

    let (public_key, secret_key) = generate_key_pair(Some(keygen_seed))?;
    let (encapsulated_key, shared_secret) = encapsulate(&public_key, Some(encapsulation_seed))?;
    let wrapped_payload = wrap_wrapped_payload(private_metadata, payload)?;
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
    Ok((container, secret_key))
}
