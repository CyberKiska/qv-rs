use anyhow::Result;
use serde_json::Value;

use qvault_core::aead::{
    build_chunk_aad, decrypt_chunk, derive_chunk_iv_from_k, encrypt_chunk, PerChunkIvParams,
    IV_STRATEGY_KMAC_PREFIX64_CTR32_V3, NONCE_COUNTER_BITS_U32, NONCE_MAX_CHUNK_COUNT_U32,
};
use qvault_core::auth::signature_suites::{
    get_signature_suite_info, list_supported_signature_suites, normalize_signature_suite,
};
use qvault_core::kdf::{derive_key_with_kmac, KDF_SALT_SIZE};
use qvault_core::mlkem::{
    ML_KEM_1024_ENCAPSULATED_KEY_SIZE, ML_KEM_1024_PUBLIC_KEY_SIZE, ML_KEM_1024_SECRET_KEY_SIZE,
    ML_KEM_1024_SHARED_SECRET_SIZE,
};
use qvault_core::policy::{
    validate_container_policy_metadata, AAD_POLICY_ID_V1, CRYPTO_PROFILE_ID_V2, KDF_TREE_ID_V2,
};
use qvault_core::qenc::metadata::{
    build_qenc_metadata, parse_qenc_metadata_bytes, serialize_qenc_metadata,
    AEAD_ALG_ID_AES_256_GCM, KDF_ALG_ID_KMAC256, KEM_ALG_ID_ML_KEM_1024,
};
use qvault_core::{encapsulate, generate_key_pair};

#[test]
fn qenc_metadata_fixes_current_algorithm_and_policy_ids() -> Result<()> {
    let metadata = build_qenc_metadata("single-container-aead", 128, 8 * 1024 * 1024, 1)?;

    assert_eq!(metadata.kem.as_deref(), Some(KEM_ALG_ID_ML_KEM_1024));
    assert_eq!(metadata.kdf.as_deref(), Some(KDF_ALG_ID_KMAC256));
    assert_eq!(metadata.aead.as_deref(), Some(AEAD_ALG_ID_AES_256_GCM));
    assert_eq!(
        metadata.crypto_profile_id.as_deref(),
        Some(CRYPTO_PROFILE_ID_V2)
    );
    assert_eq!(metadata.kdf_tree_id.as_deref(), Some(KDF_TREE_ID_V2));
    assert_eq!(metadata.aad_policy_id.as_deref(), Some(AAD_POLICY_ID_V1));

    validate_container_policy_metadata(&metadata, false)?;
    let parsed = parse_qenc_metadata_bytes(&serialize_qenc_metadata(&metadata)?)?;
    assert_eq!(parsed, metadata);
    Ok(())
}

#[test]
fn qenc_metadata_rejects_wrong_present_algorithm_ids() -> Result<()> {
    let metadata = build_qenc_metadata("single-container-aead", 128, 8 * 1024 * 1024, 1)?;
    let base = serde_json::to_value(&metadata)?;

    for (field, bad_value, expected_message) in [
        ("KEM", "ML-KEM-768", "Unsupported KEM"),
        ("KDF", "HKDF-SHA256", "Unsupported KDF"),
        ("AEAD", "AES-128-GCM", "Unsupported AEAD"),
    ] {
        let mut value = base.clone();
        value[field] = Value::String(bad_value.to_string());
        let error = parse_qenc_metadata_bytes(&serde_json::to_vec(&value)?).unwrap_err();
        assert!(
            error.to_string().contains(expected_message),
            "{field} should reject {bad_value}; got {error}"
        );
    }
    Ok(())
}

#[test]
fn qenc_metadata_rejects_duplicate_and_unknown_fields() -> Result<()> {
    let metadata = build_qenc_metadata("single-container-aead", 128, 8 * 1024 * 1024, 1)?;
    let serialized = String::from_utf8(serialize_qenc_metadata(&metadata)?)?;
    let duplicate = serialized.replacen(
        "{\"KEM\":\"ML-KEM-1024\"",
        "{\"KEM\":\"ML-KEM-1024\",\"KEM\":\"ML-KEM-768\"",
        1,
    );
    let error = parse_qenc_metadata_bytes(duplicate.as_bytes()).unwrap_err();
    assert!(
        error.to_string().contains("Duplicate object key \"KEM\""),
        "duplicate key should fail closed; got {error}"
    );

    let mut value = serde_json::to_value(&metadata)?;
    value["DRBG"] = Value::String("SP800-90A".to_string());
    let error = parse_qenc_metadata_bytes(&serde_json::to_vec(&value)?).unwrap_err();
    assert!(
        error.to_string().contains("unknown field `DRBG`"),
        "unknown metadata fields must not be accepted; got {error}"
    );
    Ok(())
}

#[test]
fn kdf_requires_fixed_salt_length_and_distinct_domains() -> Result<()> {
    let metadata = build_qenc_metadata("single-container-aead", 128, 8 * 1024 * 1024, 1)?;
    let shared_secret = [0x42u8; ML_KEM_1024_SHARED_SECRET_SIZE];
    let salt = [0x24u8; KDF_SALT_SIZE];
    let meta_bytes = serialize_qenc_metadata(&metadata)?;

    let derived =
        derive_key_with_kmac(&shared_secret, &salt, &meta_bytes, &metadata.domain_strings)?;
    assert_ne!(derived.kraw, derived.kenc);
    assert_ne!(derived.kraw, derived.kiv);
    assert_ne!(derived.kenc, derived.kiv);

    let short_salt = [0x24u8; KDF_SALT_SIZE - 1];
    let error = match derive_key_with_kmac(
        &shared_secret,
        &short_salt,
        &meta_bytes,
        &metadata.domain_strings,
    ) {
        Ok(_) => panic!("short KDF salt should fail"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("KMAC KDF salt must be"));

    let mut duplicate_domains = metadata.domain_strings.clone();
    duplicate_domains.kiv = duplicate_domains.kenc.clone();
    let error = match derive_key_with_kmac(&shared_secret, &salt, &meta_bytes, &duplicate_domains) {
        Ok(_) => panic!("duplicate KMAC domains should fail"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("KMAC customization domains must be distinct"),
        "duplicate KMAC domains should fail; got {error}"
    );
    Ok(())
}

#[test]
fn aes_gcm_aad_is_injective_and_authenticated() -> Result<()> {
    let header = b"qv-header-bytes";
    let aad = build_chunk_aad(header, 1, 7);
    assert_eq!(&aad[..header.len()], header);
    assert_eq!(&aad[header.len()..header.len() + 4], &1u32.to_be_bytes());
    assert_eq!(&aad[header.len() + 4..], &7u32.to_be_bytes());

    let key = [0x42u8; 32];
    let iv = [0x24u8; 12];
    let plaintext = b"payload";
    let ciphertext = encrypt_chunk(&key, plaintext, &iv, &aad)?;
    assert_eq!(decrypt_chunk(&key, &ciphertext, &iv, &aad)?, plaintext);

    let tampered_aad = build_chunk_aad(header, 1, 8);
    let error = decrypt_chunk(&key, &ciphertext, &iv, &tampered_aad).unwrap_err();
    assert_eq!(error.to_string(), "AES-GCM decryption failed");
    Ok(())
}

#[test]
fn per_chunk_iv_counter_is_unique_big_endian_and_bounded() -> Result<()> {
    let kiv = [0x31u8; 32];
    let container_nonce = [0x42u8; 12];
    let iv0 = derive_chunk_iv_from_k(
        &kiv,
        &container_nonce,
        0,
        "quantum-vault:chunk-iv:v2",
        PerChunkIvParams {
            chunk_count: Some(2),
            max_chunk_count: NONCE_MAX_CHUNK_COUNT_U32,
            counter_bits: NONCE_COUNTER_BITS_U32,
            iv_strategy: IV_STRATEGY_KMAC_PREFIX64_CTR32_V3,
        },
    )?;
    let iv1 = derive_chunk_iv_from_k(
        &kiv,
        &container_nonce,
        1,
        "quantum-vault:chunk-iv:v2",
        PerChunkIvParams {
            chunk_count: Some(2),
            max_chunk_count: NONCE_MAX_CHUNK_COUNT_U32,
            counter_bits: NONCE_COUNTER_BITS_U32,
            iv_strategy: IV_STRATEGY_KMAC_PREFIX64_CTR32_V3,
        },
    )?;

    assert_eq!(
        &iv0[..8],
        &iv1[..8],
        "same key/nonce must share KMAC prefix"
    );
    assert_eq!(&iv0[8..], &0u32.to_be_bytes());
    assert_eq!(&iv1[8..], &1u32.to_be_bytes());
    assert_ne!(iv0, iv1);

    let error = derive_chunk_iv_from_k(
        &kiv,
        &container_nonce,
        2,
        "quantum-vault:chunk-iv:v2",
        PerChunkIvParams {
            chunk_count: Some(2),
            max_chunk_count: NONCE_MAX_CHUNK_COUNT_U32,
            counter_bits: NONCE_COUNTER_BITS_U32,
            iv_strategy: IV_STRATEGY_KMAC_PREFIX64_CTR32_V3,
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("chunkIndex 2 out of bounds"));
    Ok(())
}

#[test]
fn ml_kem_1024_lengths_are_bound_to_the_format() -> Result<()> {
    let seed = [0x5au8; 64];
    let encapsulation_seed = [0x33u8; 32];
    let (public_key, secret_key) = generate_key_pair(Some(seed))?;
    assert_eq!(public_key.len(), ML_KEM_1024_PUBLIC_KEY_SIZE);
    assert_eq!(secret_key.len(), ML_KEM_1024_SECRET_KEY_SIZE);

    let (ciphertext, shared_secret) = encapsulate(&public_key, Some(encapsulation_seed))?;
    assert_eq!(ciphertext.len(), ML_KEM_1024_ENCAPSULATED_KEY_SIZE);
    assert_eq!(shared_secret.len(), ML_KEM_1024_SHARED_SECRET_SIZE);

    let truncated_key = &public_key[..ML_KEM_1024_PUBLIC_KEY_SIZE - 1];
    let error = encapsulate(truncated_key, Some(encapsulation_seed)).unwrap_err();
    assert!(error
        .to_string()
        .contains("Invalid ML-KEM-1024 public key length"));
    Ok(())
}

#[test]
fn pq_signature_suite_registry_is_explicit_and_policy_classified() -> Result<()> {
    assert_eq!(
        list_supported_signature_suites(),
        &[
            "mldsa-44",
            "mldsa-65",
            "mldsa-87",
            "slhdsa-shake-128s",
            "slhdsa-shake-192s",
            "slhdsa-shake-256s",
            "slhdsa-shake-256f",
            "ed25519",
        ]
    );

    assert_eq!(normalize_signature_suite("ML-DSA-87")?, "mldsa-87");
    assert!(get_signature_suite_info("mldsa-87")?.strong_pq);
    assert!(get_signature_suite_info("slhdsa-shake-256f")?.strong_pq);
    assert!(!get_signature_suite_info("mldsa-65")?.strong_pq);
    assert!(get_signature_suite_info("ed25519")?.legacy);
    assert!(normalize_signature_suite("ml-kem-1024").is_err());
    Ok(())
}
