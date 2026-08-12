#![cfg(feature = "deterministic-test-vectors")]

use anyhow::Result;
use serde_json::Value;

mod common;

use common::fixtures::{fixture_path, read_fixture_bytes};
use qvault_core::aead::{derive_chunk_iv_from_k, PerChunkIvParams};
use qvault_core::bytes::from_hex;
use qvault_core::generate_key_pair_deterministic;
use qvault_core::hash::sha3_512_hex;
use qvault_core::kdf::derive_key_with_kmac;
use qvault_core::qenc::metadata::parse_qenc_metadata_bytes;
use qvault_core::qenc::CHUNK_SIZE;
use qvault_core::{
    decapsulate, decrypt_qenc, encrypt_qenc_deterministic, parse_qenc_header,
    DeterministicQencTestVectorOptions,
};

fn read_fixture_json(path: impl AsRef<std::path::Path>) -> Result<Value> {
    let bytes = read_fixture_bytes(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

#[test]
fn seeded_fips203_keygen_matches_single_small_fixture() -> Result<()> {
    assert_seeded_keygen_matches_fixture("single-small")
}

#[test]
fn seeded_fips203_keygen_matches_split_5of3_oracle_seed_fixture() -> Result<()> {
    assert_seeded_keygen_matches_fixture("split-5of3-keygen")
}

#[test]
fn rust_decapsulation_matches_js_shared_secret() -> Result<()> {
    let fixture_dir = fixture_path("single-small");
    let expectations: Value = read_fixture_json(fixture_dir.join("expectations.json"))?;
    let qenc_bytes = read_fixture_bytes(fixture_dir.join("container.qenc"))?;
    let secret_key = read_fixture_bytes(fixture_dir.join("secret.qkey"))?;
    let parsed = parse_qenc_header(&qenc_bytes)?;

    let shared_secret = decapsulate(&parsed.encapsulated_key, &secret_key)?;
    assert_eq!(
        hex::encode(shared_secret),
        expectations["qenc"]["sharedSecretHex"].as_str().unwrap()
    );

    let derived = derive_key_with_kmac(
        &shared_secret,
        &parsed.kdf_salt,
        &parsed.meta_bytes,
        &parsed.metadata.domain_strings,
    )?;
    assert_eq!(
        hex::encode(derived.kraw),
        expectations["qenc"]["krawHex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(derived.kenc),
        expectations["qenc"]["kencHex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(derived.kiv),
        expectations["qenc"]["kivHex"].as_str().unwrap()
    );
    Ok(())
}

#[test]
fn rust_decrypts_js_single_small_qenc() -> Result<()> {
    assert_rust_decrypts_fixture("single-small")
}

#[test]
fn rust_chunk_iv_matches_oracle_expectations_vector() -> Result<()> {
    let exp_path = fixture_path("chunked-large").join("expectations.json");
    let expectations: Value = read_fixture_json(exp_path)?;
    let q = &expectations["qenc"];
    let meta_utf8 = q["metaUtf8"].as_str().expect("metaUtf8");
    let metadata = parse_qenc_metadata_bytes(meta_utf8.as_bytes())?;

    let kiv: [u8; 32] = from_hex(q["kivHex"].as_str().unwrap())?
        .try_into()
        .map_err(|_| anyhow::anyhow!("kivHex length"))?;
    let container_nonce: [u8; 12] = from_hex(q["containerNonceHex"].as_str().unwrap())?
        .try_into()
        .map_err(|_| anyhow::anyhow!("containerNonceHex length"))?;

    let iv = derive_chunk_iv_from_k(
        &kiv,
        &container_nonce,
        0,
        &metadata.domain_strings.iv,
        PerChunkIvParams {
            chunk_count: metadata.chunk_count,
            max_chunk_count: metadata.max_chunk_count,
            counter_bits: metadata.counter_bits,
            iv_strategy: &metadata.iv_strategy,
        },
    )?;

    assert_eq!(
        hex::encode(iv),
        q["firstChunkIvHex"].as_str().unwrap(),
        "per-chunk IV must match oracle-exported expectations"
    );
    Ok(())
}

#[test]
fn per_chunk_encrypt_decrypt_roundtrip_with_oracle_seeds() -> Result<()> {
    let exp_path = fixture_path("chunked-large").join("expectations.json");
    let expectations: Value = read_fixture_json(exp_path)?;
    let q = &expectations["qenc"];

    let seed_hex = expectations["input"]["keygenSeedHex"].as_str().unwrap();
    let seed: [u8; 64] = from_hex(seed_hex)?.try_into().unwrap();
    let (public_key, secret_key) = generate_key_pair_deterministic(seed)?;

    let payload_len = expectations["payloadLength"]
        .as_u64()
        .expect("payloadLength") as usize;
    assert!(
        payload_len > CHUNK_SIZE,
        "fixture must exercise per-chunk AEAD (payload > CHUNK_SIZE)"
    );
    let payload: Vec<u8> = vec![0xA7; payload_len];

    let container_nonce: [u8; 12] = from_hex(q["containerNonceHex"].as_str().unwrap())?
        .try_into()
        .map_err(|_| anyhow::anyhow!("containerNonceHex length"))?;
    let kdf_salt: [u8; 16] = from_hex(q["kdfSaltHex"].as_str().unwrap())?
        .try_into()
        .map_err(|_| anyhow::anyhow!("kdfSaltHex length"))?;
    let encapsulation_seed: [u8; 32] = from_hex(q["encapsulationSeedHex"].as_str().unwrap())?
        .try_into()
        .map_err(|_| anyhow::anyhow!("encapsulationSeedHex length"))?;

    let encrypted = encrypt_qenc_deterministic(
        &payload,
        &public_key,
        &DeterministicQencTestVectorOptions {
            original_filename: Some(
                expectations["input"]["originalFilename"]
                    .as_str()
                    .unwrap()
                    .to_string(),
            ),
            timestamp: Some(expectations["timestamp"].as_str().unwrap().to_string()),
            encapsulation_seed,
            container_nonce,
            kdf_salt,
        },
    )?;

    let decrypted = decrypt_qenc(&encrypted, &secret_key)?;
    assert_eq!(decrypted.file_bytes, payload);
    Ok(())
}

#[test]
fn rust_encrypt_matches_js_single_small_fixture() -> Result<()> {
    assert_rust_encrypt_matches_fixture("single-small")
}

fn assert_seeded_keygen_matches_fixture(name: &str) -> Result<()> {
    let fixture_dir = fixture_path(name);
    let expectations: Value = read_fixture_json(fixture_dir.join("expectations.json"))?;
    let seed_hex = expectations["input"]["keygenSeedHex"].as_str().unwrap();
    let seed: [u8; 64] = from_hex(seed_hex)?.try_into().unwrap();

    let (public_key, secret_key) = generate_key_pair_deterministic(seed)?;
    assert_eq!(
        public_key,
        read_fixture_bytes(fixture_dir.join("public.qkey"))?
    );
    assert_eq!(
        secret_key,
        read_fixture_bytes(fixture_dir.join("secret.qkey"))?
    );
    Ok(())
}

fn assert_rust_decrypts_fixture(name: &str) -> Result<()> {
    let fixture_dir = fixture_path(name);
    let expectations: Value = read_fixture_json(fixture_dir.join("expectations.json"))?;
    let qenc_bytes = read_fixture_bytes(fixture_dir.join("container.qenc"))?;
    let secret_key = read_fixture_bytes(fixture_dir.join("secret.qkey"))?;

    let decrypted = decrypt_qenc(&qenc_bytes, &secret_key)?;
    assert_eq!(
        sha3_512_hex(&decrypted.file_bytes),
        expectations["input"]["payloadHash"].as_str().unwrap()
    );
    assert_eq!(
        decrypted.private_metadata.original_filename.as_deref(),
        Some(expectations["input"]["originalFilename"].as_str().unwrap())
    );
    assert_eq!(
        decrypted.private_metadata.timestamp,
        expectations["timestamp"].as_str().unwrap()
    );
    assert_eq!(
        decrypted.private_metadata.file_hash,
        expectations["input"]["payloadHash"].as_str().unwrap()
    );
    assert_eq!(
        decrypted.private_metadata.original_length,
        expectations["payloadLength"].as_u64().unwrap()
    );
    Ok(())
}

fn assert_rust_encrypt_matches_fixture(name: &str) -> Result<()> {
    let fixture_dir = fixture_path(name);
    let expectations: Value = read_fixture_json(fixture_dir.join("expectations.json"))?;
    let payload = read_fixture_bytes(fixture_dir.join("payload.bin"))?;
    let public_key = read_fixture_bytes(fixture_dir.join("public.qkey"))?;
    let container_nonce: [u8; 12] =
        from_hex(expectations["qenc"]["containerNonceHex"].as_str().unwrap())?
            .try_into()
            .unwrap();
    let kdf_salt: [u8; 16] = from_hex(expectations["qenc"]["kdfSaltHex"].as_str().unwrap())?
        .try_into()
        .unwrap();
    let encapsulation_seed: [u8; 32] = from_hex(
        expectations["qenc"]["encapsulationSeedHex"]
            .as_str()
            .unwrap(),
    )?
    .try_into()
    .unwrap();

    let rust_qenc = encrypt_qenc_deterministic(
        &payload,
        &public_key,
        &DeterministicQencTestVectorOptions {
            original_filename: Some(
                expectations["input"]["originalFilename"]
                    .as_str()
                    .unwrap()
                    .to_string(),
            ),
            timestamp: Some(expectations["timestamp"].as_str().unwrap().to_string()),
            encapsulation_seed,
            container_nonce,
            kdf_salt,
        },
    )?;

    assert_eq!(
        rust_qenc,
        read_fixture_bytes(fixture_dir.join("container.qenc"))?
    );
    Ok(())
}
