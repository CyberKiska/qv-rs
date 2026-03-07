use anyhow::Result;
use serde_json::Value;

use qvault_core::aead::derive_chunk_iv_from_k;
use qvault_core::bytes::from_hex;
use qvault_core::generate_key_pair;
use qvault_core::hash::sha3_512_hex;
use qvault_core::kdf::derive_key_with_kmac;
use qvault_core::test_support::fixtures::{fixture_path, read_fixture_bytes, read_fixture_json};
use qvault_core::{decapsulate, decrypt_qenc, encrypt_qenc, parse_qenc_header, EncryptQencOptions};

#[test]
fn seeded_fips203_keygen_matches_single_small_fixture() -> Result<()> {
    assert_seeded_keygen_matches_fixture("single-small")
}

#[test]
fn seeded_fips203_keygen_matches_split_5of3_fixture() -> Result<()> {
    assert_seeded_keygen_matches_fixture("split-5of3")
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
fn rust_decrypts_js_chunked_large_qenc() -> Result<()> {
    assert_rust_decrypts_fixture("chunked-large")
}

#[test]
fn rust_chunk_iv_matches_js_fixture() -> Result<()> {
    let fixture_dir = fixture_path("chunked-large");
    let expectations: Value = read_fixture_json(fixture_dir.join("expectations.json"))?;
    let qenc_bytes = read_fixture_bytes(fixture_dir.join("container.qenc"))?;
    let secret_key = read_fixture_bytes(fixture_dir.join("secret.qkey"))?;
    let parsed = parse_qenc_header(&qenc_bytes)?;
    let shared_secret = decapsulate(&parsed.encapsulated_key, &secret_key)?;
    let derived = derive_key_with_kmac(
        &shared_secret,
        &parsed.kdf_salt,
        &parsed.meta_bytes,
        &parsed.metadata.domain_strings,
    )?;

    let iv = derive_chunk_iv_from_k(
        &derived.kiv,
        &parsed.container_nonce,
        0,
        &parsed.metadata.domain_strings.iv,
        parsed.metadata.chunk_count,
        parsed.metadata.max_chunk_count,
        parsed.metadata.counter_bits,
        &parsed.metadata.iv_strategy,
    )?;

    assert_eq!(
        hex::encode(iv),
        expectations["qenc"]["firstChunkIvHex"].as_str().unwrap()
    );
    Ok(())
}

#[test]
fn rust_encrypt_matches_js_single_small_fixture() -> Result<()> {
    assert_rust_encrypt_matches_fixture("single-small")
}

#[test]
fn rust_encrypt_matches_js_chunked_large_fixture() -> Result<()> {
    assert_rust_encrypt_matches_fixture("chunked-large")
}

fn assert_seeded_keygen_matches_fixture(name: &str) -> Result<()> {
    let fixture_dir = fixture_path(name);
    let expectations: Value = read_fixture_json(fixture_dir.join("expectations.json"))?;
    let seed_hex = expectations["input"]["keygenSeedHex"].as_str().unwrap();
    let seed: [u8; 64] = from_hex(seed_hex)?.try_into().unwrap();

    let (public_key, secret_key) = generate_key_pair(Some(seed))?;
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

    let rust_qenc = encrypt_qenc(
        &payload,
        &public_key,
        &EncryptQencOptions {
            original_filename: Some(
                expectations["input"]["originalFilename"]
                    .as_str()
                    .unwrap()
                    .to_string(),
            ),
            timestamp: Some(expectations["timestamp"].as_str().unwrap().to_string()),
            encapsulation_seed: Some(encapsulation_seed),
            container_nonce: Some(container_nonce),
            kdf_salt: Some(kdf_salt),
        },
    )?;

    assert_eq!(
        rust_qenc,
        read_fixture_bytes(fixture_dir.join("container.qenc"))?
    );
    Ok(())
}
