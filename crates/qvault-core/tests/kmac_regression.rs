use anyhow::Result;

use qvault_core::aead::{
    derive_chunk_iv_from_k, PerChunkIvParams, IV_STRATEGY_KMAC_PREFIX64_CTR32_V3,
    NONCE_COUNTER_BITS_U32, NONCE_MAX_CHUNK_COUNT_U32,
};
use qvault_core::kdf::kmac256;

#[test]
fn kmac_wrapper_matches_qv_hotfix_vectors() -> Result<()> {
    let key = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let message = b"Quantum Vault KMAC regression test";

    let out32 = kmac256(&key, message, 32, "quantum-vault:test:v2")?;
    let out8 = kmac256(&key, message, 8, "quantum-vault:test:v2")?;
    let out32_alt = kmac256(&key, message, 32, "quantum-vault:test:alt:v2")?;

    assert_eq!(
        hex::encode(&out32),
        "e4c32540bbeba9c4ada8e0b74df68e0dd9280181d1ee95cabe61a7f290a7253d"
    );
    assert_eq!(hex::encode(&out8), "166add657780655a");
    assert_eq!(
        hex::encode(&out32_alt),
        "e691cf1c1df8c2a55415532c0b1076e1891f11dc0af86c9cab46cc98485bbf88"
    );
    assert_ne!(out8.as_slice(), &out32[..8]);
    Ok(())
}

#[test]
fn derive_chunk_iv_matches_qv_hotfix_vector() -> Result<()> {
    let kiv = std::array::from_fn(|i| ((i * 7 + 3) & 0xff) as u8);
    let container_nonce = std::array::from_fn(|i| ((i * 5 + 11) & 0xff) as u8);
    let iv = derive_chunk_iv_from_k(
        &kiv,
        &container_nonce,
        7,
        "quantum-vault:chunk-iv:v2",
        PerChunkIvParams {
            chunk_count: Some(16),
            max_chunk_count: NONCE_MAX_CHUNK_COUNT_U32,
            counter_bits: NONCE_COUNTER_BITS_U32,
            iv_strategy: IV_STRATEGY_KMAC_PREFIX64_CTR32_V3,
        },
    )?;

    assert_eq!(hex::encode(iv), "1a0f9d63bb6bf37300000007");
    Ok(())
}
