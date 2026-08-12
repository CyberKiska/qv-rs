use fips203::ml_kem_1024;
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{coded, err, QvCode, Result};
use crate::rng::SystemRng;

pub const ML_KEM_1024_PUBLIC_KEY_SIZE: usize = 1568;
pub const ML_KEM_1024_SECRET_KEY_SIZE: usize = 3168;
pub const ML_KEM_1024_ENCAPSULATED_KEY_SIZE: usize = 1568;
pub const ML_KEM_1024_SHARED_SECRET_SIZE: usize = 32;

pub fn generate_key_pair() -> Result<(Vec<u8>, Vec<u8>)> {
    generate_key_pair_inner(None)
}

#[cfg(feature = "deterministic-test-vectors")]
pub fn generate_key_pair_deterministic(seed: [u8; 64]) -> Result<(Vec<u8>, Vec<u8>)> {
    generate_key_pair_inner(Some(seed))
}

fn generate_key_pair_inner(custom_seed: Option<[u8; 64]>) -> Result<(Vec<u8>, Vec<u8>)> {
    let (encaps_key, decaps_key) = match custom_seed {
        Some(mut seed) => {
            let mut d = Zeroizing::new([0u8; 32]);
            let mut z = Zeroizing::new([0u8; 32]);
            d.copy_from_slice(&seed[..32]);
            z.copy_from_slice(&seed[32..]);
            seed.zeroize();
            ml_kem_1024::KG::keygen_from_seed(*d, *z)
        }
        None => ml_kem_1024::KG::try_keygen_with_rng(&mut SystemRng).map_err(|error| {
            coded(
                QvCode::EntropyFailed,
                format!("ML-KEM-1024 key generation failed: {error}"),
            )
        })?,
    };

    let public_key = encaps_key.into_bytes().to_vec();
    let secret_key_bytes = Zeroizing::new(decaps_key.into_bytes());
    let secret_key = secret_key_bytes.to_vec();
    validate_public_key(&public_key)?;
    validate_secret_key(&secret_key)?;
    Ok((public_key, secret_key))
}

pub fn encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
    encapsulate_inner(public_key, None)
}

#[cfg(feature = "deterministic-test-vectors")]
pub fn encapsulate_deterministic(public_key: &[u8], seed: [u8; 32]) -> Result<(Vec<u8>, [u8; 32])> {
    encapsulate_inner(public_key, Some(seed))
}

fn encapsulate_inner(public_key: &[u8], seed: Option<[u8; 32]>) -> Result<(Vec<u8>, [u8; 32])> {
    validate_public_key(public_key)?;
    let encaps_key = ml_kem_1024::EncapsKey::try_from_bytes(
        public_key
            .try_into()
            .map_err(|_| coded(QvCode::KeyRejected, "Public key must be 1568 bytes"))?,
    )
    .map_err(|error| {
        coded(
            QvCode::KeyRejected,
            format!("Invalid ML-KEM-1024 public key bytes: {error}"),
        )
    })?;

    let (shared_secret, ciphertext) = match seed {
        Some(mut seed) => {
            let result = encaps_key.encaps_from_seed(&seed);
            seed.zeroize();
            result
        }
        None => encaps_key
            .try_encaps_with_rng(&mut SystemRng)
            .map_err(|error| {
                coded(
                    QvCode::EntropyFailed,
                    format!("ML-KEM-1024 encapsulation failed: {error}"),
                )
            })?,
    };

    Ok((ciphertext.into_bytes().to_vec(), shared_secret.into_bytes()))
}

pub fn decapsulate(ciphertext: &[u8], secret_key: &[u8]) -> Result<[u8; 32]> {
    validate_encapsulated_key(ciphertext)?;
    validate_secret_key(secret_key)?;

    let mut secret_key_bytes = Zeroizing::new([0u8; ML_KEM_1024_SECRET_KEY_SIZE]);
    secret_key_bytes.copy_from_slice(secret_key);
    let decaps_key =
        ml_kem_1024::DecapsKey::try_from_bytes(*secret_key_bytes).map_err(|error| {
            coded(
                QvCode::KeyRejected,
                format!("Invalid ML-KEM-1024 secret key bytes: {error}"),
            )
        })?;
    let ciphertext = ml_kem_1024::CipherText::try_from_bytes(
        ciphertext
            .try_into()
            .map_err(|_| err("Ciphertext must be 1568 bytes"))?,
    )
    .map_err(|error| err(format!("Invalid ML-KEM-1024 ciphertext bytes: {error}")))?;

    let shared_secret = decaps_key
        .try_decaps(&ciphertext)
        .map_err(|error| {
            err(format!(
                "KEM decapsulation failed. The key may be incorrect or the ciphertext corrupted: {error}"
            ))
        })?;
    Ok(shared_secret.into_bytes())
}

pub fn validate_public_key(public_key: &[u8]) -> Result<()> {
    if public_key.len() != ML_KEM_1024_PUBLIC_KEY_SIZE {
        return Err(coded(
            QvCode::KeyRejected,
            format!(
                "Invalid ML-KEM-1024 public key length: expected {ML_KEM_1024_PUBLIC_KEY_SIZE} bytes, got {}",
                public_key.len()
            ),
        ));
    }
    Ok(())
}

pub fn validate_secret_key(secret_key: &[u8]) -> Result<()> {
    if secret_key.len() != ML_KEM_1024_SECRET_KEY_SIZE {
        return Err(coded(
            QvCode::KeyRejected,
            format!(
                "Invalid ML-KEM-1024 secret key length: expected {ML_KEM_1024_SECRET_KEY_SIZE} bytes, got {}",
                secret_key.len()
            ),
        ));
    }
    Ok(())
}

pub fn validate_encapsulated_key(encapsulated_key: &[u8]) -> Result<()> {
    if encapsulated_key.len() != ML_KEM_1024_ENCAPSULATED_KEY_SIZE {
        return Err(err(format!(
            "Invalid ML-KEM-1024 encapsulated key length: expected {ML_KEM_1024_ENCAPSULATED_KEY_SIZE} bytes, got {}",
            encapsulated_key.len()
        )));
    }
    Ok(())
}
