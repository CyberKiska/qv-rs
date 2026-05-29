use tiny_keccak::{Hasher, Kmac};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::bytes::timing_safe_equal;
use crate::error::{err, Result};
use crate::hash::sha3_256;
use crate::qenc::metadata::DomainStrings;

pub const AES_KEY_SIZE: usize = 32;
pub const KDF_SALT_SIZE: usize = 16;
pub const KMAC256_DEFAULT_DKLEN: usize = 32;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DerivedKeys {
    pub kraw: [u8; 32],
    pub kenc: [u8; 32],
    pub kiv: [u8; 32],
}

pub fn kmac256(
    key: &[u8],
    message: &[u8],
    output_len: usize,
    customization: &str,
) -> Result<Vec<u8>> {
    if output_len == 0 {
        return Err(err("KMAC dkLen must be a positive integer"));
    }

    let mut output = vec![0u8; output_len];
    let mut kmac = Kmac::v256(key, customization.as_bytes());
    kmac.update(message);
    kmac.finalize(&mut output);
    Ok(output)
}

pub fn derive_key_with_kmac(
    shared_secret: &[u8],
    salt: &[u8],
    meta_bytes: &[u8],
    domain_strings: &DomainStrings,
) -> Result<DerivedKeys> {
    if salt.len() != KDF_SALT_SIZE {
        return Err(err(format!("KMAC KDF salt must be {KDF_SALT_SIZE} bytes")));
    }
    if domain_strings.kdf.is_empty() {
        return Err(err("KMAC KDF customization domain is required"));
    }
    if domain_strings.kenc.is_empty() {
        return Err(err("KMAC Kenc customization domain is required"));
    }
    if domain_strings.kiv.is_empty() {
        return Err(err("KMAC Kiv customization domain is required"));
    }
    if domain_strings.kdf == domain_strings.kenc
        || domain_strings.kdf == domain_strings.kiv
        || domain_strings.kdf == domain_strings.iv
        || domain_strings.kenc == domain_strings.kiv
        || domain_strings.kenc == domain_strings.iv
        || domain_strings.kiv == domain_strings.iv
    {
        return Err(err("KMAC customization domains must be distinct"));
    }

    let mut message = Zeroizing::new(Vec::with_capacity(salt.len() + meta_bytes.len()));
    message.extend_from_slice(salt);
    message.extend_from_slice(meta_bytes);

    let kraw = to_fixed_32(kmac256(
        shared_secret,
        &message,
        KMAC256_DEFAULT_DKLEN,
        &domain_strings.kdf,
    )?)?;
    let kenc = to_fixed_32(kmac256(&kraw, &[1], AES_KEY_SIZE, &domain_strings.kenc)?)?;
    let kiv = to_fixed_32(kmac256(&kraw, &[2], AES_KEY_SIZE, &domain_strings.kiv)?)?;

    Ok(DerivedKeys { kraw, kenc, kiv })
}

pub fn compute_key_commitment(kenc: &[u8; 32]) -> [u8; 32] {
    sha3_256(kenc)
}

pub fn verify_key_commitment(kenc: &[u8; 32], expected_commitment: &[u8; 32]) -> bool {
    let computed = compute_key_commitment(kenc);
    timing_safe_equal(&computed, expected_commitment)
}

fn to_fixed_32(bytes: Vec<u8>) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| err("Expected 32-byte KMAC output"))
}
