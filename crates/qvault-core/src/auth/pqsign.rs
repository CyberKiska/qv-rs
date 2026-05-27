use fips204::traits::{SerDes as MlDsaSerDes, Signer as MlDsaSigner};
use fips205::traits::{SerDes as SlhDsaSerDes, Signer as SlhDsaSigner};
use zeroize::Zeroizing;

use crate::auth::PqSignatureSuite;
use crate::error::{coded, QvCode, QvError, Result};
use crate::rng::SystemRng;

pub struct PqSigningKeypair {
    suite: PqSignatureSuite,
    public_key: Vec<u8>,
    secret_key: Zeroizing<Vec<u8>>,
}

impl PqSigningKeypair {
    pub fn suite(&self) -> PqSignatureSuite {
        self.suite
    }

    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }

    pub fn secret_key_bytes(&self) -> &[u8] {
        self.secret_key.as_slice()
    }

    pub fn into_parts(self) -> (PqSignatureSuite, Vec<u8>, Zeroizing<Vec<u8>>) {
        (self.suite, self.public_key, self.secret_key)
    }
}

pub fn generate_signing_keypair(suite: PqSignatureSuite) -> Result<PqSigningKeypair> {
    match suite {
        PqSignatureSuite::MlDsa44 => generate_ml_dsa_44(),
        PqSignatureSuite::MlDsa65 => generate_ml_dsa_65(),
        PqSignatureSuite::MlDsa87 => generate_ml_dsa_87(),
        PqSignatureSuite::SlhDsaShake128s => generate_slh_dsa_shake_128s(),
        PqSignatureSuite::SlhDsaShake192s => generate_slh_dsa_shake_192s(),
        PqSignatureSuite::SlhDsaShake256s => generate_slh_dsa_shake_256s(),
        PqSignatureSuite::SlhDsaShake256f => generate_slh_dsa_shake_256f(),
    }
}

pub fn public_from_secret(suite: PqSignatureSuite, secret_key_bytes: &[u8]) -> Result<Vec<u8>> {
    match suite {
        PqSignatureSuite::MlDsa44 => derive_ml_dsa_44_public(secret_key_bytes),
        PqSignatureSuite::MlDsa65 => derive_ml_dsa_65_public(secret_key_bytes),
        PqSignatureSuite::MlDsa87 => derive_ml_dsa_87_public(secret_key_bytes),
        PqSignatureSuite::SlhDsaShake128s => derive_slh_dsa_shake_128s_public(secret_key_bytes),
        PqSignatureSuite::SlhDsaShake192s => derive_slh_dsa_shake_192s_public(secret_key_bytes),
        PqSignatureSuite::SlhDsaShake256s => derive_slh_dsa_shake_256s_public(secret_key_bytes),
        PqSignatureSuite::SlhDsaShake256f => derive_slh_dsa_shake_256f_public(secret_key_bytes),
    }
}

fn generate_ml_dsa_44() -> Result<PqSigningKeypair> {
    let suite = PqSignatureSuite::MlDsa44;
    let (public_key, secret_key) = fips204::ml_dsa_44::try_keygen_with_rng(&mut SystemRng)
        .map_err(|error| entropy_failed(suite, "key generation", error))?;
    let public_key_bytes = public_key.into_bytes();
    let secret_key_bytes = Zeroizing::new(secret_key.into_bytes());
    finish_generated_keypair(suite, &public_key_bytes[..], &secret_key_bytes[..])
}

fn generate_ml_dsa_65() -> Result<PqSigningKeypair> {
    let suite = PqSignatureSuite::MlDsa65;
    let (public_key, secret_key) = fips204::ml_dsa_65::try_keygen_with_rng(&mut SystemRng)
        .map_err(|error| entropy_failed(suite, "key generation", error))?;
    let public_key_bytes = public_key.into_bytes();
    let secret_key_bytes = Zeroizing::new(secret_key.into_bytes());
    finish_generated_keypair(suite, &public_key_bytes[..], &secret_key_bytes[..])
}

fn generate_ml_dsa_87() -> Result<PqSigningKeypair> {
    let suite = PqSignatureSuite::MlDsa87;
    let (public_key, secret_key) = fips204::ml_dsa_87::try_keygen_with_rng(&mut SystemRng)
        .map_err(|error| entropy_failed(suite, "key generation", error))?;
    let public_key_bytes = public_key.into_bytes();
    let secret_key_bytes = Zeroizing::new(secret_key.into_bytes());
    finish_generated_keypair(suite, &public_key_bytes[..], &secret_key_bytes[..])
}

fn generate_slh_dsa_shake_128s() -> Result<PqSigningKeypair> {
    let suite = PqSignatureSuite::SlhDsaShake128s;
    let (public_key, secret_key) = fips205::slh_dsa_shake_128s::try_keygen_with_rng(&mut SystemRng)
        .map_err(|error| entropy_failed(suite, "key generation", error))?;
    let public_key_bytes = public_key.into_bytes();
    let secret_key_bytes = Zeroizing::new(secret_key.into_bytes());
    finish_generated_keypair(suite, &public_key_bytes[..], &secret_key_bytes[..])
}

fn generate_slh_dsa_shake_192s() -> Result<PqSigningKeypair> {
    let suite = PqSignatureSuite::SlhDsaShake192s;
    let (public_key, secret_key) = fips205::slh_dsa_shake_192s::try_keygen_with_rng(&mut SystemRng)
        .map_err(|error| entropy_failed(suite, "key generation", error))?;
    let public_key_bytes = public_key.into_bytes();
    let secret_key_bytes = Zeroizing::new(secret_key.into_bytes());
    finish_generated_keypair(suite, &public_key_bytes[..], &secret_key_bytes[..])
}

fn generate_slh_dsa_shake_256s() -> Result<PqSigningKeypair> {
    let suite = PqSignatureSuite::SlhDsaShake256s;
    let (public_key, secret_key) = fips205::slh_dsa_shake_256s::try_keygen_with_rng(&mut SystemRng)
        .map_err(|error| entropy_failed(suite, "key generation", error))?;
    let public_key_bytes = public_key.into_bytes();
    let secret_key_bytes = Zeroizing::new(secret_key.into_bytes());
    finish_generated_keypair(suite, &public_key_bytes[..], &secret_key_bytes[..])
}

fn generate_slh_dsa_shake_256f() -> Result<PqSigningKeypair> {
    let suite = PqSignatureSuite::SlhDsaShake256f;
    let (public_key, secret_key) = fips205::slh_dsa_shake_256f::try_keygen_with_rng(&mut SystemRng)
        .map_err(|error| entropy_failed(suite, "key generation", error))?;
    let public_key_bytes = public_key.into_bytes();
    let secret_key_bytes = Zeroizing::new(secret_key.into_bytes());
    finish_generated_keypair(suite, &public_key_bytes[..], &secret_key_bytes[..])
}

fn finish_generated_keypair(
    suite: PqSignatureSuite,
    public_key_bytes: &[u8],
    secret_key_bytes: &[u8],
) -> Result<PqSigningKeypair> {
    if public_key_bytes.len() != suite.public_key_len() {
        return Err(key_rejected(
            suite,
            format!(
                "Generated public key length mismatch: expected {} bytes, got {}",
                suite.public_key_len(),
                public_key_bytes.len()
            ),
        ));
    }
    if secret_key_bytes.len() != suite.secret_key_len() {
        return Err(key_rejected(
            suite,
            format!(
                "Generated secret key length mismatch: expected {} bytes, got {}",
                suite.secret_key_len(),
                secret_key_bytes.len()
            ),
        ));
    }

    let public_key = public_key_bytes.to_vec();
    let secret_key = Zeroizing::new(secret_key_bytes.to_vec());
    Ok(PqSigningKeypair {
        suite,
        public_key,
        secret_key,
    })
}

fn derive_ml_dsa_44_public(secret_key_bytes: &[u8]) -> Result<Vec<u8>> {
    let suite = PqSignatureSuite::MlDsa44;
    let secret_key_bytes =
        copy_secret_array::<{ fips204::ml_dsa_44::SK_LEN }>(suite, secret_key_bytes)?;
    let secret_key = fips204::ml_dsa_44::PrivateKey::try_from_bytes(*secret_key_bytes)
        .map_err(|error| key_rejected(suite, format!("Invalid secret key bytes: {error}")))?;
    Ok(secret_key.get_public_key().into_bytes().to_vec())
}

fn derive_ml_dsa_65_public(secret_key_bytes: &[u8]) -> Result<Vec<u8>> {
    let suite = PqSignatureSuite::MlDsa65;
    let secret_key_bytes =
        copy_secret_array::<{ fips204::ml_dsa_65::SK_LEN }>(suite, secret_key_bytes)?;
    let secret_key = fips204::ml_dsa_65::PrivateKey::try_from_bytes(*secret_key_bytes)
        .map_err(|error| key_rejected(suite, format!("Invalid secret key bytes: {error}")))?;
    Ok(secret_key.get_public_key().into_bytes().to_vec())
}

fn derive_ml_dsa_87_public(secret_key_bytes: &[u8]) -> Result<Vec<u8>> {
    let suite = PqSignatureSuite::MlDsa87;
    let secret_key_bytes =
        copy_secret_array::<{ fips204::ml_dsa_87::SK_LEN }>(suite, secret_key_bytes)?;
    let secret_key = fips204::ml_dsa_87::PrivateKey::try_from_bytes(*secret_key_bytes)
        .map_err(|error| key_rejected(suite, format!("Invalid secret key bytes: {error}")))?;
    Ok(secret_key.get_public_key().into_bytes().to_vec())
}

fn derive_slh_dsa_shake_128s_public(secret_key_bytes: &[u8]) -> Result<Vec<u8>> {
    let suite = PqSignatureSuite::SlhDsaShake128s;
    let secret_key_bytes =
        copy_secret_array::<{ fips205::slh_dsa_shake_128s::SK_LEN }>(suite, secret_key_bytes)?;
    let secret_key = fips205::slh_dsa_shake_128s::PrivateKey::try_from_bytes(&*secret_key_bytes)
        .map_err(|error| key_rejected(suite, format!("Invalid secret key bytes: {error}")))?;
    Ok(secret_key.get_public_key().into_bytes().to_vec())
}

fn derive_slh_dsa_shake_192s_public(secret_key_bytes: &[u8]) -> Result<Vec<u8>> {
    let suite = PqSignatureSuite::SlhDsaShake192s;
    let secret_key_bytes =
        copy_secret_array::<{ fips205::slh_dsa_shake_192s::SK_LEN }>(suite, secret_key_bytes)?;
    let secret_key = fips205::slh_dsa_shake_192s::PrivateKey::try_from_bytes(&*secret_key_bytes)
        .map_err(|error| key_rejected(suite, format!("Invalid secret key bytes: {error}")))?;
    Ok(secret_key.get_public_key().into_bytes().to_vec())
}

fn derive_slh_dsa_shake_256s_public(secret_key_bytes: &[u8]) -> Result<Vec<u8>> {
    let suite = PqSignatureSuite::SlhDsaShake256s;
    let secret_key_bytes =
        copy_secret_array::<{ fips205::slh_dsa_shake_256s::SK_LEN }>(suite, secret_key_bytes)?;
    let secret_key = fips205::slh_dsa_shake_256s::PrivateKey::try_from_bytes(&*secret_key_bytes)
        .map_err(|error| key_rejected(suite, format!("Invalid secret key bytes: {error}")))?;
    Ok(secret_key.get_public_key().into_bytes().to_vec())
}

fn derive_slh_dsa_shake_256f_public(secret_key_bytes: &[u8]) -> Result<Vec<u8>> {
    let suite = PqSignatureSuite::SlhDsaShake256f;
    let secret_key_bytes =
        copy_secret_array::<{ fips205::slh_dsa_shake_256f::SK_LEN }>(suite, secret_key_bytes)?;
    let secret_key = fips205::slh_dsa_shake_256f::PrivateKey::try_from_bytes(&*secret_key_bytes)
        .map_err(|error| key_rejected(suite, format!("Invalid secret key bytes: {error}")))?;
    Ok(secret_key.get_public_key().into_bytes().to_vec())
}

fn copy_secret_array<const N: usize>(
    suite: PqSignatureSuite,
    secret_key_bytes: &[u8],
) -> Result<Zeroizing<[u8; N]>> {
    if secret_key_bytes.len() != N {
        return Err(key_rejected(
            suite,
            format!(
                "Secret key length mismatch: expected {N} bytes, got {}",
                secret_key_bytes.len()
            ),
        ));
    }

    let mut out = [0u8; N];
    out.copy_from_slice(secret_key_bytes);
    Ok(Zeroizing::new(out))
}

fn entropy_failed(suite: PqSignatureSuite, operation: &str, error: &'static str) -> QvError {
    coded(
        QvCode::EntropyFailed,
        format!(
            "PQC signing {} failed for {}: {}",
            operation,
            suite.canonical_name(),
            error
        ),
    )
}

fn key_rejected(suite: PqSignatureSuite, message: impl Into<String>) -> QvError {
    coded(
        QvCode::KeyRejected,
        format!(
            "PQC signing key rejected for {}: {}",
            suite.canonical_name(),
            message.into()
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUPPORTED_SUITES: [PqSignatureSuite; 7] = [
        PqSignatureSuite::MlDsa44,
        PqSignatureSuite::MlDsa65,
        PqSignatureSuite::MlDsa87,
        PqSignatureSuite::SlhDsaShake128s,
        PqSignatureSuite::SlhDsaShake192s,
        PqSignatureSuite::SlhDsaShake256s,
        PqSignatureSuite::SlhDsaShake256f,
    ];

    #[test]
    fn generated_public_key_matches_public_from_secret_for_supported_suites() -> Result<()> {
        for suite in SUPPORTED_SUITES {
            let keypair = generate_signing_keypair(suite)?;
            assert_eq!(keypair.suite(), suite);
            assert_eq!(keypair.public_key_bytes().len(), suite.public_key_len());
            assert_eq!(keypair.secret_key_bytes().len(), suite.secret_key_len());

            let derived_public_key = public_from_secret(suite, keypair.secret_key_bytes())?;
            assert_eq!(derived_public_key, keypair.public_key_bytes());
        }
        Ok(())
    }

    #[test]
    fn wrong_suite_secret_fails_closed_on_length_mismatch() -> Result<()> {
        let keypair = generate_signing_keypair(PqSignatureSuite::MlDsa65)?;
        let error =
            public_from_secret(PqSignatureSuite::MlDsa44, keypair.secret_key_bytes()).unwrap_err();

        assert_eq!(error.qv_code(), Some(QvCode::KeyRejected));
        Ok(())
    }

    #[test]
    fn wrong_suite_secret_fails_closed_on_same_length_slh_variant() -> Result<()> {
        let keypair = generate_signing_keypair(PqSignatureSuite::SlhDsaShake256s)?;
        let error = public_from_secret(
            PqSignatureSuite::SlhDsaShake256f,
            keypair.secret_key_bytes(),
        )
        .unwrap_err();

        assert_eq!(error.qv_code(), Some(QvCode::KeyRejected));
        Ok(())
    }
}
