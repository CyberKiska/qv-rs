use fips204::traits::{SerDes as MlDsaSerDes, Signer as MlDsaSigner};
use fips205::traits::{SerDes as SlhDsaSerDes, Signer as SlhDsaSigner};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use zeroize::Zeroizing;

use crate::auth::pqkey::pack_public_key_file;
use crate::auth::qsig::{
    build_qsig_tbs, verify_qsig_against_bytes, QsigTbsFields, AUTH_DIGEST_ALG_ID_SHA3_256,
    AUTH_META_DIGEST_LEN, DISPLAY_TAG_CREATED_AT, DISPLAY_TAG_FILENAME, DISPLAY_TAG_FILESIZE,
    FILE_HASH_LEN, FP_ALG_ID_SHA3_256, MAGIC_QSIG, MAX_AUTH_METADATA_BYTES, MAX_CONTEXT_BYTES,
    MAX_DISPLAY_METADATA_BYTES, MAX_SIGNATURE_BYTES, MAX_SIGNATURE_FILE_BYTES,
    META_TAG_SIGNER_FINGERPRINT, META_TAG_SIGNER_PUBLIC_KEY, QSIG_FLAG_CREATED_AT_PRESENT,
    QSIG_FLAG_CTX_PRESENT, QSIG_FLAG_FILENAME_PRESENT, QSIG_FLAG_FILESIZE_PRESENT,
    QSIG_FORMAT_VERSION_MAJOR, QSIG_FORMAT_VERSION_MINOR,
    SIGNATURE_PROFILE_ID_PQ_DETACHED_PURE_CONTEXT_V2, SIG_HASH_ALG_ID_SHA3_512,
    SUPPORTED_QSIG_CONTEXT,
};
use crate::auth::PqSignatureSuite;
use crate::error::{coded, QvCode, QvError, Result};
use crate::hash::{sha3_256, sha3_512};
use crate::rng::SystemRng;

const QSIG_V2_HEADER_LEN: usize = 118;
const SIGNER_FINGERPRINT_RECORD_LEN: usize = 33;

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

pub struct DetachedSignOptions<'a> {
    pub suite: PqSignatureSuite,
    pub secret_key: &'a [u8],
    pub payload: &'a [u8],
    pub display_metadata: DisplayMetadata,
}

impl<'a> DetachedSignOptions<'a> {
    pub fn new(suite: PqSignatureSuite, secret_key: &'a [u8], payload: &'a [u8]) -> Self {
        Self {
            suite,
            secret_key,
            payload,
            display_metadata: DisplayMetadata::default(),
        }
    }

    pub fn with_display_metadata(mut self, display_metadata: DisplayMetadata) -> Self {
        self.display_metadata = display_metadata;
        self
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DisplayMetadata {
    pub filename: Option<String>,
    pub filesize: Option<u64>,
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetachedSignatureArtifact {
    pub suite: PqSignatureSuite,
    pub qsig_bytes: Vec<u8>,
    pub public_key: Vec<u8>,
    pub signer_fingerprint_record: [u8; SIGNER_FINGERPRINT_RECORD_LEN],
    pub payload_digest: [u8; FILE_HASH_LEN],
    pub auth_meta_digest: [u8; AUTH_META_DIGEST_LEN],
}

pub fn create_detached_qsig(options: DetachedSignOptions<'_>) -> Result<DetachedSignatureArtifact> {
    let suite = options.suite;
    let public_key = public_from_secret(suite, options.secret_key)?;
    if public_key.len() != suite.public_key_len() {
        return Err(key_rejected(
            suite,
            format!(
                "Derived public key length mismatch: expected {} bytes, got {}",
                suite.public_key_len(),
                public_key.len()
            ),
        ));
    }

    let signer_fingerprint_record = signer_fingerprint_record(&public_key);
    let auth_meta_bytes = Zeroizing::new(build_authenticated_metadata(
        &public_key,
        &signer_fingerprint_record,
    )?);
    let display_meta_bytes = build_display_metadata(&options.display_metadata)?;
    let payload_digest = sha3_512(options.payload);
    let auth_meta_digest = sha3_256(auth_meta_bytes.as_slice());

    let tbs = build_qsig_tbs(QsigTbsFields {
        version_major: QSIG_FORMAT_VERSION_MAJOR,
        version_minor: QSIG_FORMAT_VERSION_MINOR,
        suite_id: suite.suite_id(),
        hash_alg_id: SIG_HASH_ALG_ID_SHA3_512,
        signature_profile_id: SIGNATURE_PROFILE_ID_PQ_DETACHED_PURE_CONTEXT_V2,
        auth_digest_alg_id: AUTH_DIGEST_ALG_ID_SHA3_256,
        file_hash: &payload_digest,
        auth_meta_digest: &auth_meta_digest,
    });

    let signature = sign_qsig_tbs(suite, options.secret_key, &tbs, SUPPORTED_QSIG_CONTEXT)?;
    let qsig_bytes = pack_qsig(
        suite,
        &payload_digest,
        &auth_meta_digest,
        auth_meta_bytes.as_slice(),
        &display_meta_bytes,
        &signature,
        &options.display_metadata,
    )?;

    self_verify_generated_qsig(suite, options.payload, &qsig_bytes, &public_key)?;

    Ok(DetachedSignatureArtifact {
        suite,
        qsig_bytes,
        public_key,
        signer_fingerprint_record,
        payload_digest,
        auth_meta_digest,
    })
}

fn generate_ml_dsa_44() -> Result<PqSigningKeypair> {
    let suite = PqSignatureSuite::MlDsa44;
    let (public_key, secret_key) = with_system_rng(suite, "key generation", |rng| {
        fips204::ml_dsa_44::try_keygen_with_rng(rng)
    })?;
    let public_key_bytes = public_key.into_bytes();
    let secret_key_bytes = Zeroizing::new(secret_key.into_bytes());
    finish_generated_keypair(suite, &public_key_bytes[..], &secret_key_bytes[..])
}

fn generate_ml_dsa_65() -> Result<PqSigningKeypair> {
    let suite = PqSignatureSuite::MlDsa65;
    let (public_key, secret_key) = with_system_rng(suite, "key generation", |rng| {
        fips204::ml_dsa_65::try_keygen_with_rng(rng)
    })?;
    let public_key_bytes = public_key.into_bytes();
    let secret_key_bytes = Zeroizing::new(secret_key.into_bytes());
    finish_generated_keypair(suite, &public_key_bytes[..], &secret_key_bytes[..])
}

fn generate_ml_dsa_87() -> Result<PqSigningKeypair> {
    let suite = PqSignatureSuite::MlDsa87;
    let (public_key, secret_key) = with_system_rng(suite, "key generation", |rng| {
        fips204::ml_dsa_87::try_keygen_with_rng(rng)
    })?;
    let public_key_bytes = public_key.into_bytes();
    let secret_key_bytes = Zeroizing::new(secret_key.into_bytes());
    finish_generated_keypair(suite, &public_key_bytes[..], &secret_key_bytes[..])
}

fn generate_slh_dsa_shake_128s() -> Result<PqSigningKeypair> {
    let suite = PqSignatureSuite::SlhDsaShake128s;
    let (public_key, secret_key) = with_system_rng(suite, "key generation", |rng| {
        fips205::slh_dsa_shake_128s::try_keygen_with_rng(rng)
    })?;
    let public_key_bytes = public_key.into_bytes();
    let secret_key_bytes = Zeroizing::new(secret_key.into_bytes());
    finish_generated_keypair(suite, &public_key_bytes[..], &secret_key_bytes[..])
}

fn generate_slh_dsa_shake_192s() -> Result<PqSigningKeypair> {
    let suite = PqSignatureSuite::SlhDsaShake192s;
    let (public_key, secret_key) = with_system_rng(suite, "key generation", |rng| {
        fips205::slh_dsa_shake_192s::try_keygen_with_rng(rng)
    })?;
    let public_key_bytes = public_key.into_bytes();
    let secret_key_bytes = Zeroizing::new(secret_key.into_bytes());
    finish_generated_keypair(suite, &public_key_bytes[..], &secret_key_bytes[..])
}

fn generate_slh_dsa_shake_256s() -> Result<PqSigningKeypair> {
    let suite = PqSignatureSuite::SlhDsaShake256s;
    let (public_key, secret_key) = with_system_rng(suite, "key generation", |rng| {
        fips205::slh_dsa_shake_256s::try_keygen_with_rng(rng)
    })?;
    let public_key_bytes = public_key.into_bytes();
    let secret_key_bytes = Zeroizing::new(secret_key.into_bytes());
    finish_generated_keypair(suite, &public_key_bytes[..], &secret_key_bytes[..])
}

fn generate_slh_dsa_shake_256f() -> Result<PqSigningKeypair> {
    let suite = PqSignatureSuite::SlhDsaShake256f;
    let (public_key, secret_key) = with_system_rng(suite, "key generation", |rng| {
        fips205::slh_dsa_shake_256f::try_keygen_with_rng(rng)
    })?;
    let public_key_bytes = public_key.into_bytes();
    let secret_key_bytes = Zeroizing::new(secret_key.into_bytes());
    finish_generated_keypair(suite, &public_key_bytes[..], &secret_key_bytes[..])
}

fn sign_qsig_tbs(
    suite: PqSignatureSuite,
    secret_key_bytes: &[u8],
    tbs: &[u8],
    context: &[u8],
) -> Result<Vec<u8>> {
    match suite {
        PqSignatureSuite::MlDsa44 => sign_ml_dsa_44(secret_key_bytes, tbs, context),
        PqSignatureSuite::MlDsa65 => sign_ml_dsa_65(secret_key_bytes, tbs, context),
        PqSignatureSuite::MlDsa87 => sign_ml_dsa_87(secret_key_bytes, tbs, context),
        PqSignatureSuite::SlhDsaShake128s => {
            sign_slh_dsa_shake_128s(secret_key_bytes, tbs, context)
        }
        PqSignatureSuite::SlhDsaShake192s => {
            sign_slh_dsa_shake_192s(secret_key_bytes, tbs, context)
        }
        PqSignatureSuite::SlhDsaShake256s => {
            sign_slh_dsa_shake_256s(secret_key_bytes, tbs, context)
        }
        PqSignatureSuite::SlhDsaShake256f => {
            sign_slh_dsa_shake_256f(secret_key_bytes, tbs, context)
        }
    }
}

fn sign_ml_dsa_44(secret_key_bytes: &[u8], tbs: &[u8], context: &[u8]) -> Result<Vec<u8>> {
    let suite = PqSignatureSuite::MlDsa44;
    let secret_key_bytes =
        copy_secret_array::<{ fips204::ml_dsa_44::SK_LEN }>(suite, secret_key_bytes)?;
    let secret_key = fips204::ml_dsa_44::PrivateKey::try_from_bytes(*secret_key_bytes)
        .map_err(|error| key_rejected(suite, format!("Invalid secret key bytes: {error}")))?;
    let signature = with_system_rng(suite, "signing", |rng| {
        secret_key.try_sign_with_rng(rng, tbs, context)
    })?;
    Ok(signature.to_vec())
}

fn sign_ml_dsa_65(secret_key_bytes: &[u8], tbs: &[u8], context: &[u8]) -> Result<Vec<u8>> {
    let suite = PqSignatureSuite::MlDsa65;
    let secret_key_bytes =
        copy_secret_array::<{ fips204::ml_dsa_65::SK_LEN }>(suite, secret_key_bytes)?;
    let secret_key = fips204::ml_dsa_65::PrivateKey::try_from_bytes(*secret_key_bytes)
        .map_err(|error| key_rejected(suite, format!("Invalid secret key bytes: {error}")))?;
    let signature = with_system_rng(suite, "signing", |rng| {
        secret_key.try_sign_with_rng(rng, tbs, context)
    })?;
    Ok(signature.to_vec())
}

fn sign_ml_dsa_87(secret_key_bytes: &[u8], tbs: &[u8], context: &[u8]) -> Result<Vec<u8>> {
    let suite = PqSignatureSuite::MlDsa87;
    let secret_key_bytes =
        copy_secret_array::<{ fips204::ml_dsa_87::SK_LEN }>(suite, secret_key_bytes)?;
    let secret_key = fips204::ml_dsa_87::PrivateKey::try_from_bytes(*secret_key_bytes)
        .map_err(|error| key_rejected(suite, format!("Invalid secret key bytes: {error}")))?;
    let signature = with_system_rng(suite, "signing", |rng| {
        secret_key.try_sign_with_rng(rng, tbs, context)
    })?;
    Ok(signature.to_vec())
}

fn sign_slh_dsa_shake_128s(secret_key_bytes: &[u8], tbs: &[u8], context: &[u8]) -> Result<Vec<u8>> {
    let suite = PqSignatureSuite::SlhDsaShake128s;
    let secret_key_bytes =
        copy_secret_array::<{ fips205::slh_dsa_shake_128s::SK_LEN }>(suite, secret_key_bytes)?;
    let secret_key = fips205::slh_dsa_shake_128s::PrivateKey::try_from_bytes(&*secret_key_bytes)
        .map_err(|error| key_rejected(suite, format!("Invalid secret key bytes: {error}")))?;
    let signature = with_system_rng(suite, "signing", |rng| {
        secret_key.try_sign_with_rng(rng, tbs, context, true)
    })?;
    Ok(signature.to_vec())
}

fn sign_slh_dsa_shake_192s(secret_key_bytes: &[u8], tbs: &[u8], context: &[u8]) -> Result<Vec<u8>> {
    let suite = PqSignatureSuite::SlhDsaShake192s;
    let secret_key_bytes =
        copy_secret_array::<{ fips205::slh_dsa_shake_192s::SK_LEN }>(suite, secret_key_bytes)?;
    let secret_key = fips205::slh_dsa_shake_192s::PrivateKey::try_from_bytes(&*secret_key_bytes)
        .map_err(|error| key_rejected(suite, format!("Invalid secret key bytes: {error}")))?;
    let signature = with_system_rng(suite, "signing", |rng| {
        secret_key.try_sign_with_rng(rng, tbs, context, true)
    })?;
    Ok(signature.to_vec())
}

fn sign_slh_dsa_shake_256s(secret_key_bytes: &[u8], tbs: &[u8], context: &[u8]) -> Result<Vec<u8>> {
    let suite = PqSignatureSuite::SlhDsaShake256s;
    let secret_key_bytes =
        copy_secret_array::<{ fips205::slh_dsa_shake_256s::SK_LEN }>(suite, secret_key_bytes)?;
    let secret_key = fips205::slh_dsa_shake_256s::PrivateKey::try_from_bytes(&*secret_key_bytes)
        .map_err(|error| key_rejected(suite, format!("Invalid secret key bytes: {error}")))?;
    let signature = with_system_rng(suite, "signing", |rng| {
        secret_key.try_sign_with_rng(rng, tbs, context, true)
    })?;
    Ok(signature.to_vec())
}

fn sign_slh_dsa_shake_256f(secret_key_bytes: &[u8], tbs: &[u8], context: &[u8]) -> Result<Vec<u8>> {
    let suite = PqSignatureSuite::SlhDsaShake256f;
    let secret_key_bytes =
        copy_secret_array::<{ fips205::slh_dsa_shake_256f::SK_LEN }>(suite, secret_key_bytes)?;
    let secret_key = fips205::slh_dsa_shake_256f::PrivateKey::try_from_bytes(&*secret_key_bytes)
        .map_err(|error| key_rejected(suite, format!("Invalid secret key bytes: {error}")))?;
    let signature = with_system_rng(suite, "signing", |rng| {
        secret_key.try_sign_with_rng(rng, tbs, context, true)
    })?;
    Ok(signature.to_vec())
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

fn signer_fingerprint_record(public_key: &[u8]) -> [u8; SIGNER_FINGERPRINT_RECORD_LEN] {
    let mut record = [0u8; SIGNER_FINGERPRINT_RECORD_LEN];
    record[0] = FP_ALG_ID_SHA3_256;
    record[1..].copy_from_slice(&sha3_256(public_key));
    record
}

fn build_authenticated_metadata(
    public_key: &[u8],
    signer_fingerprint_record: &[u8; SIGNER_FINGERPRINT_RECORD_LEN],
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(6 + public_key.len() + signer_fingerprint_record.len());
    push_tlv(&mut out, META_TAG_SIGNER_PUBLIC_KEY, public_key)?;
    push_tlv(
        &mut out,
        META_TAG_SIGNER_FINGERPRINT,
        signer_fingerprint_record,
    )?;
    if out.len() > MAX_AUTH_METADATA_BYTES {
        return Err(format_rejected(format!(
            "authMetaLen exceeds maximum size ({MAX_AUTH_METADATA_BYTES} bytes)"
        )));
    }
    Ok(out)
}

fn build_display_metadata(metadata: &DisplayMetadata) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    if let Some(filename) = metadata.filename.as_deref() {
        if filename.is_empty() {
            return Err(format_rejected("display filename must not be empty"));
        }
        push_tlv(&mut out, DISPLAY_TAG_FILENAME, filename.as_bytes())?;
    }
    if let Some(filesize) = metadata.filesize {
        push_tlv(&mut out, DISPLAY_TAG_FILESIZE, &filesize.to_le_bytes())?;
    }
    if let Some(created_at) = metadata.created_at.as_deref() {
        validate_canonical_created_at(created_at)?;
        push_tlv(&mut out, DISPLAY_TAG_CREATED_AT, created_at.as_bytes())?;
    }
    if out.len() > MAX_DISPLAY_METADATA_BYTES {
        return Err(format_rejected(format!(
            "displayMetaLen exceeds maximum size ({MAX_DISPLAY_METADATA_BYTES} bytes)"
        )));
    }
    Ok(out)
}

fn push_tlv(out: &mut Vec<u8>, tag: u8, value: &[u8]) -> Result<()> {
    if tag == 0 {
        return Err(format_rejected("TLV tag 0 is invalid"));
    }
    let value_len = u16::try_from(value.len())
        .map_err(|_| format_rejected(format!("TLV value for tag {tag} is too large")))?;
    out.push(tag);
    out.extend_from_slice(&value_len.to_le_bytes());
    out.extend_from_slice(value);
    Ok(())
}

fn validate_canonical_created_at(value: &str) -> Result<()> {
    if !is_canonical_utc_millis_timestamp(value.as_bytes()) {
        return Err(format_rejected(
            "display createdAt must be canonical UTC ISO-8601 milliseconds",
        ));
    }
    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| format_rejected("display createdAt is not valid ISO-8601"))?;
    Ok(())
}

fn is_canonical_utc_millis_timestamp(bytes: &[u8]) -> bool {
    if bytes.len() != 24 {
        return false;
    }
    for index in [
        0usize, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18, 20, 21, 22,
    ] {
        if !bytes[index].is_ascii_digit() {
            return false;
        }
    }
    bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':'
        && bytes[19] == b'.'
        && bytes[23] == b'Z'
}

fn pack_qsig(
    suite: PqSignatureSuite,
    payload_digest: &[u8; FILE_HASH_LEN],
    auth_meta_digest: &[u8; AUTH_META_DIGEST_LEN],
    auth_meta_bytes: &[u8],
    display_meta_bytes: &[u8],
    signature: &[u8],
    display_metadata: &DisplayMetadata,
) -> Result<Vec<u8>> {
    if auth_meta_bytes.len() > MAX_AUTH_METADATA_BYTES {
        return Err(format_rejected(format!(
            "authMetaLen exceeds maximum size ({MAX_AUTH_METADATA_BYTES} bytes)"
        )));
    }
    if display_meta_bytes.len() > MAX_DISPLAY_METADATA_BYTES {
        return Err(format_rejected(format!(
            "displayMetaLen exceeds maximum size ({MAX_DISPLAY_METADATA_BYTES} bytes)"
        )));
    }
    if signature.len() != signature_len(suite) {
        return Err(format_rejected(format!(
            "signature length mismatch for {}: expected {} bytes, got {}",
            suite.canonical_name(),
            signature_len(suite),
            signature.len()
        )));
    }
    if signature.len() > MAX_SIGNATURE_BYTES {
        return Err(format_rejected(format!(
            "sigLen exceeds maximum size ({MAX_SIGNATURE_BYTES} bytes)"
        )));
    }
    if SUPPORTED_QSIG_CONTEXT.is_empty() || SUPPORTED_QSIG_CONTEXT.len() > MAX_CONTEXT_BYTES {
        return Err(format_rejected("QSIG context length is invalid"));
    }

    let auth_meta_len = u16::try_from(auth_meta_bytes.len())
        .map_err(|_| format_rejected("authMetaLen is too large"))?;
    let display_meta_len = u16::try_from(display_meta_bytes.len())
        .map_err(|_| format_rejected("displayMetaLen is too large"))?;
    let sig_len =
        u32::try_from(signature.len()).map_err(|_| format_rejected("sigLen is too large"))?;
    let total_len = QSIG_V2_HEADER_LEN
        .checked_add(SUPPORTED_QSIG_CONTEXT.len())
        .and_then(|len| len.checked_add(auth_meta_bytes.len()))
        .and_then(|len| len.checked_add(display_meta_bytes.len()))
        .and_then(|len| len.checked_add(signature.len()))
        .ok_or_else(|| format_rejected("Detached PQ signature length overflow"))?;
    if total_len > MAX_SIGNATURE_FILE_BYTES {
        return Err(format_rejected(format!(
            "sigBytes exceeds maximum size ({MAX_SIGNATURE_FILE_BYTES} bytes)"
        )));
    }

    let mut flags = QSIG_FLAG_CTX_PRESENT;
    if display_metadata.filename.is_some() {
        flags |= QSIG_FLAG_FILENAME_PRESENT;
    }
    if display_metadata.filesize.is_some() {
        flags |= QSIG_FLAG_FILESIZE_PRESENT;
    }
    if display_metadata.created_at.is_some() {
        flags |= QSIG_FLAG_CREATED_AT_PRESENT;
    }

    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(MAGIC_QSIG);
    out.push(QSIG_FORMAT_VERSION_MAJOR);
    out.push(QSIG_FORMAT_VERSION_MINOR);
    out.push(suite.suite_id());
    out.push(SIGNATURE_PROFILE_ID_PQ_DETACHED_PURE_CONTEXT_V2);
    out.push(SIG_HASH_ALG_ID_SHA3_512);
    out.push(AUTH_DIGEST_ALG_ID_SHA3_256);
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(payload_digest);
    out.extend_from_slice(auth_meta_digest);
    out.push(SUPPORTED_QSIG_CONTEXT.len() as u8);
    out.push(0);
    out.extend_from_slice(&auth_meta_len.to_le_bytes());
    out.extend_from_slice(&display_meta_len.to_le_bytes());
    out.extend_from_slice(&sig_len.to_le_bytes());
    out.extend_from_slice(SUPPORTED_QSIG_CONTEXT);
    out.extend_from_slice(auth_meta_bytes);
    out.extend_from_slice(display_meta_bytes);
    out.extend_from_slice(signature);

    if out.len() != total_len {
        return Err(format_rejected("Detached PQ signature length mismatch"));
    }
    Ok(out)
}

fn signature_len(suite: PqSignatureSuite) -> usize {
    match suite {
        PqSignatureSuite::MlDsa44 => fips204::ml_dsa_44::SIG_LEN,
        PqSignatureSuite::MlDsa65 => fips204::ml_dsa_65::SIG_LEN,
        PqSignatureSuite::MlDsa87 => fips204::ml_dsa_87::SIG_LEN,
        PqSignatureSuite::SlhDsaShake128s => fips205::slh_dsa_shake_128s::SIG_LEN,
        PqSignatureSuite::SlhDsaShake192s => fips205::slh_dsa_shake_192s::SIG_LEN,
        PqSignatureSuite::SlhDsaShake256s => fips205::slh_dsa_shake_256s::SIG_LEN,
        PqSignatureSuite::SlhDsaShake256f => fips205::slh_dsa_shake_256f::SIG_LEN,
    }
}

fn self_verify_generated_qsig(
    suite: PqSignatureSuite,
    payload: &[u8],
    qsig_bytes: &[u8],
    public_key: &[u8],
) -> Result<()> {
    let public_key_file = pack_public_key_file(suite, public_key)?;
    let verification =
        verify_qsig_against_bytes(payload, qsig_bytes, None, Some(public_key_file.as_slice()))
            .map_err(|error| {
                coded(
                    QvCode::VerificationFailed,
                    format!("Generated detached PQ signature failed self-verification: {error}"),
                )
            })?;
    if !verification.ok {
        return Err(coded(
            QvCode::VerificationFailed,
            format!(
                "Generated detached PQ signature failed self-verification: {}",
                verification
                    .error
                    .unwrap_or_else(|| "verification failed".to_string())
            ),
        ));
    }
    Ok(())
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

fn with_system_rng<T>(
    suite: PqSignatureSuite,
    operation: &str,
    run: impl FnOnce(&mut SystemRng) -> core::result::Result<T, &'static str>,
) -> Result<T> {
    let mut rng = SystemRng::default();
    match run(&mut rng) {
        Ok(value) => Ok(value),
        Err(error) if rng.entropy_failed() => Err(entropy_failed(suite, operation, error)),
        Err(error) => Err(coded(
            QvCode::VerificationFailed,
            format!(
                "PQC {} failed for {}: {}",
                operation,
                suite.canonical_name(),
                error
            ),
        )),
    }
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

fn format_rejected(message: impl Into<String>) -> QvError {
    coded(
        QvCode::InvalidFormat,
        format!("Detached PQ signature format rejected: {}", message.into()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::qsig::unpack_qsig;

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

    #[test]
    fn detached_qsig_roundtrip_verifies_with_pinned_public_key() -> Result<()> {
        let payload = b"{\"schema\":\"quantum-vault-archive-state-descriptor/v1\",\"version\":1}";
        let keypair = generate_signing_keypair(PqSignatureSuite::MlDsa87)?;
        let display_metadata = DisplayMetadata {
            filename: Some("archive-state.json".to_string()),
            filesize: Some(payload.len() as u64),
            created_at: Some("2025-01-01T00:00:00.000Z".to_string()),
        };
        let artifact = create_detached_qsig(
            DetachedSignOptions::new(
                PqSignatureSuite::MlDsa87,
                keypair.secret_key_bytes(),
                payload,
            )
            .with_display_metadata(display_metadata),
        )?;

        assert_eq!(artifact.suite, PqSignatureSuite::MlDsa87);
        assert_eq!(artifact.public_key, keypair.public_key_bytes());
        assert_eq!(artifact.payload_digest, sha3_512(payload));
        assert_eq!(artifact.signer_fingerprint_record[0], FP_ALG_ID_SHA3_256);
        assert_eq!(
            &artifact.signer_fingerprint_record[1..],
            sha3_256(keypair.public_key_bytes()).as_slice()
        );

        let parsed = unpack_qsig(&artifact.qsig_bytes)?;
        assert_eq!(parsed.version_major, QSIG_FORMAT_VERSION_MAJOR);
        assert_eq!(parsed.version_minor, QSIG_FORMAT_VERSION_MINOR);
        assert_eq!(parsed.suite_id, PqSignatureSuite::MlDsa87.suite_id());
        assert_eq!(parsed.file_hash, artifact.payload_digest);
        assert_eq!(parsed.ctx_bytes, SUPPORTED_QSIG_CONTEXT);
        assert_eq!(
            parsed.metadata.signer_public_key.as_deref(),
            Some(keypair.public_key_bytes())
        );
        assert_eq!(
            parsed.metadata.signer_fingerprint_record.as_deref(),
            Some(artifact.signer_fingerprint_record.as_slice())
        );
        assert_eq!(
            parsed.flags
                & (QSIG_FLAG_CTX_PRESENT
                    | QSIG_FLAG_FILENAME_PRESENT
                    | QSIG_FLAG_FILESIZE_PRESENT
                    | QSIG_FLAG_CREATED_AT_PRESENT),
            QSIG_FLAG_CTX_PRESENT
                | QSIG_FLAG_FILENAME_PRESENT
                | QSIG_FLAG_FILESIZE_PRESENT
                | QSIG_FLAG_CREATED_AT_PRESENT
        );

        let public_key_file =
            pack_public_key_file(PqSignatureSuite::MlDsa87, keypair.public_key_bytes())?;
        let verification = verify_qsig_against_bytes(
            payload,
            &artifact.qsig_bytes,
            None,
            Some(public_key_file.as_slice()),
        )?;
        assert!(verification.ok);
        assert!(verification.user_pinned);
        assert!(verification.signer_pinned);
        assert!(!verification.self_signed);
        Ok(())
    }

    #[test]
    fn detached_qsig_rejects_payload_signature_and_metadata_tampering() -> Result<()> {
        let payload = b"phase-1 archive state bytes";
        let keypair = generate_signing_keypair(PqSignatureSuite::MlDsa44)?;
        let artifact = create_detached_qsig(DetachedSignOptions::new(
            PqSignatureSuite::MlDsa44,
            keypair.secret_key_bytes(),
            payload,
        ))?;

        let payload_tampered = verify_qsig_against_bytes(
            b"phase-2 archive state bytes",
            &artifact.qsig_bytes,
            None,
            None,
        )?;
        assert!(!payload_tampered.ok);

        let mut signature_tampered = artifact.qsig_bytes.clone();
        let last = signature_tampered
            .last_mut()
            .expect("generated qsig has signature bytes");
        *last ^= 0x01;
        let signature_tampered =
            verify_qsig_against_bytes(payload, &signature_tampered, None, None)?;
        assert!(!signature_tampered.ok);

        let mut auth_digest_tampered = artifact.qsig_bytes;
        let auth_meta_digest_offset = 4 + 1 + 1 + 1 + 1 + 1 + 1 + 2 + FILE_HASH_LEN;
        auth_digest_tampered[auth_meta_digest_offset] ^= 0x01;
        assert!(unpack_qsig(&auth_digest_tampered).is_err());
        Ok(())
    }

    #[test]
    fn detached_qsig_rejects_noncanonical_created_at() -> Result<()> {
        let keypair = generate_signing_keypair(PqSignatureSuite::MlDsa44)?;
        let error = create_detached_qsig(
            DetachedSignOptions::new(
                PqSignatureSuite::MlDsa44,
                keypair.secret_key_bytes(),
                b"payload",
            )
            .with_display_metadata(DisplayMetadata {
                filename: None,
                filesize: None,
                created_at: Some("2025-01-01T00:00:00Z".to_string()),
            }),
        )
        .expect_err("noncanonical createdAt must be rejected");

        assert_eq!(error.qv_code(), Some(QvCode::InvalidFormat));
        Ok(())
    }
}
