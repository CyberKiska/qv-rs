use crc32fast::Hasher as Crc32;
use fips204::traits::{SerDes as MlDsaSerDes, Verifier as MlDsaVerifier};
use fips205::traits::{SerDes as SlhDsaSerDes, Verifier as SlhDsaVerifier};

use crate::auth::{get_signature_suite_info, SignatureCheckResult};
use crate::bytes::timing_safe_equal;
use crate::error::{err, Result};
use crate::hash::{sha3_256, sha3_512};

const MAGIC_QSIG: &[u8; 4] = b"PQSG";
const MAGIC_TBS: &[u8; 4] = b"QSTB";
const MAGIC_PQPK: &[u8; 4] = b"PQPK";
const FILE_HASH_LEN: usize = 64;
const AUTH_META_DIGEST_LEN: usize = 32;
const SIG_HASH_ALG_ID_SHA3_512: u8 = 0x01;
const AUTH_DIGEST_ALG_ID_SHA3_256: u8 = 0x01;
const SIGNATURE_PROFILE_ID_PQ_DETACHED_PURE_CONTEXT_V2: u8 = 0x01;
const QSIG_FORMAT_VERSION_MAJOR: u8 = 0x02;
const QSIG_TBS_VERSION_MAJOR: u8 = 0x02;
const SUPPORTED_QSIG_CONTEXT: &[u8] = b"quantum-signer/v2";
const FP_ALG_ID_SHA3_256: u8 = 0x01;
const FP_RECORD_LEN: usize = 33;
const QSIG_FLAG_CTX_PRESENT: u16 = 0x0001;
const QSIG_KNOWN_FLAGS: u16 = 0x000f;
#[cfg(feature = "legacy-mvp")]
const LEGACY_QSIG_FLAG_PROFILE_MVP_V1: u16 = 0x000f;
const META_TAG_SIGNER_PUBLIC_KEY: u8 = 0x10;
const META_TAG_SIGNER_FINGERPRINT: u8 = 0x11;

pub const SUITE_ID_ML_DSA_44: u8 = 0x01;
pub const SUITE_ID_ML_DSA_65: u8 = 0x02;
pub const SUITE_ID_ML_DSA_87: u8 = 0x03;
pub const SUITE_ID_SLH_DSA_SHAKE_128S: u8 = 0x11;
pub const SUITE_ID_SLH_DSA_SHAKE_192S: u8 = 0x12;
pub const SUITE_ID_SLH_DSA_SHAKE_256S: u8 = 0x13;
pub const SUITE_ID_SLH_DSA_SHAKE_256F: u8 = 0x14;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QsigMetadata {
    pub signer_public_key: Option<Vec<u8>>,
    pub signer_fingerprint_record: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerFingerprint {
    pub alg_id: u8,
    pub digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedQsig {
    pub version_major: u8,
    pub version_minor: u8,
    pub suite_id: u8,
    pub hash_alg_id: u8,
    pub flags: u16,
    pub file_hash: [u8; 64],
    pub ctx_bytes: Vec<u8>,
    pub signature: Vec<u8>,
    pub metadata: QsigMetadata,
    pub signer_fingerprint: Option<SignerFingerprint>,
    pub tbs: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPqpk {
    pub suite_id: u8,
    pub key_bytes: Vec<u8>,
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn take(&mut self, len: usize, field: &str) -> Result<&'a [u8]> {
        if self.offset + len > self.bytes.len() {
            return Err(err(format!("Truncated {field}")));
        }
        let out = &self.bytes[self.offset..self.offset + len];
        self.offset += len;
        Ok(out)
    }

    fn u8(&mut self, field: &str) -> Result<u8> {
        Ok(self.take(1, field)?[0])
    }

    fn u16le(&mut self, field: &str) -> Result<u16> {
        let raw = self.take(2, field)?;
        Ok(u16::from_le_bytes([raw[0], raw[1]]))
    }

    fn u32le(&mut self, field: &str) -> Result<u32> {
        let raw = self.take(4, field)?;
        Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
    }
}

pub(crate) fn qsig_suite_name(suite_id: u8) -> Result<&'static str> {
    Ok(match suite_id {
        SUITE_ID_ML_DSA_44 => "mldsa-44",
        SUITE_ID_ML_DSA_65 => "mldsa-65",
        SUITE_ID_ML_DSA_87 => "mldsa-87",
        SUITE_ID_SLH_DSA_SHAKE_128S => "slhdsa-shake-128s",
        SUITE_ID_SLH_DSA_SHAKE_192S => "slhdsa-shake-192s",
        SUITE_ID_SLH_DSA_SHAKE_256S => "slhdsa-shake-256s",
        SUITE_ID_SLH_DSA_SHAKE_256F => "slhdsa-shake-256f",
        _ => {
            return Err(err(format!(
                "Unsupported detached PQ signature suiteId: {suite_id}"
            )))
        }
    })
}

fn decode_metadata_tlv(bytes: &[u8]) -> Result<QsigMetadata> {
    let mut reader = Reader::new(bytes);
    let mut signer_public_key = None;
    let mut signer_fingerprint_record = None;
    let mut last_tag = 0i32 - 1;

    while reader.remaining() > 0 {
        let tag = reader.u8("meta.tag")?;
        let len = usize::from(reader.u16le("meta.len")?);
        let value = reader.take(len, &format!("meta.tag.{tag}"))?.to_vec();

        if i32::from(tag) <= last_tag {
            return Err(err("Non-canonical metadata TLV order"));
        }
        last_tag = i32::from(tag);

        match tag {
            META_TAG_SIGNER_PUBLIC_KEY => signer_public_key = Some(value),
            META_TAG_SIGNER_FINGERPRINT => signer_fingerprint_record = Some(value),
            other if other >= 0x80 => {
                return Err(err(format!("Unknown critical metadata TLV tag: {other}")))
            }
            _ => {}
        }
    }

    Ok(QsigMetadata {
        signer_public_key,
        signer_fingerprint_record,
    })
}

fn decode_display_metadata_tlv(bytes: &[u8]) -> Result<()> {
    let mut reader = Reader::new(bytes);
    let mut last_tag = 0i32 - 1;

    while reader.remaining() > 0 {
        let tag = reader.u8("displayMeta.tag")?;
        let len = usize::from(reader.u16le("displayMeta.len")?);
        let _value = reader.take(len, &format!("displayMeta.tag.{tag}"))?;

        if i32::from(tag) <= last_tag {
            return Err(err("Non-canonical displayMeta TLV order"));
        }
        last_tag = i32::from(tag);

        match tag {
            0x01..=0x03 => {}
            other if other >= 0x80 => {
                return Err(err(format!(
                    "Unknown critical displayMeta TLV tag: {other}"
                )))
            }
            other => return Err(err(format!("Unexpected displayMeta tag: {other}"))),
        }
    }
    Ok(())
}

fn unpack_signer_fingerprint(record: &[u8]) -> Result<SignerFingerprint> {
    if record.len() != FP_RECORD_LEN {
        return Err(err("Invalid signer fingerprint record length"));
    }
    let alg_id = record[0];
    if alg_id != FP_ALG_ID_SHA3_256 {
        return Err(err(format!(
            "Unsupported signer fingerprint algorithm: {alg_id}"
        )));
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&record[1..]);
    Ok(SignerFingerprint { alg_id, digest })
}

fn build_tbs(
    version_major: u8,
    version_minor: u8,
    suite_id: u8,
    hash_alg_id: u8,
    signature_profile_id: u8,
    auth_digest_alg_id: u8,
    file_hash: &[u8; 64],
    auth_meta_digest: &[u8; AUTH_META_DIGEST_LEN],
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(4 + 8 + file_hash.len() + auth_meta_digest.len());
    out.extend_from_slice(MAGIC_TBS);
    out.extend_from_slice(&[
        QSIG_TBS_VERSION_MAJOR,
        0x00,
        version_major,
        version_minor,
        suite_id,
        signature_profile_id,
        hash_alg_id,
        auth_digest_alg_id,
    ]);
    out.extend_from_slice(file_hash);
    out.extend_from_slice(auth_meta_digest);
    Ok(out)
}

#[cfg(feature = "legacy-mvp")]
fn build_legacy_tbs_v1(
    version_major: u8,
    version_minor: u8,
    suite_id: u8,
    hash_alg_id: u8,
    ctx_bytes: &[u8],
    file_hash: &[u8; 64],
) -> Result<Vec<u8>> {
    if ctx_bytes.len() > u8::MAX as usize {
        return Err(err("Context length exceeds u8 limit"));
    }
    let mut out = Vec::with_capacity(4 + 7 + ctx_bytes.len() + file_hash.len());
    out.extend_from_slice(MAGIC_TBS);
    out.extend_from_slice(&[
        0x01,
        0x00,
        version_major,
        version_minor,
        suite_id,
        hash_alg_id,
        ctx_bytes.len() as u8,
    ]);
    out.extend_from_slice(ctx_bytes);
    out.extend_from_slice(file_hash);
    Ok(out)
}

pub fn unpack_qsig(sig_bytes: &[u8]) -> Result<ParsedQsig> {
    let mut reader = Reader::new(sig_bytes);
    if reader.take(4, "magic")? != MAGIC_QSIG {
        return Err(err("Invalid .qsig magic"));
    }

    let version_major = reader.u8("versionMajor")?;
    let version_minor = reader.u8("versionMinor")?;
    #[cfg(feature = "legacy-mvp")]
    if version_major == 0x01 {
        return unpack_legacy_qsig_v1(reader, version_major, version_minor);
    }
    if version_major != QSIG_FORMAT_VERSION_MAJOR {
        return Err(err(format!(
            "Unsupported detached PQ signature major version: {version_major}"
        )));
    }

    let suite_id = reader.u8("suiteId")?;
    qsig_suite_name(suite_id)?;

    let signature_profile_id = reader.u8("signatureProfileId")?;
    if signature_profile_id != SIGNATURE_PROFILE_ID_PQ_DETACHED_PURE_CONTEXT_V2 {
        return Err(err(format!(
            "Unsupported detached PQ signature profile: {signature_profile_id}"
        )));
    }

    let hash_alg_id = reader.u8("payloadDigestAlgId")?;
    if hash_alg_id != SIG_HASH_ALG_ID_SHA3_512 {
        return Err(err(format!(
            "Unsupported detached PQ signature hashAlgId: {hash_alg_id}"
        )));
    }

    let auth_digest_alg_id = reader.u8("authDigestAlgId")?;
    if auth_digest_alg_id != AUTH_DIGEST_ALG_ID_SHA3_256 {
        return Err(err(format!(
            "Unsupported detached PQ signature authDigestAlgId: {auth_digest_alg_id}"
        )));
    }

    let flags = reader.u16le("flags")?;
    if flags & !QSIG_KNOWN_FLAGS != 0 {
        return Err(err(format!(
            "Unsupported detached PQ signature flags: {flags}"
        )));
    }

    let mut file_hash = [0u8; FILE_HASH_LEN];
    file_hash.copy_from_slice(reader.take(FILE_HASH_LEN, "payloadDigest")?);
    let mut auth_meta_digest = [0u8; AUTH_META_DIGEST_LEN];
    auth_meta_digest.copy_from_slice(reader.take(AUTH_META_DIGEST_LEN, "authMetaDigest")?);
    let ctx_len = usize::from(reader.u8("ctxLen")?);
    let reserved = reader.u8("reserved")?;
    if reserved != 0 {
        return Err(err("Invalid detached PQ signature reserved field"));
    }
    let auth_meta_len = usize::from(reader.u16le("authMetaLen")?);
    let display_meta_len = usize::from(reader.u16le("displayMetaLen")?);
    let sig_len = reader.u32le("sigLen")? as usize;

    let expected_remaining = ctx_len + auth_meta_len + display_meta_len + sig_len;
    if reader.remaining() != expected_remaining {
        return Err(err("Invalid detached PQ signature length framing"));
    }

    let ctx_bytes = reader.take(ctx_len, "ctxBytes")?.to_vec();
    if ctx_bytes.is_empty() {
        return Err(err("Detached PQ signature context is required"));
    }
    if flags & QSIG_FLAG_CTX_PRESENT == 0 {
        return Err(err("Detached PQ signature context flag is missing"));
    }
    if ctx_bytes != SUPPORTED_QSIG_CONTEXT {
        return Err(err(format!(
            "Unsupported detached PQ signature context: {}",
            String::from_utf8_lossy(&ctx_bytes)
        )));
    }

    let auth_meta_bytes = reader.take(auth_meta_len, "authMetaBytes")?;
    let display_meta_bytes = reader.take(display_meta_len, "displayMetaBytes")?;
    let signature = reader.take(sig_len, "signature")?.to_vec();

    let recomputed_auth_meta_digest = sha3_256(auth_meta_bytes);
    if !timing_safe_equal(&recomputed_auth_meta_digest, &auth_meta_digest) {
        return Err(err("Detached PQ signature authMetaDigest mismatch"));
    }
    let metadata = decode_metadata_tlv(auth_meta_bytes)?;
    if metadata.signer_public_key.is_none() || metadata.signer_fingerprint_record.is_none() {
        return Err(err(
            "Detached PQ signature authMeta is missing signer binding",
        ));
    }
    let _display_metadata = decode_display_metadata_tlv(display_meta_bytes)?;
    let signer_fingerprint = metadata
        .signer_fingerprint_record
        .as_deref()
        .map(unpack_signer_fingerprint)
        .transpose()?;
    if let (Some(public_key), Some(fingerprint)) =
        (&metadata.signer_public_key, &signer_fingerprint)
    {
        if !timing_safe_equal(&sha3_256(public_key), &fingerprint.digest) {
            return Err(err(
                "Signer fingerprint does not match signer public key in authMeta",
            ));
        }
    }

    let tbs = build_tbs(
        version_major,
        version_minor,
        suite_id,
        hash_alg_id,
        signature_profile_id,
        auth_digest_alg_id,
        &file_hash,
        &auth_meta_digest,
    )?;

    Ok(ParsedQsig {
        version_major,
        version_minor,
        suite_id,
        hash_alg_id,
        flags,
        file_hash,
        ctx_bytes,
        signature,
        metadata,
        signer_fingerprint,
        tbs,
    })
}

#[cfg(feature = "legacy-mvp")]
fn unpack_legacy_qsig_v1(
    mut reader: Reader<'_>,
    version_major: u8,
    version_minor: u8,
) -> Result<ParsedQsig> {
    let suite_id = reader.u8("suiteId")?;
    qsig_suite_name(suite_id)?;

    let hash_alg_id = reader.u8("hashAlgId")?;
    if hash_alg_id != SIG_HASH_ALG_ID_SHA3_512 {
        return Err(err(format!("Unsupported .qsig hashAlgId: {hash_alg_id}")));
    }

    let flags = reader.u16le("flags")?;
    if flags != 0 && flags != LEGACY_QSIG_FLAG_PROFILE_MVP_V1 {
        return Err(err(format!("Unsupported .qsig flags value: {flags}")));
    }

    let mut file_hash = [0u8; FILE_HASH_LEN];
    file_hash.copy_from_slice(reader.take(FILE_HASH_LEN, "fileHash")?);
    let ctx_len = usize::from(reader.u16le("ctxLen")?);
    let meta_len = usize::from(reader.u16le("metaLen")?);
    let sig_len = reader.u32le("sigLen")? as usize;

    let expected_remaining = ctx_len + meta_len + sig_len;
    if reader.remaining() != expected_remaining {
        return Err(err("Invalid .qsig length framing"));
    }

    let ctx_bytes = reader.take(ctx_len, "ctxBytes")?.to_vec();
    let meta_bytes = reader.take(meta_len, "metaBytes")?;
    let signature = reader.take(sig_len, "signature")?.to_vec();

    let metadata = decode_metadata_tlv(meta_bytes)?;
    let signer_fingerprint = metadata
        .signer_fingerprint_record
        .as_deref()
        .map(unpack_signer_fingerprint)
        .transpose()?;

    let tbs = build_legacy_tbs_v1(
        version_major,
        version_minor,
        suite_id,
        hash_alg_id,
        &ctx_bytes,
        &file_hash,
    )?;

    Ok(ParsedQsig {
        version_major,
        version_minor,
        suite_id,
        hash_alg_id,
        flags,
        file_hash,
        ctx_bytes: Vec::new(),
        signature,
        metadata,
        signer_fingerprint,
        tbs,
    })
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut hasher = Crc32::new();
    hasher.update(bytes);
    hasher.finalize()
}

pub fn unpack_pqpk(public_key_file_bytes: &[u8]) -> Result<ParsedPqpk> {
    let mut reader = Reader::new(public_key_file_bytes);
    if reader.take(4, "magic")? != MAGIC_PQPK {
        return Err(err("Invalid detached PQ public key magic"));
    }

    let version_major = reader.u8("versionMajor")?;
    let _version_minor = reader.u8("versionMinor")?;
    if version_major != 0x01 {
        return Err(err(format!(
            "Unsupported detached PQ public key major version: {version_major}"
        )));
    }

    let suite_id = reader.u8("suiteId")?;
    qsig_suite_name(suite_id)?;

    let reserved = reader.u8("reserved")?;
    if reserved != 0 {
        return Err(err("Invalid detached PQ public key flags"));
    }

    let key_len = reader.u32le("keyLen")? as usize;
    let key_bytes = reader.take(key_len, "keyBytes")?.to_vec();
    let checksum = reader.u32le("crc32")?;
    if reader.remaining() != 0 {
        return Err(err("Trailing bytes in detached PQ public key"));
    }
    if checksum != crc32(&public_key_file_bytes[..public_key_file_bytes.len() - 4]) {
        return Err(err("Invalid detached PQ public key CRC32"));
    }

    Ok(ParsedPqpk {
        suite_id,
        key_bytes,
    })
}

fn verify_by_suite(
    suite_id: u8,
    signature: &[u8],
    message: &[u8],
    public_key: &[u8],
    context: &[u8],
) -> bool {
    match suite_id {
        SUITE_ID_ML_DSA_44 => verify_ml_dsa_44(signature, message, public_key, context),
        SUITE_ID_ML_DSA_65 => verify_ml_dsa_65(signature, message, public_key, context),
        SUITE_ID_ML_DSA_87 => verify_ml_dsa_87(signature, message, public_key, context),
        SUITE_ID_SLH_DSA_SHAKE_128S => {
            verify_slh_dsa_shake_128s(signature, message, public_key, context)
        }
        SUITE_ID_SLH_DSA_SHAKE_192S => {
            verify_slh_dsa_shake_192s(signature, message, public_key, context)
        }
        SUITE_ID_SLH_DSA_SHAKE_256S => {
            verify_slh_dsa_shake_256s(signature, message, public_key, context)
        }
        SUITE_ID_SLH_DSA_SHAKE_256F => {
            verify_slh_dsa_shake_256f(signature, message, public_key, context)
        }
        _ => false,
    }
}

fn fail_result(error: impl Into<String>, warnings: Vec<String>) -> SignatureCheckResult {
    SignatureCheckResult {
        ok: false,
        self_signed: false,
        bundle_pinned: false,
        user_pinned: false,
        signer_pinned: false,
        name: String::new(),
        source: String::new(),
        format: "qsig".to_string(),
        suite: None,
        suite_display: None,
        strong_pq: false,
        key_source: None,
        signer_fingerprint_hex: None,
        signer_label: None,
        signer: None,
        error: Some(error.into()),
        warnings,
        artifact_id: String::new(),
        signature_content_digest_alg: None,
        signature_content_digest_hex: None,
        ots_stamped_digest_alg: None,
        ots_stamped_digest_hex: None,
        proof_identity_digest_alg: None,
        proof_identity_digest_hex: None,
        counted_for_policy: false,
        signature_bytes: None,
    }
}

pub fn verify_qsig_against_bytes(
    message_bytes: &[u8],
    qsig_bytes: &[u8],
    bundle_pq_public_key_file_bytes: Option<&[u8]>,
    pinned_pq_public_key_file_bytes: Option<&[u8]>,
) -> Result<SignatureCheckResult> {
    let parsed = unpack_qsig(qsig_bytes)?;
    let mut warnings = Vec::new();

    let computed_file_hash = sha3_512(message_bytes);
    if !timing_safe_equal(&computed_file_hash, &parsed.file_hash) {
        return Ok(fail_result(
            "Signed SHA3-512 hash does not match manifest bytes",
            warnings,
        ));
    }

    let mut candidates = Vec::<(Vec<u8>, &'static str)>::new();
    let mut seen_keys = Vec::<Vec<u8>>::new();
    let mut add_candidate = |public_key: Option<Vec<u8>>, source: &'static str| {
        let Some(public_key) = public_key else {
            return;
        };
        if seen_keys
            .iter()
            .any(|seen| timing_safe_equal(seen, &public_key))
        {
            return;
        }
        seen_keys.push(public_key.clone());
        candidates.push((public_key, source));
    };

    let unpack_candidate_key = |pqpk_bytes: Option<&[u8]>,
                                label: &str,
                                optional: bool,
                                warnings: &mut Vec<String>|
     -> Result<Option<Vec<u8>>> {
        let Some(pqpk_bytes) = pqpk_bytes else {
            return Ok(None);
        };
        let unpacked = match unpack_pqpk(pqpk_bytes) {
            Ok(value) => value,
            Err(error) if optional => {
                warnings.push(format!(
                    "{label} could not be parsed as .pqpk and was ignored: {error}"
                ));
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        if unpacked.suite_id != parsed.suite_id {
            if !optional {
                return Err(err(format!("{label} suite does not match this .qsig.")));
            }
            warnings.push(format!(
                "{label} suite does not match this .qsig and was ignored."
            ));
            return Ok(None);
        }
        Ok(Some(unpacked.key_bytes))
    };

    let bundled_key = unpack_candidate_key(
        bundle_pq_public_key_file_bytes,
        "Bundled PQ public key",
        false,
        &mut warnings,
    )?;
    add_candidate(
        parsed.metadata.signer_public_key.clone(),
        "embedded-signature-key",
    );
    let pinned_key = unpack_candidate_key(
        pinned_pq_public_key_file_bytes,
        "Pinned PQ signer key",
        true,
        &mut warnings,
    )?;
    add_candidate(pinned_key.clone(), "user-pqpk");

    let suite = qsig_suite_name(parsed.suite_id)?;
    let suite_info = get_signature_suite_info(suite)?;
    if let Some(bundled_key) = bundled_key {
        if !verify_by_suite(
            parsed.suite_id,
            &parsed.signature,
            &parsed.tbs,
            &bundled_key,
            &parsed.ctx_bytes,
        ) {
            return Ok(fail_result(
                "PQ signature did not verify with bundled public key",
                warnings,
            ));
        }

        let user_pinned = pinned_key
            .as_ref()
            .map(|key| timing_safe_equal(key, &bundled_key))
            .unwrap_or(false);
        if pinned_key.is_some() && !user_pinned {
            warnings.push("Pinned PQ signer key did not match the bundled signer key.".to_string());
        }

        let computed_fp = sha3_256(&bundled_key);
        if let Some(parsed_fp) = &parsed.signer_fingerprint {
            if !timing_safe_equal(&parsed_fp.digest, &computed_fp) {
                warnings.push(
                    "Signer fingerprint in .qsig metadata does not match the bundled verification key."
                        .to_string(),
                );
            }
        }
        let computed_fp_hex = hex::encode(computed_fp);
        return Ok(SignatureCheckResult {
            ok: true,
            self_signed: false,
            bundle_pinned: true,
            user_pinned,
            signer_pinned: true,
            name: String::new(),
            source: String::new(),
            format: "qsig".to_string(),
            suite: Some(suite.to_string()),
            suite_display: Some(suite_info.display_name.to_string()),
            strong_pq: suite_info.strong_pq,
            key_source: Some("bundle-pqpk".to_string()),
            signer_fingerprint_hex: Some(computed_fp_hex.clone()),
            signer_label: Some(computed_fp_hex),
            signer: None,
            error: None,
            warnings,
            artifact_id: String::new(),
            signature_content_digest_alg: None,
            signature_content_digest_hex: None,
            ots_stamped_digest_alg: None,
            ots_stamped_digest_hex: None,
            proof_identity_digest_alg: None,
            proof_identity_digest_hex: None,
            counted_for_policy: false,
            signature_bytes: Some(qsig_bytes.to_vec()),
        });
    }

    if candidates.is_empty() {
        return Ok(fail_result(
            "No verification key available (.pqpk not provided and no embedded signer key)",
            warnings,
        ));
    }

    let verified_candidate = candidates
        .iter()
        .find(|(public_key, _)| {
            verify_by_suite(
                parsed.suite_id,
                &parsed.signature,
                &parsed.tbs,
                public_key,
                &parsed.ctx_bytes,
            )
        })
        .cloned();

    let Some((verified_key, key_source)) = verified_candidate else {
        return Ok(fail_result("PQ signature verification failed", warnings));
    };

    let user_pinned = pinned_key
        .as_ref()
        .map(|key| timing_safe_equal(key, &verified_key))
        .unwrap_or(false);
    if pinned_key.is_some() && !user_pinned {
        warnings.push("Pinned PQ signer key did not match this verified signature.".to_string());
    }
    if key_source == "embedded-signature-key" && !user_pinned {
        warnings.push(
            "Using signer public key embedded in .qsig; verification succeeded but signer identity is not pinned."
                .to_string(),
        );
    }

    let computed_fp = sha3_256(&verified_key);
    if let Some(parsed_fp) = &parsed.signer_fingerprint {
        if !timing_safe_equal(&parsed_fp.digest, &computed_fp) {
            warnings.push(
                "Signer fingerprint in .qsig metadata does not match the verification key."
                    .to_string(),
            );
        }
    }
    let computed_fp_hex = hex::encode(computed_fp);
    let self_signed = key_source == "embedded-signature-key" && !user_pinned;
    Ok(SignatureCheckResult {
        ok: true,
        self_signed,
        bundle_pinned: false,
        user_pinned,
        signer_pinned: user_pinned,
        name: String::new(),
        source: String::new(),
        format: "qsig".to_string(),
        suite: Some(suite.to_string()),
        suite_display: Some(suite_info.display_name.to_string()),
        strong_pq: suite_info.strong_pq,
        key_source: Some(key_source.to_string()),
        signer_fingerprint_hex: Some(computed_fp_hex.clone()),
        signer_label: Some(computed_fp_hex),
        signer: None,
        error: None,
        warnings,
        artifact_id: String::new(),
        signature_content_digest_alg: None,
        signature_content_digest_hex: None,
        ots_stamped_digest_alg: None,
        ots_stamped_digest_hex: None,
        proof_identity_digest_alg: None,
        proof_identity_digest_hex: None,
        counted_for_policy: false,
        signature_bytes: Some(qsig_bytes.to_vec()),
    })
}

fn verify_ml_dsa_44(signature: &[u8], message: &[u8], public_key: &[u8], context: &[u8]) -> bool {
    if signature.len() != fips204::ml_dsa_44::SIG_LEN
        || public_key.len() != fips204::ml_dsa_44::PK_LEN
    {
        return false;
    }
    let Ok(sig) = <[u8; fips204::ml_dsa_44::SIG_LEN]>::try_from(signature) else {
        return false;
    };
    let Ok(pk_bytes) = <[u8; fips204::ml_dsa_44::PK_LEN]>::try_from(public_key) else {
        return false;
    };
    let Ok(pk) = fips204::ml_dsa_44::PublicKey::try_from_bytes(pk_bytes) else {
        return false;
    };
    pk.verify(message, &sig, context)
}

fn verify_ml_dsa_65(signature: &[u8], message: &[u8], public_key: &[u8], context: &[u8]) -> bool {
    if signature.len() != fips204::ml_dsa_65::SIG_LEN
        || public_key.len() != fips204::ml_dsa_65::PK_LEN
    {
        return false;
    }
    let Ok(sig) = <[u8; fips204::ml_dsa_65::SIG_LEN]>::try_from(signature) else {
        return false;
    };
    let Ok(pk_bytes) = <[u8; fips204::ml_dsa_65::PK_LEN]>::try_from(public_key) else {
        return false;
    };
    let Ok(pk) = fips204::ml_dsa_65::PublicKey::try_from_bytes(pk_bytes) else {
        return false;
    };
    pk.verify(message, &sig, context)
}

fn verify_ml_dsa_87(signature: &[u8], message: &[u8], public_key: &[u8], context: &[u8]) -> bool {
    if signature.len() != fips204::ml_dsa_87::SIG_LEN
        || public_key.len() != fips204::ml_dsa_87::PK_LEN
    {
        return false;
    }
    let Ok(sig) = <[u8; fips204::ml_dsa_87::SIG_LEN]>::try_from(signature) else {
        return false;
    };
    let Ok(pk_bytes) = <[u8; fips204::ml_dsa_87::PK_LEN]>::try_from(public_key) else {
        return false;
    };
    let Ok(pk) = fips204::ml_dsa_87::PublicKey::try_from_bytes(pk_bytes) else {
        return false;
    };
    pk.verify(message, &sig, context)
}

fn verify_slh_dsa_shake_128s(
    signature: &[u8],
    message: &[u8],
    public_key: &[u8],
    context: &[u8],
) -> bool {
    if signature.len() != fips205::slh_dsa_shake_128s::SIG_LEN
        || public_key.len() != fips205::slh_dsa_shake_128s::PK_LEN
    {
        return false;
    }
    let Ok(sig) = <[u8; fips205::slh_dsa_shake_128s::SIG_LEN]>::try_from(signature) else {
        return false;
    };
    let Ok(pk_bytes) = <[u8; fips205::slh_dsa_shake_128s::PK_LEN]>::try_from(public_key) else {
        return false;
    };
    let Ok(pk) = fips205::slh_dsa_shake_128s::PublicKey::try_from_bytes(&pk_bytes) else {
        return false;
    };
    pk.verify(message, &sig, context)
}

fn verify_slh_dsa_shake_192s(
    signature: &[u8],
    message: &[u8],
    public_key: &[u8],
    context: &[u8],
) -> bool {
    if signature.len() != fips205::slh_dsa_shake_192s::SIG_LEN
        || public_key.len() != fips205::slh_dsa_shake_192s::PK_LEN
    {
        return false;
    }
    let Ok(sig) = <[u8; fips205::slh_dsa_shake_192s::SIG_LEN]>::try_from(signature) else {
        return false;
    };
    let Ok(pk_bytes) = <[u8; fips205::slh_dsa_shake_192s::PK_LEN]>::try_from(public_key) else {
        return false;
    };
    let Ok(pk) = fips205::slh_dsa_shake_192s::PublicKey::try_from_bytes(&pk_bytes) else {
        return false;
    };
    pk.verify(message, &sig, context)
}

fn verify_slh_dsa_shake_256s(
    signature: &[u8],
    message: &[u8],
    public_key: &[u8],
    context: &[u8],
) -> bool {
    if signature.len() != fips205::slh_dsa_shake_256s::SIG_LEN
        || public_key.len() != fips205::slh_dsa_shake_256s::PK_LEN
    {
        return false;
    }
    let Ok(sig) = <[u8; fips205::slh_dsa_shake_256s::SIG_LEN]>::try_from(signature) else {
        return false;
    };
    let Ok(pk_bytes) = <[u8; fips205::slh_dsa_shake_256s::PK_LEN]>::try_from(public_key) else {
        return false;
    };
    let Ok(pk) = fips205::slh_dsa_shake_256s::PublicKey::try_from_bytes(&pk_bytes) else {
        return false;
    };
    pk.verify(message, &sig, context)
}

fn verify_slh_dsa_shake_256f(
    signature: &[u8],
    message: &[u8],
    public_key: &[u8],
    context: &[u8],
) -> bool {
    if signature.len() != fips205::slh_dsa_shake_256f::SIG_LEN
        || public_key.len() != fips205::slh_dsa_shake_256f::PK_LEN
    {
        return false;
    }
    let Ok(sig) = <[u8; fips205::slh_dsa_shake_256f::SIG_LEN]>::try_from(signature) else {
        return false;
    };
    let Ok(pk_bytes) = <[u8; fips205::slh_dsa_shake_256f::PK_LEN]>::try_from(public_key) else {
        return false;
    };
    let Ok(pk) = fips205::slh_dsa_shake_256f::PublicKey::try_from_bytes(&pk_bytes) else {
        return false;
    };
    pk.verify(message, &sig, context)
}
