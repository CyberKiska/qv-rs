use crc32fast::Hasher as Crc32;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{err, Result};

pub const MAGIC_PQPK: &[u8; 4] = b"PQPK";
pub const MAGIC_PQSK: &[u8; 4] = b"PQSK";
pub const KEY_FORMAT_VERSION_MAJOR: u8 = 0x01;
pub const KEY_FORMAT_VERSION_MINOR: u8 = 0x01;

pub const SUITE_ID_ML_DSA_44: u8 = 0x01;
pub const SUITE_ID_ML_DSA_65: u8 = 0x02;
pub const SUITE_ID_ML_DSA_87: u8 = 0x03;
pub const SUITE_ID_SLH_DSA_SHAKE_128S: u8 = 0x11;
pub const SUITE_ID_SLH_DSA_SHAKE_192S: u8 = 0x12;
pub const SUITE_ID_SLH_DSA_SHAKE_256S: u8 = 0x13;
pub const SUITE_ID_SLH_DSA_SHAKE_256F: u8 = 0x14;

const MAX_KEY_BYTES: usize = 16 * 1024;
const MAX_KEY_FILE_BYTES: usize = 32 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqSignatureSuite {
    MlDsa44,
    MlDsa65,
    MlDsa87,
    SlhDsaShake128s,
    SlhDsaShake192s,
    SlhDsaShake256s,
    SlhDsaShake256f,
}

impl PqSignatureSuite {
    pub fn from_suite_id(suite_id: u8) -> Result<Self> {
        match suite_id {
            SUITE_ID_ML_DSA_44 => Ok(Self::MlDsa44),
            SUITE_ID_ML_DSA_65 => Ok(Self::MlDsa65),
            SUITE_ID_ML_DSA_87 => Ok(Self::MlDsa87),
            SUITE_ID_SLH_DSA_SHAKE_128S => Ok(Self::SlhDsaShake128s),
            SUITE_ID_SLH_DSA_SHAKE_192S => Ok(Self::SlhDsaShake192s),
            SUITE_ID_SLH_DSA_SHAKE_256S => Ok(Self::SlhDsaShake256s),
            SUITE_ID_SLH_DSA_SHAKE_256F => Ok(Self::SlhDsaShake256f),
            _ => Err(err(format!(
                "Unsupported detached PQ signature suiteId: {suite_id}"
            ))),
        }
    }

    pub fn suite_id(self) -> u8 {
        match self {
            Self::MlDsa44 => SUITE_ID_ML_DSA_44,
            Self::MlDsa65 => SUITE_ID_ML_DSA_65,
            Self::MlDsa87 => SUITE_ID_ML_DSA_87,
            Self::SlhDsaShake128s => SUITE_ID_SLH_DSA_SHAKE_128S,
            Self::SlhDsaShake192s => SUITE_ID_SLH_DSA_SHAKE_192S,
            Self::SlhDsaShake256s => SUITE_ID_SLH_DSA_SHAKE_256S,
            Self::SlhDsaShake256f => SUITE_ID_SLH_DSA_SHAKE_256F,
        }
    }

    pub fn canonical_name(self) -> &'static str {
        match self {
            Self::MlDsa44 => "mldsa-44",
            Self::MlDsa65 => "mldsa-65",
            Self::MlDsa87 => "mldsa-87",
            Self::SlhDsaShake128s => "slhdsa-shake-128s",
            Self::SlhDsaShake192s => "slhdsa-shake-192s",
            Self::SlhDsaShake256s => "slhdsa-shake-256s",
            Self::SlhDsaShake256f => "slhdsa-shake-256f",
        }
    }

    pub fn public_key_len(self) -> usize {
        match self {
            Self::MlDsa44 => fips204::ml_dsa_44::PK_LEN,
            Self::MlDsa65 => fips204::ml_dsa_65::PK_LEN,
            Self::MlDsa87 => fips204::ml_dsa_87::PK_LEN,
            Self::SlhDsaShake128s => fips205::slh_dsa_shake_128s::PK_LEN,
            Self::SlhDsaShake192s => fips205::slh_dsa_shake_192s::PK_LEN,
            Self::SlhDsaShake256s => fips205::slh_dsa_shake_256s::PK_LEN,
            Self::SlhDsaShake256f => fips205::slh_dsa_shake_256f::PK_LEN,
        }
    }

    pub fn secret_key_len(self) -> usize {
        match self {
            Self::MlDsa44 => fips204::ml_dsa_44::SK_LEN,
            Self::MlDsa65 => fips204::ml_dsa_65::SK_LEN,
            Self::MlDsa87 => fips204::ml_dsa_87::SK_LEN,
            Self::SlhDsaShake128s => fips205::slh_dsa_shake_128s::SK_LEN,
            Self::SlhDsaShake192s => fips205::slh_dsa_shake_192s::SK_LEN,
            Self::SlhDsaShake256s => fips205::slh_dsa_shake_256s::SK_LEN,
            Self::SlhDsaShake256f => fips205::slh_dsa_shake_256f::SK_LEN,
        }
    }
}

/// Legacy structural `.pqpk` parse result used by the verifier compatibility API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPqpk {
    pub suite_id: u8,
    pub key_bytes: Vec<u8>,
}

/// Strict parsed `.pqpk` container with suite-specific key length already checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqPublicKeyFile {
    pub suite: PqSignatureSuite,
    pub version_minor: u8,
    pub key_bytes: Vec<u8>,
}

/// Strict parsed `.pqsk` container. Secret key bytes are zeroized on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct PqSecretKeyFile {
    pub suite: PqSignatureSuite,
    pub version_minor: u8,
    key_bytes: Zeroizing<Vec<u8>>,
}

impl PqSecretKeyFile {
    pub fn key_bytes(&self) -> &[u8] {
        self.key_bytes.as_slice()
    }

    pub fn into_key_bytes(self) -> Zeroizing<Vec<u8>> {
        self.key_bytes
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyFileKind {
    Public,
    Secret,
}

impl KeyFileKind {
    fn magic(self) -> &'static [u8; 4] {
        match self {
            Self::Public => MAGIC_PQPK,
            Self::Secret => MAGIC_PQSK,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Secret => "secret",
        }
    }

    fn expected_key_len(self, suite: PqSignatureSuite) -> usize {
        match self {
            Self::Public => suite.public_key_len(),
            Self::Secret => suite.secret_key_len(),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct RawKeyFile {
    suite: PqSignatureSuite,
    version_minor: u8,
    key_bytes: Vec<u8>,
}

pub fn unpack_pqpk(public_key_file_bytes: &[u8]) -> Result<ParsedPqpk> {
    let raw = parse_key_file(public_key_file_bytes, KeyFileKind::Public)?;
    Ok(ParsedPqpk {
        suite_id: raw.suite.suite_id(),
        key_bytes: raw.key_bytes,
    })
}

pub fn unpack_public_key_file(public_key_file_bytes: &[u8]) -> Result<PqPublicKeyFile> {
    let raw = parse_key_file(public_key_file_bytes, KeyFileKind::Public)?;
    validate_key_len(raw.suite, raw.key_bytes.len(), KeyFileKind::Public)?;
    Ok(PqPublicKeyFile {
        suite: raw.suite,
        version_minor: raw.version_minor,
        key_bytes: raw.key_bytes,
    })
}

pub fn unpack_secret_key_file(secret_key_file_bytes: &[u8]) -> Result<PqSecretKeyFile> {
    let raw = parse_key_file(secret_key_file_bytes, KeyFileKind::Secret)?;
    let key_bytes = Zeroizing::new(raw.key_bytes);
    validate_key_len(raw.suite, key_bytes.len(), KeyFileKind::Secret)?;
    Ok(PqSecretKeyFile {
        suite: raw.suite,
        version_minor: raw.version_minor,
        key_bytes,
    })
}

pub fn pack_public_key_file(suite: PqSignatureSuite, key_bytes: &[u8]) -> Result<Vec<u8>> {
    pack_key_file(suite, key_bytes, KeyFileKind::Public)
}

pub fn pack_secret_key_file(suite: PqSignatureSuite, key_bytes: &[u8]) -> Result<Vec<u8>> {
    pack_key_file(suite, key_bytes, KeyFileKind::Secret)
}

fn parse_key_file(bytes: &[u8], kind: KeyFileKind) -> Result<RawKeyFile> {
    if bytes.len() > MAX_KEY_FILE_BYTES {
        return Err(err(format!(
            "Detached PQ {} key exceeds maximum size ({MAX_KEY_FILE_BYTES} bytes)",
            kind.label()
        )));
    }

    let mut reader = Reader::new(bytes);
    let magic = reader.take(4, "magic")?;
    if magic != &kind.magic()[..] {
        return Err(err(format!(
            "Invalid detached PQ {} key magic",
            kind.label()
        )));
    }

    let version_major = reader.u8("versionMajor")?;
    if version_major != KEY_FORMAT_VERSION_MAJOR {
        return Err(err(format!(
            "Unsupported detached PQ {} key major version: {version_major}",
            kind.label()
        )));
    }

    let version_minor = reader.u8("versionMinor")?;
    let suite_id = reader.u8("suiteId")?;
    let suite = PqSignatureSuite::from_suite_id(suite_id)?;
    let flags = reader.u8("reserved")?;
    if flags != 0 {
        return Err(err(format!(
            "Invalid detached PQ {} key flags",
            kind.label()
        )));
    }

    let key_len = reader.u32le("keyLen")? as usize;
    if key_len > MAX_KEY_BYTES {
        return Err(err(format!(
            "Detached PQ {} key keyLen exceeds maximum size ({MAX_KEY_BYTES} bytes)",
            kind.label()
        )));
    }

    let mut key_bytes = reader.take(key_len, "keyBytes")?.to_vec();
    let crc_expected = match reader.u32le("crc32") {
        Ok(value) => value,
        Err(error) => {
            zeroize_if_secret(key_bytes.as_mut_slice(), kind);
            return Err(error);
        }
    };
    if !reader.remaining().is_empty() {
        zeroize_if_secret(key_bytes.as_mut_slice(), kind);
        return Err(match kind {
            KeyFileKind::Public => err("Trailing bytes in detached PQ public key"),
            KeyFileKind::Secret => err("Trailing bytes in detached PQ secret key"),
        });
    }

    let crc_start = bytes
        .len()
        .checked_sub(4)
        .ok_or_else(|| err("Truncated crc32"))?;
    let crc_actual = crc32(&bytes[..crc_start]);
    if crc_actual != crc_expected {
        zeroize_if_secret(key_bytes.as_mut_slice(), kind);
        return Err(err(format!(
            "Invalid detached PQ {} key CRC32",
            kind.label()
        )));
    }

    Ok(RawKeyFile {
        suite,
        version_minor,
        key_bytes,
    })
}

fn zeroize_if_secret(key_bytes: &mut [u8], kind: KeyFileKind) {
    if kind == KeyFileKind::Secret {
        key_bytes.zeroize();
    }
}

fn pack_key_file(suite: PqSignatureSuite, key_bytes: &[u8], kind: KeyFileKind) -> Result<Vec<u8>> {
    validate_key_len(suite, key_bytes.len(), kind)?;

    let key_len = u32::try_from(key_bytes.len())
        .map_err(|_| err(format!("Detached PQ {} key is too large", kind.label())))?;
    let mut out = Vec::with_capacity(12 + key_bytes.len() + 4);
    out.extend_from_slice(kind.magic());
    out.push(KEY_FORMAT_VERSION_MAJOR);
    out.push(KEY_FORMAT_VERSION_MINOR);
    out.push(suite.suite_id());
    out.push(0);
    out.extend_from_slice(&key_len.to_le_bytes());
    out.extend_from_slice(key_bytes);
    let checksum = crc32(&out);
    out.extend_from_slice(&checksum.to_le_bytes());

    if out.len() > MAX_KEY_FILE_BYTES {
        return Err(err(format!(
            "Detached PQ {} key exceeds maximum size ({MAX_KEY_FILE_BYTES} bytes)",
            kind.label()
        )));
    }

    Ok(out)
}

fn validate_key_len(suite: PqSignatureSuite, key_len: usize, kind: KeyFileKind) -> Result<()> {
    let expected = kind.expected_key_len(suite);
    if key_len != expected {
        return Err(err(format!(
            "Detached PQ {} key length mismatch for {}: expected {expected} bytes, got {key_len}",
            kind.label(),
            suite.canonical_name()
        )));
    }
    Ok(())
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut hasher = Crc32::new();
    hasher.update(bytes);
    hasher.finalize()
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.offset..]
    }

    fn take(&mut self, len: usize, what: &'static str) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| err(format!("Invalid {what} length")))?;
        if end > self.bytes.len() {
            return Err(err(format!("Truncated {what}")));
        }
        let out = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(out)
    }

    fn u8(&mut self, what: &'static str) -> Result<u8> {
        Ok(self.take(1, what)?[0])
    }

    fn u32le(&mut self, what: &'static str) -> Result<u32> {
        let bytes = self.take(4, what)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
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
    fn public_key_pack_round_trips_all_supported_suites() {
        for suite in SUPPORTED_SUITES {
            let key_bytes = fixed_bytes(suite.public_key_len(), suite.suite_id());
            let packed = pack_public_key_file(suite, &key_bytes).unwrap();

            assert_eq!(&packed[..4], MAGIC_PQPK);
            assert_eq!(packed[4], KEY_FORMAT_VERSION_MAJOR);
            assert_eq!(packed[5], KEY_FORMAT_VERSION_MINOR);
            assert_eq!(packed[6], suite.suite_id());
            assert_eq!(packed[7], 0);
            assert_eq!(
                u32::from_le_bytes([packed[8], packed[9], packed[10], packed[11]]) as usize,
                key_bytes.len()
            );
            assert_eq!(packed, pack_public_key_file(suite, &key_bytes).unwrap());

            let parsed = unpack_public_key_file(&packed).unwrap();
            assert_eq!(parsed.suite, suite);
            assert_eq!(parsed.version_minor, KEY_FORMAT_VERSION_MINOR);
            assert_eq!(parsed.key_bytes, key_bytes);
        }
    }

    #[test]
    fn secret_key_pack_round_trips_all_supported_suites() {
        for suite in SUPPORTED_SUITES {
            let key_bytes = fixed_bytes(suite.secret_key_len(), suite.suite_id() ^ 0xa5);
            let packed = pack_secret_key_file(suite, &key_bytes).unwrap();

            assert_eq!(&packed[..4], MAGIC_PQSK);
            assert_eq!(packed[4], KEY_FORMAT_VERSION_MAJOR);
            assert_eq!(packed[5], KEY_FORMAT_VERSION_MINOR);
            assert_eq!(packed[6], suite.suite_id());
            assert_eq!(packed[7], 0);
            assert_eq!(
                u32::from_le_bytes([packed[8], packed[9], packed[10], packed[11]]) as usize,
                key_bytes.len()
            );
            assert_eq!(packed, pack_secret_key_file(suite, &key_bytes).unwrap());

            let parsed = unpack_secret_key_file(&packed).unwrap();
            assert_eq!(parsed.suite, suite);
            assert_eq!(parsed.version_minor, KEY_FORMAT_VERSION_MINOR);
            assert_eq!(parsed.key_bytes(), key_bytes.as_slice());
        }
    }

    #[test]
    fn legacy_pqpk_unpack_keeps_structural_length_behavior() {
        let key_bytes = vec![0x42; PqSignatureSuite::MlDsa65.public_key_len() - 1];
        let packed = pack_key_file_unchecked(MAGIC_PQPK, PqSignatureSuite::MlDsa65, &key_bytes);

        let parsed = unpack_pqpk(&packed).unwrap();
        assert_eq!(parsed.suite_id, SUITE_ID_ML_DSA_65);
        assert_eq!(parsed.key_bytes, key_bytes);

        assert_err_contains(unpack_public_key_file(&packed), "length mismatch");
    }

    #[test]
    fn strict_secret_key_unpack_rejects_wrong_suite_length() {
        let key_bytes = vec![0x34; PqSignatureSuite::MlDsa44.secret_key_len() - 1];
        let packed = pack_key_file_unchecked(MAGIC_PQSK, PqSignatureSuite::MlDsa44, &key_bytes);

        assert_err_contains(unpack_secret_key_file(&packed), "length mismatch");
    }

    #[test]
    fn packers_reject_wrong_suite_lengths() {
        let public_key = vec![0u8; PqSignatureSuite::SlhDsaShake256s.public_key_len() + 1];
        let secret_key = vec![0u8; PqSignatureSuite::SlhDsaShake256s.secret_key_len() - 1];

        assert_err_contains(
            pack_public_key_file(PqSignatureSuite::SlhDsaShake256s, &public_key),
            "length mismatch",
        );

        assert_err_contains(
            pack_secret_key_file(PqSignatureSuite::SlhDsaShake256s, &secret_key),
            "length mismatch",
        );
    }

    #[test]
    fn unpack_rejects_wrong_magic_for_key_kind() {
        let public_key = fixed_bytes(
            PqSignatureSuite::SlhDsaShake128s.public_key_len(),
            SUITE_ID_SLH_DSA_SHAKE_128S,
        );
        let public_packed =
            pack_public_key_file(PqSignatureSuite::SlhDsaShake128s, &public_key).unwrap();
        assert_err_contains(
            unpack_secret_key_file(&public_packed),
            "Invalid detached PQ secret key magic",
        );

        let secret_key = fixed_bytes(
            PqSignatureSuite::SlhDsaShake128s.secret_key_len(),
            SUITE_ID_SLH_DSA_SHAKE_128S,
        );
        let secret_packed =
            pack_secret_key_file(PqSignatureSuite::SlhDsaShake128s, &secret_key).unwrap();
        assert_err_contains(
            unpack_public_key_file(&secret_packed),
            "Invalid detached PQ public key magic",
        );
    }

    #[test]
    fn secret_key_unpack_rejects_malformed_container_fields() {
        let key_bytes = fixed_bytes(
            PqSignatureSuite::MlDsa65.secret_key_len(),
            SUITE_ID_ML_DSA_65,
        );
        let packed = pack_secret_key_file(PqSignatureSuite::MlDsa65, &key_bytes).unwrap();

        let mut bad_flags = packed.clone();
        bad_flags[7] = 1;
        rewrite_crc(&mut bad_flags);
        assert_err_contains(unpack_secret_key_file(&bad_flags), "flags");

        let mut bad_payload = packed.clone();
        bad_payload[12] ^= 0x01;
        assert_err_contains(unpack_secret_key_file(&bad_payload), "CRC32");

        let mut bad_crc = packed.clone();
        let last = bad_crc.len() - 1;
        bad_crc[last] ^= 0x01;
        assert_err_contains(unpack_secret_key_file(&bad_crc), "CRC32");

        let truncated_crc = &packed[..packed.len() - 1];
        assert_err_contains(unpack_secret_key_file(truncated_crc), "Truncated crc32");

        let mut trailing = packed;
        trailing.extend_from_slice(&[0x99]);
        assert_err_contains(unpack_secret_key_file(&trailing), "Trailing bytes");

        let oversized = vec![0u8; MAX_KEY_FILE_BYTES + 1];
        assert_err_contains(unpack_secret_key_file(&oversized), "exceeds maximum size");

        let unknown_suite = pack_key_file_unchecked_with_suite_id(MAGIC_PQSK, 0x21, &[0x55; 64]);
        assert_err_contains(
            unpack_secret_key_file(&unknown_suite),
            "Unsupported detached PQ signature suiteId: 33",
        );
    }

    #[test]
    fn unpack_rejects_unknown_suite_id() {
        let packed = pack_key_file_unchecked_with_suite_id(MAGIC_PQPK, 0x21, &[0x55; 32]);

        assert_err_contains(
            unpack_pqpk(&packed),
            "Unsupported detached PQ signature suiteId: 33",
        );
    }

    #[test]
    fn unpack_rejects_bad_major_flags_crc_and_trailing_bytes() {
        let key_bytes = fixed_bytes(
            PqSignatureSuite::MlDsa44.public_key_len(),
            SUITE_ID_ML_DSA_44,
        );
        let packed = pack_public_key_file(PqSignatureSuite::MlDsa44, &key_bytes).unwrap();

        let mut bad_major = packed.clone();
        bad_major[4] = KEY_FORMAT_VERSION_MAJOR + 1;
        rewrite_crc(&mut bad_major);
        assert_err_contains(unpack_public_key_file(&bad_major), "major version");

        let mut bad_flags = packed.clone();
        bad_flags[7] = 1;
        rewrite_crc(&mut bad_flags);
        assert_err_contains(unpack_public_key_file(&bad_flags), "flags");

        let mut bad_crc = packed.clone();
        let last = bad_crc.len() - 1;
        bad_crc[last] ^= 0x01;
        assert_err_contains(unpack_public_key_file(&bad_crc), "CRC32");

        let mut bad_payload = packed.clone();
        bad_payload[12] ^= 0x01;
        assert_err_contains(unpack_public_key_file(&bad_payload), "CRC32");

        let mut trailing = packed;
        trailing.extend_from_slice(&[0x99]);
        assert_err_contains(unpack_public_key_file(&trailing), "Trailing bytes");
    }

    #[test]
    fn unpack_rejects_oversized_key_len() {
        let packed = pack_key_file_unchecked_with_suite_id(
            MAGIC_PQPK,
            SUITE_ID_ML_DSA_44,
            &vec![0x22; MAX_KEY_BYTES + 1],
        );

        assert_err_contains(unpack_pqpk(&packed), "keyLen exceeds maximum size");
    }

    fn fixed_bytes(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|idx| seed.wrapping_add((idx & 0xff) as u8))
            .collect()
    }

    fn assert_err_contains<T>(result: Result<T>, expected: &str) {
        match result {
            Ok(_) => panic!("expected error containing {expected:?}"),
            Err(error) => {
                let message = error.to_string();
                assert!(
                    message.contains(expected),
                    "expected error containing {expected:?}, got {message:?}"
                );
            }
        }
    }

    fn pack_key_file_unchecked(
        magic: &[u8; 4],
        suite: PqSignatureSuite,
        key_bytes: &[u8],
    ) -> Vec<u8> {
        pack_key_file_unchecked_with_suite_id(magic, suite.suite_id(), key_bytes)
    }

    fn pack_key_file_unchecked_with_suite_id(
        magic: &[u8; 4],
        suite_id: u8,
        key_bytes: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(12 + key_bytes.len() + 4);
        out.extend_from_slice(magic);
        out.push(KEY_FORMAT_VERSION_MAJOR);
        out.push(KEY_FORMAT_VERSION_MINOR);
        out.push(suite_id);
        out.push(0);
        out.extend_from_slice(&(key_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(key_bytes);
        let checksum = crc32(&out);
        out.extend_from_slice(&checksum.to_le_bytes());
        out
    }

    fn rewrite_crc(bytes: &mut [u8]) {
        let crc_offset = bytes.len() - 4;
        let checksum = crc32(&bytes[..crc_offset]);
        bytes[crc_offset..].copy_from_slice(&checksum.to_le_bytes());
    }
}
