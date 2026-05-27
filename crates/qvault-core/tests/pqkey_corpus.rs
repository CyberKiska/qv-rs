use anyhow::{Context, Result};
use crc32fast::Hasher as Crc32;
use qvault_core::auth::pqkey::{
    pack_secret_key_file, unpack_secret_key_file, PqSignatureSuite, KEY_FORMAT_VERSION_MAJOR,
    KEY_FORMAT_VERSION_MINOR, MAGIC_PQPK, MAGIC_PQSK, SUITE_ID_ML_DSA_44, SUITE_ID_ML_DSA_65,
};

const MAX_KEY_BYTES: usize = 16 * 1024;
const MAX_KEY_FILE_BYTES: usize = 32 * 1024;

#[derive(Debug, Clone, Copy)]
struct PqskValidFixture {
    name: &'static str,
    suite: PqSignatureSuite,
}

const VALID_PQSK_FIXTURES: [PqskValidFixture; 7] = [
    PqskValidFixture {
        name: "mldsa-44",
        suite: PqSignatureSuite::MlDsa44,
    },
    PqskValidFixture {
        name: "mldsa-65",
        suite: PqSignatureSuite::MlDsa65,
    },
    PqskValidFixture {
        name: "mldsa-87",
        suite: PqSignatureSuite::MlDsa87,
    },
    PqskValidFixture {
        name: "slhdsa-shake-128s",
        suite: PqSignatureSuite::SlhDsaShake128s,
    },
    PqskValidFixture {
        name: "slhdsa-shake-192s",
        suite: PqSignatureSuite::SlhDsaShake192s,
    },
    PqskValidFixture {
        name: "slhdsa-shake-256s",
        suite: PqSignatureSuite::SlhDsaShake256s,
    },
    PqskValidFixture {
        name: "slhdsa-shake-256f",
        suite: PqSignatureSuite::SlhDsaShake256f,
    },
];

#[test]
fn pqsk_valid_corpus_round_trips_all_supported_suites() -> Result<()> {
    for fixture in VALID_PQSK_FIXTURES {
        let key_bytes = deterministic_test_key_bytes(fixture.suite, fixture.name);
        let packed = pack_secret_key_file(fixture.suite, &key_bytes)
            .with_context(|| format!("{}: pack pqsk", fixture.name))?;

        assert_eq!(&packed[..4], MAGIC_PQSK, "{}: magic", fixture.name);
        assert_eq!(
            packed[4], KEY_FORMAT_VERSION_MAJOR,
            "{}: version major",
            fixture.name
        );
        assert_eq!(
            packed[5], KEY_FORMAT_VERSION_MINOR,
            "{}: version minor",
            fixture.name
        );
        assert_eq!(
            packed[6],
            fixture.suite.suite_id(),
            "{}: suite id",
            fixture.name
        );
        assert_eq!(packed[7], 0, "{}: flags", fixture.name);
        assert_eq!(
            read_u32_le(&packed[8..12]) as usize,
            key_bytes.len(),
            "{}: key length",
            fixture.name
        );
        assert_eq!(
            read_u32_le(&packed[packed.len() - 4..]),
            crc32(&packed[..packed.len() - 4]),
            "{}: crc32",
            fixture.name
        );
        assert_eq!(
            packed,
            pack_secret_key_file(fixture.suite, &key_bytes)?,
            "{}: deterministic serialization",
            fixture.name
        );

        let parsed = unpack_secret_key_file(&packed)
            .with_context(|| format!("{}: unpack pqsk", fixture.name))?;
        assert_eq!(
            parsed.suite, fixture.suite,
            "{}: parsed suite",
            fixture.name
        );
        assert_eq!(
            parsed.version_minor, KEY_FORMAT_VERSION_MINOR,
            "{}: parsed version minor",
            fixture.name
        );
        assert_eq!(
            parsed.key_bytes(),
            key_bytes.as_slice(),
            "{}: parsed key",
            fixture.name
        );
    }

    Ok(())
}

#[test]
fn pqsk_malformed_corpus_rejects_fail_closed() {
    let valid_key = deterministic_test_key_bytes(PqSignatureSuite::MlDsa65, "mldsa-65");
    let valid = pack_secret_key_file(PqSignatureSuite::MlDsa65, &valid_key).unwrap();

    let mut cases = Vec::<MalformedPqskFixture>::new();

    let mut bad_magic = valid.clone();
    bad_magic[..4].copy_from_slice(MAGIC_PQPK);
    rewrite_crc(&mut bad_magic);
    cases.push(MalformedPqskFixture::new(
        "bad-magic",
        bad_magic,
        "Invalid detached PQ secret key magic",
    ));

    cases.push(MalformedPqskFixture::new(
        "unsupported-suite",
        pack_key_file_unchecked(MAGIC_PQSK, 0x21, &[0x55; 64]),
        "Unsupported detached PQ signature suiteId: 33",
    ));

    let mut nonzero_flags = valid.clone();
    nonzero_flags[7] = 1;
    rewrite_crc(&mut nonzero_flags);
    cases.push(MalformedPqskFixture::new(
        "nonzero-flags",
        nonzero_flags,
        "Invalid detached PQ secret key flags",
    ));

    let mut bad_crc = valid.clone();
    let last = bad_crc.len() - 1;
    bad_crc[last] ^= 0x80;
    cases.push(MalformedPqskFixture::new(
        "bad-crc32",
        bad_crc,
        "Invalid detached PQ secret key CRC32",
    ));

    cases.push(MalformedPqskFixture::new(
        "truncated-header",
        b"PQS".to_vec(),
        "Truncated magic",
    ));

    cases.push(MalformedPqskFixture::new(
        "truncated-crc32",
        valid[..valid.len() - 1].to_vec(),
        "Truncated crc32",
    ));

    let mut trailing = valid.clone();
    trailing.push(0x99);
    cases.push(MalformedPqskFixture::new(
        "trailing-bytes",
        trailing,
        "Trailing bytes in detached PQ secret key",
    ));

    cases.push(MalformedPqskFixture::new(
        "wrong-key-length",
        pack_key_file_unchecked(
            MAGIC_PQSK,
            SUITE_ID_ML_DSA_65,
            &valid_key[..valid_key.len() - 1],
        ),
        "Detached PQ secret key length mismatch",
    ));

    cases.push(MalformedPqskFixture::new(
        "oversized-file",
        vec![0u8; MAX_KEY_FILE_BYTES + 1],
        "Detached PQ secret key exceeds maximum size",
    ));

    cases.push(MalformedPqskFixture::new(
        "oversized-key-len",
        pack_key_file_unchecked(
            MAGIC_PQSK,
            SUITE_ID_ML_DSA_44,
            &vec![0x22; MAX_KEY_BYTES + 1],
        ),
        "Detached PQ secret key keyLen exceeds maximum size",
    ));

    for case in cases {
        assert_err_contains(
            unpack_secret_key_file(&case.bytes),
            case.expected_error,
            case.name,
        );
    }
}

#[test]
fn pqsk_crc_tamper_corpus_rejects_payload_and_trailer_flips() {
    let key_bytes =
        deterministic_test_key_bytes(PqSignatureSuite::SlhDsaShake128s, "slhdsa-shake-128s");
    let valid = pack_secret_key_file(PqSignatureSuite::SlhDsaShake128s, &key_bytes).unwrap();

    let mut payload_tampered = valid.clone();
    payload_tampered[12] ^= 0x01;
    assert_err_contains(
        unpack_secret_key_file(&payload_tampered),
        "Invalid detached PQ secret key CRC32",
        "payload-tampered",
    );

    let mut crc_tampered = valid;
    let last = crc_tampered.len() - 1;
    crc_tampered[last] ^= 0x01;
    assert_err_contains(
        unpack_secret_key_file(&crc_tampered),
        "Invalid detached PQ secret key CRC32",
        "crc-tampered",
    );
}

struct MalformedPqskFixture {
    name: &'static str,
    bytes: Vec<u8>,
    expected_error: &'static str,
}

impl MalformedPqskFixture {
    fn new(name: &'static str, bytes: Vec<u8>, expected_error: &'static str) -> Self {
        Self {
            name,
            bytes,
            expected_error,
        }
    }
}

fn deterministic_test_key_bytes(suite: PqSignatureSuite, label: &str) -> Vec<u8> {
    let mut state = crc32(label.as_bytes()) ^ u32::from(suite.suite_id());
    let mut out = Vec::with_capacity(suite.secret_key_len());
    while out.len() < suite.secret_key_len() {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(suite.secret_key_len());
    out
}

fn pack_key_file_unchecked(magic: &[u8; 4], suite_id: u8, key_bytes: &[u8]) -> Vec<u8> {
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

fn crc32(bytes: &[u8]) -> u32 {
    let mut hasher = Crc32::new();
    hasher.update(bytes);
    hasher.finalize()
}

fn read_u32_le(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().expect("slice length is checked by caller"))
}

fn assert_err_contains<T>(
    result: qvault_core::error::Result<T>,
    expected_error: &str,
    case_name: &str,
) {
    match result {
        Ok(_) => panic!("{case_name}: expected error containing {expected_error:?}"),
        Err(error) => {
            let message = error.to_string();
            assert!(
                message.contains(expected_error),
                "{case_name}: expected error containing {expected_error:?}, got {message:?}"
            );
        }
    }
}
