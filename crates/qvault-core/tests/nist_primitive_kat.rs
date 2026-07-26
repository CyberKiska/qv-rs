//! Known-answer tests against official published vectors, anchoring the
//! primitives to the standards rather than only to JS-oracle parity.
//!
//! - KMAC256: NIST SP 800-185 sample vectors (samples #4, #5, #6).
//!   <https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values>
//! - SHA3-256 / SHA3-512: FIPS 202 known answers for the empty string and "abc".

use qvault_core::hash::{sha3_256, sha3_512};
use qvault_core::kdf::kmac256;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The 256-bit key `40 41 42 ... 5F` shared by every SP 800-185 KMAC sample.
fn sample_key() -> Vec<u8> {
    (0x40u8..=0x5f).collect()
}

/// Sample #4/#5/#6 data is `00 01 02 03` (4 bytes) or `00..C7` (200 bytes).
fn ramp(len: usize) -> Vec<u8> {
    (0..len).map(|index| index as u8).collect()
}

#[test]
fn kmac256_matches_nist_sp800_185_samples() {
    // (data, customization, expected output) — KMAC256, 512-bit output.
    let cases: [(Vec<u8>, &str, &str); 3] = [
        (
            ramp(4),
            "My Tagged Application",
            "20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7\
             f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd",
        ),
        (
            ramp(200),
            "",
            "75358cf39e41494e949707927cee0af20a3ff553904c86b08f21cc414bcfd691\
             589d27cf5e15369cbbff8b9a4c2eb17800855d0235ff635da82533ec6b759b69",
        ),
        (
            ramp(200),
            "My Tagged Application",
            "b58618f71f92e1d56c1b8c55ddd7cd188b97b4ca4d99831eb2699a837da2e4d9\
             70fbacfde50033aea585f1a2708510c32d07880801bd182898fe476876fc8965",
        ),
    ];

    let key = sample_key();
    for (index, (data, customization, expected)) in cases.iter().enumerate() {
        let output = kmac256(&key, data, expected.len() / 2, customization)
            .expect("KMAC256 must produce output");
        assert_eq!(
            hex(&output),
            *expected,
            "KMAC256 SP 800-185 sample #{} mismatch",
            index + 4
        );
    }
}

#[test]
fn sha3_matches_fips202_known_answers() {
    assert_eq!(
        hex(&sha3_256(b"")),
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    );
    assert_eq!(
        hex(&sha3_256(b"abc")),
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
    );
    assert_eq!(
        hex(&sha3_512(b"")),
        "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6\
         15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    );
    assert_eq!(
        hex(&sha3_512(b"abc")),
        "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e\
         10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
    );
}
