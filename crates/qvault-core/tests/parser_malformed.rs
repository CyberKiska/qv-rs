use proptest::prelude::*;

use qvault_core::bundle::parse_bundle_payload;
use qvault_core::qcont::parse_qvqcont7_shard;
use qvault_core::qenc::parse_qenc_header;

const VALID_QENC: &[u8] = include_bytes!("data/qenc_interop/single-small/container.qenc");
const VALID_QCONT: &[u8] = include_bytes!("data/examples/single/file_500kb.part1-of-5.qcont");

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn public_container_parsers_reject_arbitrary_bytes_without_panicking(
        bytes in proptest::collection::vec(any::<u8>(), 0..8192),
    ) {
        let qenc = std::panic::catch_unwind(|| parse_qenc_header(&bytes));
        let qcont = std::panic::catch_unwind(|| parse_qvqcont7_shard(&bytes));
        let qvpack = std::panic::catch_unwind(|| parse_bundle_payload(&bytes));
        prop_assert!(qenc.is_ok(), "QENC parser panicked");
        prop_assert!(qcont.is_ok(), "QCONT parser panicked");
        prop_assert!(qvpack.is_ok(), "QVPACK parser panicked");
    }

    #[test]
    fn qenc_parser_is_panic_free_under_single_byte_mutation(
        index in 0usize..VALID_QENC.len(),
        replacement in any::<u8>(),
    ) {
        let mut bytes = VALID_QENC.to_vec();
        bytes[index] = replacement;
        prop_assert!(std::panic::catch_unwind(|| parse_qenc_header(&bytes)).is_ok());
    }

    #[test]
    fn qcont_parser_is_panic_free_under_single_byte_mutation(
        index in 0usize..VALID_QCONT.len(),
        replacement in any::<u8>(),
    ) {
        let mut bytes = VALID_QCONT.to_vec();
        bytes[index] = replacement;
        prop_assert!(std::panic::catch_unwind(|| parse_qvqcont7_shard(&bytes)).is_ok());
    }
}
