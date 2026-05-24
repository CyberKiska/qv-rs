#![no_main]

use libfuzzer_sys::fuzz_target;
use qvault_core::qenc::metadata::parse_qenc_metadata_bytes;
use qvault_core::qenc::parse_qenc_header;

#[path = "common/input.rs"]
mod input;
#[path = "common/qenc.rs"]
mod qenc;

const SPLIT_V7_SINGLE_SMALL_QENC: &[u8] =
    include_bytes!("../../crates/qvault-core/tests/data/split_v7/single-small.qenc");

fuzz_target!(|data: &[u8]| {
    if !input::input_is_reasonable(data) {
        return;
    }

    let _ = parse_qenc_header(SPLIT_V7_SINGLE_SMALL_QENC);
    let _ = parse_qenc_header(data);
    let _ = parse_qenc_metadata_bytes(data);

    if let Some(metadata) = qenc::qenc_metadata_from_expectations(data) {
        let _ = parse_qenc_metadata_bytes(&metadata);
    }
});
