#![no_main]

use libfuzzer_sys::fuzz_target;
use qvault_core::qenc::metadata::parse_qenc_metadata_bytes;
use qvault_core::qenc::parse_qenc_header;

mod common;

fuzz_target!(|data: &[u8]| {
    if !common::input_is_reasonable(data) {
        return;
    }

    let _ = parse_qenc_header(data);
    let _ = parse_qenc_metadata_bytes(data);

    if let Some(metadata) = common::qenc_metadata_from_expectations(data) {
        let _ = parse_qenc_metadata_bytes(&metadata);
    }
});
