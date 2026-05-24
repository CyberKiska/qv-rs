#![no_main]

use libfuzzer_sys::fuzz_target;
use qvault_core::lifecycle::parse_lifecycle_bundle_bytes;
use qvault_core::manifest::strict_json::parse_json_bytes_strict;

mod common;

fuzz_target!(|data: &[u8]| {
    if !common::input_is_reasonable(data) {
        return;
    }

    let _ = parse_json_bytes_strict(data);
    let _ = parse_lifecycle_bundle_bytes(data);
});
