#![no_main]

use libfuzzer_sys::fuzz_target;
use qvault_core::qcont::parse_qvqcont7_shard;

mod common;

fuzz_target!(|data: &[u8]| {
    if !common::input_is_reasonable(data) {
        return;
    }

    let _ = parse_qvqcont7_shard(data);
    if let Some(bytes) = common::base64_fixture_bytes(data) {
        let _ = parse_qvqcont7_shard(&bytes);
    }
});
