#![no_main]

use libfuzzer_sys::fuzz_target;
use qvault_core::qcont::parse_qvqcont7_shard;

#[path = "common/fixture.rs"]
mod fixture;
#[path = "common/input.rs"]
mod input;

fuzz_target!(|data: &[u8]| {
    if !input::input_is_reasonable(data) {
        return;
    }

    let _ = parse_qvqcont7_shard(data);
    if let Some(bytes) = fixture::base64_fixture_bytes(data) {
        let _ = parse_qvqcont7_shard(&bytes);
    }
});
