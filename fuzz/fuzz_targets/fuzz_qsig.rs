#![no_main]

use libfuzzer_sys::fuzz_target;
use qvault_core::auth::qsig::unpack_qsig;

#[path = "common/fixture.rs"]
mod fixture;
#[path = "common/input.rs"]
mod input;

fuzz_target!(|data: &[u8]| {
    if !input::input_is_reasonable(data) {
        return;
    }

    let _ = unpack_qsig(data);
    if let Some(bytes) = fixture::base64_fixture_bytes(data) {
        let _ = unpack_qsig(&bytes);
    }
});
