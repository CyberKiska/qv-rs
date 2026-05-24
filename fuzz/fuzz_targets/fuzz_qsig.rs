#![no_main]

use libfuzzer_sys::fuzz_target;
use qvault_core::auth::qsig::unpack_qsig;

mod common;

fuzz_target!(|data: &[u8]| {
    if !common::input_is_reasonable(data) {
        return;
    }

    let _ = unpack_qsig(data);
    if let Some(bytes) = common::base64_fixture_bytes(data) {
        let _ = unpack_qsig(&bytes);
    }
});
