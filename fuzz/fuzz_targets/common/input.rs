pub const MAX_FUZZ_INPUT_LEN: usize = 2 * 1024 * 1024;

pub fn input_is_reasonable(data: &[u8]) -> bool {
    data.len() <= MAX_FUZZ_INPUT_LEN
}
