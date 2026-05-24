use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use serde_json::Value;

pub const MAX_FUZZ_INPUT_LEN: usize = 2 * 1024 * 1024;

pub fn input_is_reasonable(data: &[u8]) -> bool {
    data.len() <= MAX_FUZZ_INPUT_LEN
}

#[allow(dead_code)]
pub fn base64_fixture_bytes(data: &[u8]) -> Option<Vec<u8>> {
    let value: Value = serde_json::from_slice(data).ok()?;
    if value.get("encoding").and_then(Value::as_str) != Some("base64") {
        return None;
    }
    BASE64_STANDARD
        .decode(value.get("bytes").and_then(Value::as_str)?)
        .ok()
}

#[allow(dead_code)]
pub fn qenc_metadata_from_expectations(data: &[u8]) -> Option<Vec<u8>> {
    let value: Value = serde_json::from_slice(data).ok()?;
    value
        .get("qenc")?
        .get("metaUtf8")?
        .as_str()
        .map(|text| text.as_bytes().to_vec())
}
