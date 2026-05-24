use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use serde_json::Value;

pub fn base64_fixture_bytes(data: &[u8]) -> Option<Vec<u8>> {
    let value: Value = serde_json::from_slice(data).ok()?;
    if value.get("encoding").and_then(Value::as_str) != Some("base64") {
        return None;
    }
    BASE64_STANDARD
        .decode(value.get("bytes").and_then(Value::as_str)?)
        .ok()
}
