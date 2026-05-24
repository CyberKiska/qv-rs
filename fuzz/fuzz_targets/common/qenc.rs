use serde_json::Value;

pub fn qenc_metadata_from_expectations(data: &[u8]) -> Option<Vec<u8>> {
    let value: Value = serde_json::from_slice(data).ok()?;
    value
        .get("qenc")?
        .get("metaUtf8")?
        .as_str()
        .map(|text| text.as_bytes().to_vec())
}
