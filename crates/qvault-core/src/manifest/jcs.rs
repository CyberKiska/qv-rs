use serde::Serialize;
use serde_json::Value;

use crate::error::{err, Result};

pub const MANIFEST_CANONICALIZATION_LABEL: &str = "QV-JSON-RFC8785-v1";
pub const BUNDLE_CANONICALIZATION_LABEL: &str = "QV-BUNDLE-JSON-v1";

pub fn canonicalize_json<T: Serialize>(value: &T) -> Result<String> {
    let json = serde_json::to_value(value)?;
    canonicalize_value(&json)
}

pub fn canonicalize_json_to_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    Ok(canonicalize_json(value)?.into_bytes())
}

fn canonicalize_value(value: &Value) -> Result<String> {
    match value {
        Value::Null => Ok("null".to_string()),
        Value::Bool(boolean) => Ok(boolean.to_string()),
        Value::Number(number) => {
            if !number.is_f64() || number.as_f64().map(f64::is_finite).unwrap_or(false) {
                Ok(number.to_string())
            } else {
                Err(err("JCS does not allow non-finite numbers"))
            }
        }
        Value::String(string) => {
            assert_no_lone_surrogates(string, "string")?;
            Ok(serde_json::to_string(string)?)
        }
        Value::Array(values) => {
            let mut output = String::from("[");
            for (index, item) in values.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                output.push_str(&canonicalize_value(item)?);
            }
            output.push(']');
            Ok(output)
        }
        Value::Object(map) => {
            let mut entries = map.iter().collect::<Vec<_>>();
            entries.sort_by(|(left, _), (right, _)| compare_utf16_keys(left, right));

            let mut output = String::from("{");
            for (index, (key, item)) in entries.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                assert_no_lone_surrogates(key, "object key")?;
                output.push_str(&serde_json::to_string(key)?);
                output.push(':');
                output.push_str(&canonicalize_value(item)?);
            }
            output.push('}');
            Ok(output)
        }
    }
}

fn compare_utf16_keys(left: &str, right: &str) -> std::cmp::Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

pub fn assert_no_lone_surrogates(value: &str, _field: &str) -> Result<()> {
    // Rust strings are guaranteed valid Unicode scalar values, so lone UTF-16
    // surrogate code units cannot be represented after strict JSON parsing.
    let _ = value;
    Ok(())
}
