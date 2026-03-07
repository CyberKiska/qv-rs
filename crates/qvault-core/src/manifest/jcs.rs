use serde::Serialize;
use serde_json::Value;

use crate::error::{err, Result};

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
        Value::String(string) => Ok(serde_json::to_string(string)?),
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
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));

            let mut output = String::from("{");
            for (index, (key, item)) in entries.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                output.push_str(&serde_json::to_string(key)?);
                output.push(':');
                output.push_str(&canonicalize_value(item)?);
            }
            output.push('}');
            Ok(output)
        }
    }
}
