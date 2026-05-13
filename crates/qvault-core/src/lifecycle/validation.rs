use std::collections::HashSet;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use serde_json::{Map, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::error::{err, Result};

pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

pub fn value_object<'a>(value: &'a Value, field: &str) -> Result<&'a Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| err(format!("Invalid {field}")))
}

pub fn exact_keys(
    source: &Map<String, Value>,
    required: &[&str],
    optional: &[&str],
    field: &str,
) -> Result<()> {
    let allowed = required
        .iter()
        .chain(optional.iter())
        .copied()
        .collect::<HashSet<_>>();
    for key in source.keys() {
        if !allowed.contains(key.as_str()) {
            return Err(err(format!("Unknown {field}.{key}")));
        }
    }
    for key in required {
        if !source.contains_key(*key) {
            return Err(err(format!("Missing {field}.{key}")));
        }
    }
    Ok(())
}

pub fn value_string(value: Option<&Value>, field: &str) -> Result<String> {
    let Some(Value::String(text)) = value else {
        return Err(err(format!("Invalid {field}")));
    };
    if text.is_empty() {
        return Err(err(format!("Invalid {field}")));
    }
    Ok(text.clone())
}

pub fn string(value: Option<&Value>, field: &str) -> Result<String> {
    value_string(value, field)
}

pub fn optional_string(value: Option<&Value>, field: &str) -> Result<Option<String>> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(_) => Ok(Some(value_string(value, field)?)),
    }
}

pub fn exact_string(value: Option<&Value>, field: &str, expected: &str) -> Result<String> {
    let text = string(value, field)?;
    if text != expected {
        return Err(err(format!("Invalid {field}")));
    }
    Ok(text)
}

pub fn hex_string(
    value: Option<&Value>,
    field: &str,
    expected_len: Option<usize>,
) -> Result<String> {
    let text = string(value, field)?;
    if !text
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(err(format!("Invalid {field}")));
    }
    if let Some(expected) = expected_len {
        if text.len() != expected {
            return Err(err(format!("Invalid {field}")));
        }
    }
    Ok(text)
}

pub fn nullable_hex(value: Option<&Value>, field: &str, expected_len: usize) -> Result<Value> {
    if matches!(value, Some(Value::Null)) {
        return Ok(Value::Null);
    }
    Ok(Value::String(hex_string(value, field, Some(expected_len))?))
}

pub fn integer(value: Option<&Value>, field: &str, min: u64, max: u64) -> Result<u64> {
    let Some(Value::Number(number)) = value else {
        return Err(err(format!("Invalid {field}")));
    };
    let Some(value) = number.as_u64() else {
        return Err(err(format!("Invalid {field}")));
    };
    if value < min || value > max {
        return Err(err(format!("Invalid {field}")));
    }
    Ok(value)
}

pub fn safe_integer(value: Option<&Value>, field: &str, min: u64) -> Result<u64> {
    integer(value, field, min, MAX_SAFE_INTEGER)
}

pub fn array<'a>(value: Option<&'a Value>, field: &str) -> Result<&'a Vec<Value>> {
    let Some(Value::Array(values)) = value else {
        return Err(err(format!("Invalid {field}")));
    };
    Ok(values)
}

pub fn exact_string_array(value: Option<&Value>, expected: &[&str], field: &str) -> Result<Value> {
    let values = array(value, field)?;
    if values.len() != expected.len() {
        return Err(err(format!("Invalid {field}")));
    }
    let mut out = Vec::with_capacity(values.len());
    for (index, expected_value) in expected.iter().enumerate() {
        let actual = exact_string(
            values.get(index),
            &format!("{field}[{index}]"),
            expected_value,
        )?;
        out.push(Value::String(actual));
    }
    Ok(Value::Array(out))
}

pub fn string_array(value: Option<&Value>, field: &str, min_items: usize) -> Result<Vec<String>> {
    let values = array(value, field)?;
    if values.len() < min_items {
        return Err(err(format!("Invalid {field}")));
    }
    values
        .iter()
        .enumerate()
        .map(|(index, item)| string(Some(item), &format!("{field}[{index}]")))
        .collect()
}

pub fn hash_list(value: Option<&Value>, field: &str, expected_len: usize) -> Result<Vec<Value>> {
    let values = array(value, field)?;
    if values.is_empty() {
        return Err(err(format!("Invalid {field}")));
    }
    let mut out = Vec::with_capacity(values.len());
    for (index, item) in values.iter().enumerate() {
        out.push(Value::String(hex_string(
            Some(item),
            &format!("{field}[{index}]"),
            Some(expected_len),
        )?));
    }
    Ok(out)
}

pub fn base64_string(value: Option<&Value>, field: &str) -> Result<String> {
    let text = string(value, field)?;
    BASE64_STANDARD
        .decode(text.as_bytes())
        .map_err(|_| err(format!("Invalid {field}")))?;
    Ok(text)
}

pub fn normalize_iso8601(value: Option<&Value>, field: &str) -> Result<String> {
    let text = string(value, field)?;
    let parsed =
        OffsetDateTime::parse(&text, &Rfc3339).map_err(|_| err(format!("Invalid {field}")))?;
    if parsed.nanosecond() % 1_000_000 != 0 {
        return Err(err(format!("Invalid {field}")));
    }
    let month: u8 = parsed.month().into();
    let normalized = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        parsed.year(),
        month,
        parsed.day(),
        parsed.hour(),
        parsed.minute(),
        parsed.second(),
        parsed.millisecond()
    );
    if normalized != text {
        return Err(err(format!("Invalid {field}")));
    }
    Ok(text)
}

pub fn ijson_value(value: &Value, field: &str) -> Result<Value> {
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => Ok(value.clone()),
        Value::Number(_) => {
            let n = safe_integer(Some(value), field, 0)?;
            Ok(Value::Number(serde_json::Number::from(n)))
        }
        Value::Array(values) => Ok(Value::Array(
            values
                .iter()
                .enumerate()
                .map(|(index, item)| ijson_value(item, &format!("{field}[{index}]")))
                .collect::<Result<Vec<_>>>()?,
        )),
        Value::Object(map) => {
            let mut out = Map::new();
            for (key, item) in map {
                out.insert(key.clone(), ijson_value(item, &format!("{field}.{key}"))?);
            }
            Ok(Value::Object(out))
        }
    }
}

pub fn object_from_pairs(pairs: Vec<(&str, Value)>) -> Value {
    let mut map = Map::new();
    for (key, value) in pairs {
        map.insert(key.to_string(), value);
    }
    Value::Object(map)
}

pub fn number(value: u64) -> Value {
    Value::Number(serde_json::Number::from(value))
}
