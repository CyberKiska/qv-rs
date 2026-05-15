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
            serialize_number(number).ok_or_else(|| err("JCS does not allow non-finite numbers"))
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

fn serialize_number(number: &serde_json::Number) -> Option<String> {
    serialize_f64_ecmascript(number.as_f64()?)
}

fn serialize_f64_ecmascript(value: f64) -> Option<String> {
    if !value.is_finite() {
        return None;
    }
    if value == 0.0 {
        return Some("0".to_string());
    }

    let negative = value.is_sign_negative();
    let mut shortest = format!("{:?}", value.abs());
    shortest.make_ascii_lowercase();
    let (digits, n) = decimal_digits_and_point(&shortest)?;
    if digits.is_empty() {
        return Some("0".to_string());
    }

    let mut out = String::new();
    if negative {
        out.push('-');
    }
    let k = digits.len() as i32;
    if k <= n && n <= 21 {
        out.push_str(&digits);
        for _ in 0..(n - k) {
            out.push('0');
        }
    } else if 0 < n && n <= 21 {
        let split = n as usize;
        out.push_str(&digits[..split]);
        out.push('.');
        out.push_str(&digits[split..]);
    } else if -6 < n && n <= 0 {
        out.push_str("0.");
        for _ in 0..(-n) {
            out.push('0');
        }
        out.push_str(&digits);
    } else {
        out.push_str(&digits[..1]);
        if digits.len() > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        let exponent = n - 1;
        out.push('e');
        if exponent >= 0 {
            out.push('+');
        }
        out.push_str(&exponent.to_string());
    }
    Some(out)
}

fn decimal_digits_and_point(shortest: &str) -> Option<(String, i32)> {
    let (mantissa, exponent) = match shortest.split_once('e') {
        Some((mantissa, exponent)) => (mantissa, exponent.parse::<i32>().ok()?),
        None => (shortest, 0),
    };
    let (integer, fraction) = match mantissa.split_once('.') {
        Some((integer, fraction)) => (integer, fraction),
        None => (mantissa, ""),
    };

    if integer == "0" {
        let leading_fraction_zeros = fraction.bytes().take_while(|byte| *byte == b'0').count();
        let mut digits = fraction[leading_fraction_zeros..].to_string();
        trim_trailing_zeros(&mut digits);
        if digits.is_empty() {
            return Some((String::new(), 0));
        }
        Some((digits, exponent - leading_fraction_zeros as i32))
    } else {
        let mut digits = String::with_capacity(integer.len() + fraction.len());
        digits.push_str(integer);
        digits.push_str(fraction);
        trim_trailing_zeros(&mut digits);
        Some((digits, integer.len() as i32 + exponent))
    }
}

fn trim_trailing_zeros(value: &mut String) {
    while value.ends_with('0') {
        value.pop();
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Number, Value};
    use std::process::Command;

    fn number_value(value: f64) -> Value {
        Value::Number(Number::from_f64(value).expect("finite test number"))
    }

    #[test]
    fn rfc8785_number_reference_vectors_match_js_oracle() {
        let vectors = [
            (number_value(0.0), "0"),
            (number_value(-0.0), "0"),
            (number_value(1.0), "1"),
            (number_value(-1.0), "-1"),
            (number_value(0.5), "0.5"),
            (number_value(-0.5), "-0.5"),
            (number_value(1e20), "100000000000000000000"),
            (number_value(1e21), "1e+21"),
            (number_value(1e-7), "1e-7"),
            (number_value(1e-6), "0.000001"),
            (number_value(0.1 + 0.2), "0.30000000000000004"),
            (json!(9_007_199_254_740_991u64), "9007199254740991"),
            (json!(-9_007_199_254_740_991i64), "-9007199254740991"),
            (number_value(f64::from_bits(1)), "5e-324"),
            (number_value(-f64::from_bits(1)), "-5e-324"),
            (number_value(f64::MAX), "1.7976931348623157e+308"),
            (number_value(-f64::MAX), "-1.7976931348623157e+308"),
            (json!(9_007_199_254_740_993u64), "9007199254740992"),
        ];

        for (input, expected) in vectors {
            assert_eq!(canonicalize_value(&input).unwrap(), expected);
        }
    }

    #[test]
    fn rfc8785_composite_reference_vector_matches_js_oracle() {
        let sample = json!({
            "numbers": [333333333.33333329, 1e30, 4.5, 2e-3, 1e-27],
            "string": "Euro:\u{20ac} control:\u{000f} newline:\n quote:\" slash:/ backslash:\\",
            "literals": [null, true, false],
        });
        let expected = "{\"literals\":[null,true,false],\"numbers\":[333333333.3333333,1e+30,4.5,0.002,1e-27],\"string\":\"Euro:€ control:\\u000f newline:\\n quote:\\\" slash:/ backslash:\\\\\"}";
        assert_eq!(canonicalize_value(&sample).unwrap(), expected);
    }

    #[test]
    fn sampled_numbers_match_json_stringify_when_node_is_available() {
        let samples = [
            ("0", number_value(0.0)),
            ("-0", number_value(-0.0)),
            ("1", number_value(1.0)),
            ("-1", number_value(-1.0)),
            ("0.5", number_value(0.5)),
            ("-0.5", number_value(-0.5)),
            ("1e20", number_value(1e20)),
            ("1e21", number_value(1e21)),
            ("1e-7", number_value(1e-7)),
            ("1e-6", number_value(1e-6)),
            ("0.1 + 0.2", number_value(0.1 + 0.2)),
            ("Number.MAX_SAFE_INTEGER", json!(9_007_199_254_740_991u64)),
            ("-Number.MAX_SAFE_INTEGER", json!(-9_007_199_254_740_991i64)),
            ("Number.MIN_VALUE", number_value(f64::from_bits(1))),
            ("-Number.MIN_VALUE", number_value(-f64::from_bits(1))),
            ("Number.MAX_VALUE", number_value(f64::MAX)),
            ("-Number.MAX_VALUE", number_value(-f64::MAX)),
            ("9007199254740993", json!(9_007_199_254_740_993u64)),
            ("333333333.33333329", number_value(333333333.33333329)),
            ("1e30", number_value(1e30)),
            ("2e-3", number_value(2e-3)),
            ("1e-27", number_value(1e-27)),
        ];
        let script = format!(
            "for (const value of [{}]) console.log(JSON.stringify(value));",
            samples
                .iter()
                .map(|(literal, _)| *literal)
                .collect::<Vec<_>>()
                .join(",")
        );
        let Ok(output) = Command::new("node").args(["-e", &script]).output() else {
            return;
        };
        if !output.status.success() {
            return;
        }
        let expected = String::from_utf8(output.stdout).expect("node output is UTF-8");
        let expected = expected.lines().collect::<Vec<_>>();
        assert_eq!(expected.len(), samples.len());

        for ((_, value), expected) in samples.iter().zip(expected) {
            assert_eq!(canonicalize_value(value).unwrap(), expected);
        }
    }
}
