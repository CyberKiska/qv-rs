use crate::error::{err, Result};
use subtle::ConstantTimeEq;

pub fn bytes_equal(left: &[u8], right: &[u8]) -> bool {
    left == right
}

pub fn timing_safe_equal(left: &[u8], right: &[u8]) -> bool {
    left.ct_eq(right).into()
}

pub fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

pub fn from_hex(value: &str) -> Result<Vec<u8>> {
    hex::decode(value).map_err(|error| err(format!("Invalid hex string: {error}")))
}
