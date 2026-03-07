use crate::error::{err, Result};

pub fn bytes_equal(left: &[u8], right: &[u8]) -> bool {
    left == right
}

pub fn timing_safe_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

pub fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

pub fn from_hex(value: &str) -> Result<Vec<u8>> {
    hex::decode(value).map_err(|error| err(format!("Invalid hex string: {error}")))
}
