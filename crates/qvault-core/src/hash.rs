use tiny_keccak::{Hasher, Sha3};

pub fn sha3_256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3::v256();
    hasher.update(bytes);
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    output
}

pub fn sha3_512(bytes: &[u8]) -> [u8; 64] {
    let mut hasher = Sha3::v512();
    hasher.update(bytes);
    let mut output = [0u8; 64];
    hasher.finalize(&mut output);
    output
}

pub fn sha3_512_hex(bytes: &[u8]) -> String {
    hex::encode(sha3_512(bytes))
}
