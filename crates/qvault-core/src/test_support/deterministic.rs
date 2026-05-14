use crate::qenc::parse_qenc_header;

pub fn mutate_tail(bytes: &[u8], delta: u8) -> Vec<u8> {
    let mut output = bytes.to_vec();
    let index = output.len() - 1;
    output[index] ^= delta;
    output
}

pub fn remove_qenc_key_commitment_bytes(container_bytes: &[u8]) -> Vec<u8> {
    let parsed = parse_qenc_header(container_bytes).expect("valid qenc header");
    let header_without_commit_len = parsed.offset - parsed.stored_key_commitment.len();
    let mut output =
        Vec::with_capacity(header_without_commit_len + container_bytes.len() - parsed.offset);
    output.extend_from_slice(&container_bytes[..header_without_commit_len]);
    output.extend_from_slice(&container_bytes[parsed.offset..]);
    output
}
