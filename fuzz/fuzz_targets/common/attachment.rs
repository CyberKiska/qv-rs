const MAX_FUZZ_ATTACHMENT_LEN: usize = 512 * 1024;

fn clamp_attachment_bytes(data: &[u8]) -> Vec<u8> {
    let end = data.len().min(MAX_FUZZ_ATTACHMENT_LEN);
    data[..end].to_vec()
}

/// Optional override bytes from `data[3..]`, split at the midpoint when both flags are set.
pub fn optional_attachment_bytes(data: &[u8], attach_flags: u8, archive: bool) -> Option<Vec<u8>> {
    let flag = if archive { 0x01 } else { 0x02 };
    if attach_flags & flag == 0 {
        return None;
    }
    let tail = data.get(3..)?;
    if tail.is_empty() {
        return None;
    }
    let bytes = if attach_flags & 0x01 != 0 && attach_flags & 0x02 != 0 {
        let mid = tail.len() / 2;
        if archive {
            &tail[..mid]
        } else {
            &tail[mid..]
        }
    } else {
        tail
    };
    if bytes.is_empty() {
        return None;
    }
    Some(clamp_attachment_bytes(bytes))
}
