use time::OffsetDateTime;

use crate::error::{err, Result};

const BUNDLE_MAGIC: &[u8; 4] = b"QVB1";
const BUNDLE_VERSION: u8 = 1;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BundleEntryRef<'a> {
    pub name: &'a str,
    pub bytes: &'a [u8],
}

impl std::fmt::Debug for BundleEntryRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BundleEntryRef")
            .field("name", &self.name)
            .field("bytes_len", &self.bytes.len())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ParsedBundleEntry<'a> {
    pub name: String,
    pub bytes: &'a [u8],
}

impl std::fmt::Debug for ParsedBundleEntry<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParsedBundleEntry")
            .field("name", &self.name)
            .field("bytes_len", &self.bytes.len())
            .finish()
    }
}

pub fn build_bundle_payload(entries: &[BundleEntryRef<'_>]) -> Result<Vec<u8>> {
    if entries.is_empty() {
        return Err(err("Bundle must contain at least one file"));
    }
    if entries.len() > usize::from(u16::MAX) {
        return Err(err("Bundle contains too many files"));
    }

    let total_size = 4usize
        .checked_add(1)
        .and_then(|value| value.checked_add(2))
        .ok_or_else(|| err("Bundle size overflow"))?;

    let total_size = entries.iter().try_fold(total_size, |acc, entry| {
        let name_bytes = entry.name.as_bytes();
        if name_bytes.is_empty() || name_bytes.len() > usize::from(u16::MAX) {
            return Err(err(format!(
                "Invalid filename length for bundle entry: \"{}\"",
                entry.name
            )));
        }
        if entry.bytes.len() > u32::MAX as usize {
            return Err(err(format!(
                "File is too large for bundle format: \"{}\"",
                entry.name
            )));
        }

        acc.checked_add(2)
            .and_then(|value| value.checked_add(name_bytes.len()))
            .and_then(|value| value.checked_add(4))
            .and_then(|value| value.checked_add(entry.bytes.len()))
            .ok_or_else(|| err("Bundle size overflow"))
    })?;

    let mut out = vec![0u8; total_size];
    let mut offset = 0usize;
    out[offset..offset + 4].copy_from_slice(BUNDLE_MAGIC);
    offset += 4;
    out[offset] = BUNDLE_VERSION;
    offset += 1;
    out[offset..offset + 2].copy_from_slice(&(entries.len() as u16).to_be_bytes());
    offset += 2;

    for entry in entries {
        let name_bytes = entry.name.as_bytes();
        out[offset..offset + 2].copy_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        offset += 2;
        out[offset..offset + name_bytes.len()].copy_from_slice(name_bytes);
        offset += name_bytes.len();
        out[offset..offset + 4].copy_from_slice(&(entry.bytes.len() as u32).to_be_bytes());
        offset += 4;
        out[offset..offset + entry.bytes.len()].copy_from_slice(entry.bytes);
        offset += entry.bytes.len();
    }

    debug_assert_eq!(offset, out.len());
    Ok(out)
}

pub fn is_bundle_payload(bytes: &[u8]) -> bool {
    bytes.len() >= 7 && bytes[..4] == *BUNDLE_MAGIC
}

pub fn parse_bundle_payload(bytes: &[u8]) -> Result<Vec<ParsedBundleEntry<'_>>> {
    if !is_bundle_payload(bytes) {
        return Err(err("Not a valid bundle payload"));
    }

    let mut offset = 4usize;
    let version = bytes[offset];
    offset += 1;
    if version != BUNDLE_VERSION {
        return Err(err(format!("Unsupported bundle version: {version}")));
    }

    if offset + 2 > bytes.len() {
        return Err(err("Bundle is truncated before entry count"));
    }
    let count = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
    offset += 2;
    if count == 0 {
        return Err(err("Bundle contains no files"));
    }

    let mut entries = Vec::with_capacity(count);
    for index in 0..count {
        if offset + 2 > bytes.len() {
            return Err(err("Bundle is truncated at name length"));
        }
        let name_len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        offset += 2;
        if name_len == 0 {
            return Err(err(format!(
                "Bundle entry {index} has invalid filename length"
            )));
        }
        if offset + name_len > bytes.len() {
            return Err(err(format!("Bundle entry {index} filename is truncated")));
        }
        let name = std::str::from_utf8(&bytes[offset..offset + name_len])
            .map_err(|error| {
                err(format!(
                    "Bundle entry {index} filename is invalid UTF-8: {error}"
                ))
            })?
            .to_string();
        offset += name_len;

        if offset + 4 > bytes.len() {
            return Err(err(format!(
                "Bundle entry {index} is missing payload length"
            )));
        }
        let size = u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as usize;
        offset += 4;
        if offset + size > bytes.len() {
            return Err(err(format!("Bundle entry {index} payload is truncated")));
        }
        let payload = &bytes[offset..offset + size];
        offset += size;
        entries.push(ParsedBundleEntry {
            name,
            bytes: payload,
        });
    }

    if offset != bytes.len() {
        return Err(err("Bundle has trailing bytes"));
    }

    Ok(entries)
}

pub fn current_bundle_filename() -> String {
    bundle_filename_for_time(OffsetDateTime::now_utc())
}

pub fn bundle_filename_for_time(time: OffsetDateTime) -> String {
    format!(
        "bundle-{:04}-{:02}-{:02}T{:02}-{:02}-{:02}.qvpack",
        time.year(),
        u8::from(time.month()),
        time.day(),
        time.hour(),
        time.minute(),
        time.second()
    )
}

#[cfg(test)]
mod tests {
    use super::{
        build_bundle_payload, bundle_filename_for_time, is_bundle_payload, parse_bundle_payload,
        BundleEntryRef,
    };
    use time::{Date, Month, Time};

    #[test]
    fn build_and_parse_bundle_round_trip() {
        let bundle = build_bundle_payload(&[
            BundleEntryRef {
                name: "a.txt",
                bytes: b"alpha payload",
            },
            BundleEntryRef {
                name: "b.bin",
                bytes: &[1, 2, 3, 4],
            },
        ])
        .expect("build bundle");

        assert!(is_bundle_payload(&bundle));
        let entries = parse_bundle_payload(&bundle).expect("parse bundle");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "a.txt");
        assert_eq!(entries[0].bytes, b"alpha payload");
        assert_eq!(entries[1].name, "b.bin");
        assert_eq!(entries[1].bytes, [1, 2, 3, 4]);
    }

    #[test]
    fn parse_bundle_rejects_trailing_bytes() {
        let mut bundle = build_bundle_payload(&[BundleEntryRef {
            name: "a.txt",
            bytes: b"alpha payload",
        }])
        .expect("build bundle");
        bundle.push(0xff);

        let error = parse_bundle_payload(&bundle).expect_err("bundle should fail");
        assert_eq!(error.to_string(), "Bundle has trailing bytes");
    }

    #[test]
    fn bundle_filename_matches_js_shape() {
        let date = Date::from_calendar_date(2026, Month::March, 7).expect("valid test date");
        let time = Time::from_hms(9, 8, 7).expect("valid test time");
        let name = bundle_filename_for_time(date.with_time(time).assume_utc());
        assert_eq!(name, "bundle-2026-03-07T09-08-07.qvpack");
    }
}
