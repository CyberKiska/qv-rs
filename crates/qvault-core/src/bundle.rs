use std::path::{Component, Path, PathBuf};

use time::OffsetDateTime;

use crate::error::{err, Result};

const BUNDLE_MAGIC: &[u8; 4] = b"QVB1";
const BUNDLE_VERSION: u8 = 1;

/// Oracle `qvpack.js` `QVPACK_RESOURCE_PROFILE`: normative caps enforced by
/// both the reader and the writer (format-spec "resource profile" MUSTs).
pub const MAX_QVPACK_ENTRY_COUNT: usize = 4096;
pub const MAX_QVPACK_ENTRY_NAME_BYTES: usize = 255;
pub const MAX_QVPACK_ENTRY_PAYLOAD_BYTES: usize = crate::qenc::crypto::MAX_FILE_SIZE;
pub const MAX_QVPACK_AGGREGATE_PAYLOAD_BYTES: usize = crate::qenc::crypto::MAX_FILE_SIZE;
pub const MAX_QVPACK_ENCODED_BYTES: usize = crate::qenc::crypto::MAX_FILE_SIZE;

pub fn validate_portable_filename(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(err("Filename must be a non-empty string"));
    }
    if name == "." || name == ".." {
        return Err(err("Filename must not be a dot path component"));
    }
    if name.chars().any(char::is_control) {
        return Err(err("Filename must not contain control characters"));
    }
    if name.bytes().any(|byte| {
        matches!(
            byte,
            b'/' | b'\\' | b':' | b'*' | b'?' | b'"' | b'<' | b'>' | b'|'
        )
    }) {
        return Err(err(
            "Filename contains a path separator or non-portable character",
        ));
    }
    if matches!(name.as_bytes().last(), Some(b' ' | b'.')) {
        return Err(err("Filename must not end with a space or period"));
    }
    let device_stem = name
        .split('.')
        .next()
        .unwrap_or_default()
        .trim_end_matches([' ', '.'])
        .to_ascii_uppercase();
    let reserved_device = matches!(device_stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || device_stem
            .strip_prefix("COM")
            .or_else(|| device_stem.strip_prefix("LPT"))
            .is_some_and(|suffix| {
                matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
            });
    if reserved_device {
        return Err(err("Filename is reserved by a supported platform"));
    }
    if name.len() > MAX_QVPACK_ENTRY_NAME_BYTES {
        return Err(err(format!(
            "Filename exceeds resource limit ({MAX_QVPACK_ENTRY_NAME_BYTES} UTF-8 bytes)"
        )));
    }
    Ok(())
}

/// Resolve a validated QVPACK entry below a caller-selected extraction root.
///
/// Entry names are restricted to one portable normal path component, so the
/// returned path cannot name the root itself, a parent, or an absolute path.
pub fn bundle_entry_output_path(root: &Path, name: &str) -> Result<PathBuf> {
    validate_portable_filename(name)?;
    let mut components = Path::new(name).components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err(err(
            "QVPACK entry name must be exactly one normal path component",
        ));
    }
    Ok(root.join(name))
}

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
    if entries.len() > MAX_QVPACK_ENTRY_COUNT {
        return Err(err(format!(
            "QVPACK entry count exceeds resource limit ({MAX_QVPACK_ENTRY_COUNT})"
        )));
    }

    let total_size = 4usize
        .checked_add(1)
        .and_then(|value| value.checked_add(2))
        .ok_or_else(|| err("Bundle size overflow"))?;

    let mut seen_names = std::collections::HashSet::new();
    let mut aggregate_payload = 0usize;
    let total_size = entries.iter().try_fold(total_size, |acc, entry| {
        validate_portable_filename(entry.name)?;
        if !seen_names.insert(entry.name.to_ascii_lowercase()) {
            return Err(err(
                "QVPACK contains duplicate or case-colliding entry filenames",
            ));
        }
        let name_bytes = entry.name.as_bytes();
        if entry.bytes.len() > MAX_QVPACK_ENTRY_PAYLOAD_BYTES {
            return Err(err(format!(
                "QVPACK entry payload exceeds resource limit ({MAX_QVPACK_ENTRY_PAYLOAD_BYTES} bytes)"
            )));
        }
        aggregate_payload = aggregate_payload
            .checked_add(entry.bytes.len())
            .filter(|total| *total <= MAX_QVPACK_AGGREGATE_PAYLOAD_BYTES)
            .ok_or_else(|| {
                err(format!(
                    "QVPACK aggregate payload exceeds resource limit ({MAX_QVPACK_AGGREGATE_PAYLOAD_BYTES} bytes)"
                ))
            })?;

        acc.checked_add(2)
            .and_then(|value| value.checked_add(name_bytes.len()))
            .and_then(|value| value.checked_add(4))
            .and_then(|value| value.checked_add(entry.bytes.len()))
            .filter(|total| *total <= MAX_QVPACK_ENCODED_BYTES)
            .ok_or_else(|| {
                err(format!(
                    "QVPACK encoded payload exceeds resource limit ({MAX_QVPACK_ENCODED_BYTES} bytes)"
                ))
            })
    })?;

    let mut out = Vec::new();
    out.try_reserve_exact(total_size)
        .map_err(|_| err("Unable to allocate bundle payload"))?;
    out.resize(total_size, 0);
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
    if bytes.len() > MAX_QVPACK_ENCODED_BYTES {
        return Err(err(format!(
            "QVPACK encoded payload exceeds resource limit ({MAX_QVPACK_ENCODED_BYTES} bytes)"
        )));
    }

    let mut offset = 4usize;
    let version = bytes[offset];
    offset += 1;
    if version != BUNDLE_VERSION {
        return Err(err(format!("Unsupported bundle version: {version}")));
    }

    let count_end = offset
        .checked_add(2)
        .ok_or_else(|| err("Bundle entry-count offset overflow"))?;
    if count_end > bytes.len() {
        return Err(err("Bundle is truncated before entry count"));
    }
    let count = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
    offset = count_end;
    if count == 0 {
        return Err(err("Bundle contains no files"));
    }
    if count > MAX_QVPACK_ENTRY_COUNT {
        return Err(err(format!(
            "QVPACK entry count exceeds resource limit ({MAX_QVPACK_ENTRY_COUNT})"
        )));
    }

    let mut entries = Vec::with_capacity(count);
    let mut seen_names = std::collections::HashSet::new();
    for index in 0..count {
        let name_length_end = offset
            .checked_add(2)
            .ok_or_else(|| err("Bundle name-length offset overflow"))?;
        if name_length_end > bytes.len() {
            return Err(err("Bundle is truncated at name length"));
        }
        let name_len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        offset = name_length_end;
        if name_len == 0 {
            return Err(err(format!(
                "Bundle entry {index} has invalid filename length"
            )));
        }
        if name_len > MAX_QVPACK_ENTRY_NAME_BYTES {
            return Err(err(format!(
                "QVPACK entry filename exceeds resource limit ({MAX_QVPACK_ENTRY_NAME_BYTES} UTF-8 bytes)"
            )));
        }
        let name_end = offset
            .checked_add(name_len)
            .ok_or_else(|| err(format!("Bundle entry {index} filename length overflow")))?;
        if name_end > bytes.len() {
            return Err(err(format!("Bundle entry {index} filename is truncated")));
        }
        let name = std::str::from_utf8(&bytes[offset..name_end])
            .map_err(|error| {
                err(format!(
                    "Bundle entry {index} filename is invalid UTF-8: {error}"
                ))
            })?
            .to_string();
        validate_portable_filename(&name)?;
        if !seen_names.insert(name.to_ascii_lowercase()) {
            return Err(err(
                "QVPACK contains duplicate or case-colliding entry filenames",
            ));
        }
        offset = name_end;

        let size_end = offset
            .checked_add(4)
            .ok_or_else(|| err(format!("Bundle entry {index} payload-length overflow")))?;
        if size_end > bytes.len() {
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
        offset = size_end;
        let payload_end = offset
            .checked_add(size)
            .ok_or_else(|| err(format!("Bundle entry {index} payload length overflow")))?;
        if payload_end > bytes.len() {
            return Err(err(format!("Bundle entry {index} payload is truncated")));
        }
        let payload = &bytes[offset..payload_end];
        offset = payload_end;
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
        build_bundle_payload, bundle_entry_output_path, bundle_filename_for_time,
        is_bundle_payload, parse_bundle_payload, BundleEntryRef,
    };
    use std::path::Path;
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
    fn build_rejects_unsafe_or_non_portable_names() {
        for bad in [
            ".",
            "..",
            "../evil",
            "dir/child",
            "back\\slash",
            "nul\0byte",
            "line\nbreak",
            "C:drive",
            "wild*card",
            "trailing.",
            "trailing ",
            "CON",
            "nul.txt",
            "COM1.log",
            "lpt9",
        ] {
            let error = build_bundle_payload(&[BundleEntryRef {
                name: bad,
                bytes: b"x",
            }])
            .expect_err("unsafe name must fail");
            assert!(!error.to_string().is_empty(), "{bad}: {error}");
        }
    }

    #[test]
    fn build_rejects_duplicate_names() {
        let error = build_bundle_payload(&[
            BundleEntryRef {
                name: "dup",
                bytes: b"a",
            },
            BundleEntryRef {
                name: "dup",
                bytes: b"b",
            },
        ])
        .expect_err("duplicate name must fail");
        assert!(error.to_string().contains("case-colliding entry filenames"));
    }

    #[test]
    fn build_rejects_case_colliding_names() {
        let error = build_bundle_payload(&[
            BundleEntryRef {
                name: "Report.txt",
                bytes: b"a",
            },
            BundleEntryRef {
                name: "report.TXT",
                bytes: b"b",
            },
        ])
        .expect_err("portable extraction collision must fail");
        assert!(error.to_string().contains("case-colliding"));
    }

    #[test]
    fn parse_rejects_path_traversal_entry_name() {
        // Hand-craft a QVB1 bundle whose single entry is named "../evil".
        let name = b"../evil";
        let mut bundle = Vec::new();
        bundle.extend_from_slice(b"QVB1");
        bundle.push(1);
        bundle.extend_from_slice(&1u16.to_be_bytes());
        bundle.extend_from_slice(&(name.len() as u16).to_be_bytes());
        bundle.extend_from_slice(name);
        bundle.extend_from_slice(&1u32.to_be_bytes());
        bundle.push(0x42);
        let error = parse_bundle_payload(&bundle).expect_err("traversal name must fail");
        assert!(error.to_string().contains("path separator"), "{error}");
    }

    #[test]
    fn output_path_is_anchored_below_extraction_root() {
        let root = Path::new("safe-output");
        assert_eq!(
            bundle_entry_output_path(root, "report.txt").unwrap(),
            root.join("report.txt")
        );
        for bad in [".", "..", "../escape", "/absolute", "C:\\escape"] {
            assert!(bundle_entry_output_path(root, bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn bundle_filename_matches_js_shape() {
        let date = Date::from_calendar_date(2026, Month::March, 7).expect("valid test date");
        let time = Time::from_hms(9, 8, 7).expect("valid test time");
        let name = bundle_filename_for_time(date.with_time(time).assume_utc());
        assert_eq!(name, "bundle-2026-03-07T09-08-07.qvpack");
    }
}
