use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use crc32fast::Hasher as Crc32Hasher;
use qvault_core::auth::{
    parse_open_timestamp_proof, resolve_open_timestamp_target, unpack_pqpk, unpack_qsig,
    verify_qsig_against_bytes, SignatureArtifact,
};
use qvault_core::hash::{sha256_hex, sha3_256, sha3_512_hex};
use serde_json::Value;

fn data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/corpus")
}

fn read_fixture(path: &Path) -> Result<Value> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn fixture_bytes(fixture: &Value) -> Result<Vec<u8>> {
    let encoding = fixture["encoding"].as_str().context("encoding")?;
    if encoding != "base64" {
        anyhow::bail!("unsupported fixture encoding {encoding}");
    }
    Ok(BASE64_STANDARD.decode(fixture["bytes"].as_str().context("bytes")?)?)
}

fn qsig_fixture_bytes(name: &str) -> Result<Vec<u8>> {
    let fixture = read_fixture(&data_dir().join("qsig").join(name))?;
    fixture_bytes(&fixture)
}

fn qsig_fixture_bytes_and_message(name: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let fixture = read_fixture(&data_dir().join("qsig").join(name))?;
    let bytes = fixture_bytes(&fixture)?;
    let message = BASE64_STANDARD.decode(
        fixture["runtime"]["messageBytes"]
            .as_str()
            .context("runtime.messageBytes")?,
    )?;
    Ok((bytes, message))
}

fn pqpk_fixture_bytes(name: &str) -> Result<Vec<u8>> {
    let fixture = read_fixture(&data_dir().join("pqpk").join(name))?;
    fixture_bytes(&fixture)
}

fn assert_fixture_digest(name: &str, fixture: &Value, bytes: &[u8]) -> Result<()> {
    assert_eq!(
        fixture["expectedDigestAlg"].as_str().unwrap_or("SHA3-512"),
        "SHA3-512",
        "{name}: expected digest algorithm"
    );
    assert_eq!(
        sha3_512_hex(bytes),
        fixture["expectedDigest"]
            .as_str()
            .context("expectedDigest")?,
        "{name}: SHA3-512 digest"
    );
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct QsigLayout {
    auth_meta_start: usize,
    auth_meta_len: usize,
    display_meta_start: usize,
    display_meta_len: usize,
}

fn read_u16le(bytes: &[u8], offset: usize) -> usize {
    usize::from(u16::from_le_bytes([bytes[offset], bytes[offset + 1]]))
}

fn read_u32le(bytes: &[u8], offset: usize) -> usize {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ]) as usize
}

fn write_u16le(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32le(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn qsig_layout(bytes: &[u8]) -> QsigLayout {
    let ctx_len = usize::from(bytes[108]);
    let auth_meta_len = read_u16le(bytes, 110);
    let display_meta_len = read_u16le(bytes, 112);
    let auth_meta_start = 118 + ctx_len;
    let display_meta_start = auth_meta_start + auth_meta_len;
    QsigLayout {
        auth_meta_start,
        auth_meta_len,
        display_meta_start,
        display_meta_len,
    }
}

fn tlv_block_has_tag(bytes: &[u8], tag: u8) -> bool {
    let mut offset = 0;
    while offset + 3 <= bytes.len() {
        let current_tag = bytes[offset];
        let len = read_u16le(bytes, offset + 1);
        offset += 3;
        if offset + len > bytes.len() {
            return false;
        }
        if current_tag == tag {
            return true;
        }
        offset += len;
    }
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TlvRecord {
    tag: u8,
    start: usize,
    value_start: usize,
    end: usize,
}

fn tlv_records(bytes: &[u8]) -> Result<Vec<TlvRecord>> {
    let mut records = Vec::new();
    let mut offset = 0usize;
    while offset < bytes.len() {
        if offset + 3 > bytes.len() {
            bail!("truncated TLV header at offset {offset}");
        }
        let tag = bytes[offset];
        let len = read_u16le(bytes, offset + 1);
        let value_start = offset + 3;
        let end = value_start + len;
        if end > bytes.len() {
            bail!("truncated TLV value at offset {offset}");
        }
        records.push(TlvRecord {
            tag,
            start: offset,
            value_start,
            end,
        });
        offset = end;
    }
    Ok(records)
}

fn auth_meta_bytes(bytes: &[u8]) -> &[u8] {
    let layout = qsig_layout(bytes);
    &bytes[layout.auth_meta_start..layout.auth_meta_start + layout.auth_meta_len]
}

fn replace_auth_meta(bytes: &mut Vec<u8>, replacement: &[u8]) {
    let layout = qsig_layout(bytes);
    bytes.splice(
        layout.auth_meta_start..layout.auth_meta_start + layout.auth_meta_len,
        replacement.iter().copied(),
    );
    write_u16le(bytes, 110, replacement.len() as u16);
    let auth_meta_digest =
        sha3_256(&bytes[layout.auth_meta_start..layout.auth_meta_start + replacement.len()]);
    bytes[76..108].copy_from_slice(&auth_meta_digest);
}

fn qsig_auth_record(bytes: &[u8], tag: u8) -> Result<TlvRecord> {
    tlv_records(auth_meta_bytes(bytes))?
        .into_iter()
        .find(|record| record.tag == tag)
        .with_context(|| format!("authMeta tag {tag:#04x} not found"))
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut hasher = Crc32Hasher::new();
    hasher.update(bytes);
    hasher.finalize()
}

fn refresh_pqpk_crc(bytes: &mut [u8]) {
    let checksum_offset = bytes.len() - 4;
    let checksum = crc32(&bytes[..checksum_offset]);
    bytes[checksum_offset..].copy_from_slice(&checksum.to_le_bytes());
}

fn suite_name(suite_id: u8) -> &'static str {
    match suite_id {
        1 => "mldsa-44",
        2 => "mldsa-65",
        3 => "mldsa-87",
        0x11 => "slhdsa-shake-128s",
        0x12 => "slhdsa-shake-192s",
        0x13 => "slhdsa-shake-256s",
        0x14 => "slhdsa-shake-256f",
        _ => "unknown",
    }
}

#[test]
fn qsig_rejects_malformed_authenticated_metadata_order_like_oracle() -> Result<()> {
    let mut bytes = qsig_fixture_bytes("mldsa-65.valid.json")?;
    let auth_meta = auth_meta_bytes(&bytes);
    let records = tlv_records(auth_meta)?;
    let signer_public_key = records
        .iter()
        .find(|record| record.tag == 0x10)
        .context("signer public key record")?;
    let signer_fingerprint = records
        .iter()
        .find(|record| record.tag == 0x11)
        .context("signer fingerprint record")?;

    let mut reordered = Vec::with_capacity(auth_meta.len());
    reordered.extend_from_slice(&auth_meta[signer_fingerprint.start..signer_fingerprint.end]);
    reordered.extend_from_slice(&auth_meta[signer_public_key.start..signer_public_key.end]);
    replace_auth_meta(&mut bytes, &reordered);

    let error = unpack_qsig(&bytes).expect_err("expected non-canonical authMeta rejection");
    assert!(
        error
            .to_string()
            .contains("Non-canonical metadata TLV order"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn qsig_rejects_duplicate_authenticated_metadata_tags_like_oracle() -> Result<()> {
    let mut bytes = qsig_fixture_bytes("mldsa-65.valid.json")?;
    let auth_meta = auth_meta_bytes(&bytes);
    let records = tlv_records(auth_meta)?;
    let signer_public_key = records
        .iter()
        .find(|record| record.tag == 0x10)
        .context("signer public key record")?;
    let signer_fingerprint = records
        .iter()
        .find(|record| record.tag == 0x11)
        .context("signer fingerprint record")?;

    let mut duplicated = Vec::with_capacity(auth_meta.len() + signer_public_key.end);
    duplicated.extend_from_slice(&auth_meta[signer_public_key.start..signer_public_key.end]);
    duplicated.extend_from_slice(&auth_meta[signer_public_key.start..signer_public_key.end]);
    duplicated.extend_from_slice(&auth_meta[signer_fingerprint.start..signer_fingerprint.end]);
    replace_auth_meta(&mut bytes, &duplicated);

    let error = unpack_qsig(&bytes).expect_err("expected duplicate authMeta tag rejection");
    assert!(
        error
            .to_string()
            .contains("Non-canonical metadata TLV order"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn qsig_rejects_oversized_length_fields_like_oracle() -> Result<()> {
    let cases = [
        (110usize, 8193u32, "authMetaLen exceeds maximum size"),
        (112usize, 4097u32, "displayMetaLen exceeds maximum size"),
        (114usize, 65537u32, "sigLen exceeds maximum size"),
    ];

    for (offset, value, expected) in cases {
        let mut bytes = qsig_fixture_bytes("mldsa-65.valid.json")?;
        if offset == 114 {
            write_u32le(&mut bytes, offset, value);
        } else {
            write_u16le(&mut bytes, offset, value as u16);
        }

        let error = unpack_qsig(&bytes).expect_err("expected oversized field rejection");
        assert!(
            error.to_string().contains(expected),
            "expected {expected:?}, got {error}"
        );
    }
    Ok(())
}

#[test]
fn qsig_rejects_context_mismatch_like_oracle() -> Result<()> {
    let mut bytes = qsig_fixture_bytes("mldsa-65.valid.json")?;
    let ctx_start = 118usize;
    bytes[ctx_start] ^= 0x01;

    let error = unpack_qsig(&bytes).expect_err("expected context mismatch rejection");
    assert!(
        error
            .to_string()
            .contains("Unsupported detached PQ signature context"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn qsig_corpus_parses_and_verifies_like_oracle() -> Result<()> {
    let mut entries =
        fs::read_dir(data_dir().join("qsig"))?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        let name = entry.file_name().to_string_lossy().to_string();
        let fixture = read_fixture(&entry.path())?;
        let bytes = fixture_bytes(&fixture)?;
        assert_fixture_digest(&name, &fixture, &bytes)?;

        if fixture["valid"].as_bool().unwrap_or(false) {
            let parsed = unpack_qsig(&bytes).with_context(|| format!("{name}: unpack qsig"))?;
            assert_eq!(
                suite_name(parsed.suite_id),
                fixture["runtime"]["expectedSuite"]
                    .as_str()
                    .context("expectedSuite")?,
                "{name}: suite"
            );
            let message = BASE64_STANDARD.decode(
                fixture["runtime"]["messageBytes"]
                    .as_str()
                    .context("messageBytes")?,
            )?;
            let result = verify_qsig_against_bytes(&message, &bytes, None, None)
                .with_context(|| format!("{name}: verify qsig"))?;
            assert!(
                result.ok,
                "{name}: expected valid signature, got {:?}",
                result.error
            );
        } else if let Some(message) = fixture["runtime"]["messageBytes"].as_str() {
            let message = BASE64_STANDARD.decode(message)?;
            let result = verify_qsig_against_bytes(&message, &bytes, None, None)
                .with_context(|| format!("{name}: verify negative qsig"))?;
            assert!(
                !result.ok,
                "{name}: expected signature verification failure"
            );
        } else {
            let error = unpack_qsig(&bytes).expect_err(&format!("{name}: expected unpack failure"));
            if let Some(reason) = fixture["rejectionReason"].as_str() {
                assert!(
                    error.to_string().contains(reason),
                    "{name}: expected error containing {reason:?}, got {error}"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn qsig_rejects_display_flag_mismatch_like_oracle() -> Result<()> {
    let mut bytes = qsig_fixture_bytes("mldsa-65.valid.json")?;
    let layout = qsig_layout(&bytes);
    let display_meta =
        &bytes[layout.display_meta_start..layout.display_meta_start + layout.display_meta_len];
    let has_filename = tlv_block_has_tag(display_meta, 0x01);

    let mut flags = u16::from_le_bytes([bytes[10], bytes[11]]);
    if has_filename {
        flags &= !0x0002;
    } else {
        flags |= 0x0002;
    }
    bytes[10..12].copy_from_slice(&flags.to_le_bytes());

    let error = unpack_qsig(&bytes).expect_err("expected display flag mismatch");
    assert!(
        error.to_string().contains("filename flag mismatch"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn qsig_rejects_bad_signer_fingerprint_binding_like_oracle() -> Result<()> {
    let mut bytes = qsig_fixture_bytes("mldsa-65.valid.json")?;
    let mut auth_meta = auth_meta_bytes(&bytes).to_vec();
    let signer_fingerprint = qsig_auth_record(&bytes, 0x11)?;
    auth_meta[signer_fingerprint.value_start + 1] ^= 0x01;
    replace_auth_meta(&mut bytes, &auth_meta);

    let error = unpack_qsig(&bytes).expect_err("expected signer fingerprint rejection");
    assert!(
        error
            .to_string()
            .contains("Signer fingerprint does not match signer public key in authMeta"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn qsig_signature_length_mismatch_fails_verification_like_oracle() -> Result<()> {
    let (mut bytes, message) = qsig_fixture_bytes_and_message("mldsa-65.valid.json")?;
    let sig_len = read_u32le(&bytes, 114);
    write_u32le(&mut bytes, 114, (sig_len - 1) as u32);
    bytes.pop();

    let parsed = unpack_qsig(&bytes).context("truncated signature should still parse")?;
    assert_eq!(parsed.signature.len(), sig_len - 1);
    let result = verify_qsig_against_bytes(&message, &bytes, None, None)?;
    assert!(!result.ok, "signature length mismatch must not verify");
    assert_eq!(
        result.error.as_deref(),
        Some("PQ signature verification failed")
    );
    Ok(())
}

#[test]
fn qsig_wrong_declared_suite_fails_verification_like_oracle() -> Result<()> {
    let (mut bytes, message) = qsig_fixture_bytes_and_message("mldsa-65.valid.json")?;
    bytes[6] = 0x01;

    let parsed = unpack_qsig(&bytes).context("wrong supported suite should still parse")?;
    assert_eq!(suite_name(parsed.suite_id), "mldsa-44");
    let result = verify_qsig_against_bytes(&message, &bytes, None, None)?;
    assert!(!result.ok, "wrong declared suite must not verify");
    assert_eq!(
        result.error.as_deref(),
        Some("PQ signature verification failed")
    );
    Ok(())
}

#[test]
fn qsig_embedded_key_only_verifies_but_is_not_pinned_like_oracle() -> Result<()> {
    let (bytes, message) = qsig_fixture_bytes_and_message("mldsa-65.valid.json")?;
    let result = verify_qsig_against_bytes(&message, &bytes, None, None)?;

    assert!(result.ok);
    assert!(result.self_signed);
    assert!(!result.signer_pinned);
    assert!(!result.bundle_pinned);
    assert!(!result.user_pinned);
    assert_eq!(result.key_source.as_deref(), Some("embedded-signature-key"));
    assert!(
        result
            .warnings
            .iter()
            .any(|warning| warning.contains("signer identity is not pinned")),
        "{:?}",
        result.warnings
    );
    Ok(())
}

#[test]
fn qsig_rejects_unexpected_authenticated_metadata_tag_like_oracle() -> Result<()> {
    let mut bytes = qsig_fixture_bytes("mldsa-65.valid.json")?;
    let layout = qsig_layout(&bytes);
    let inserted = [0x12, 0x00, 0x00];
    bytes.splice(
        layout.display_meta_start..layout.display_meta_start,
        inserted,
    );

    let auth_meta_len = layout.auth_meta_len + inserted.len();
    bytes[110..112].copy_from_slice(&(auth_meta_len as u16).to_le_bytes());
    let auth_meta_end = layout.auth_meta_start + auth_meta_len;
    let auth_meta_digest = sha3_256(&bytes[layout.auth_meta_start..auth_meta_end]);
    bytes[76..108].copy_from_slice(&auth_meta_digest);

    let error = unpack_qsig(&bytes).expect_err("expected unexpected authMeta tag rejection");
    assert!(
        error.to_string().contains("Unexpected authMeta tag"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn qsig_rejects_oversized_signature_file_like_oracle() -> Result<()> {
    let mut bytes = qsig_fixture_bytes("mldsa-65.valid.json")?;
    bytes.resize((128 * 1024) + 1, 0);

    let error = unpack_qsig(&bytes).expect_err("expected oversized qsig rejection");
    assert!(
        error.to_string().contains("exceeds maximum size"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn pqpk_rejects_oversized_key_len_like_oracle() -> Result<()> {
    let mut bytes = pqpk_fixture_bytes("mldsa-65.valid.json")?;
    write_u32le(&mut bytes, 8, (16 * 1024) + 1);

    let error = unpack_pqpk(&bytes).expect_err("expected oversized key length rejection");
    assert!(
        error.to_string().contains("keyLen exceeds maximum size"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn pqpk_rejects_unsupported_suite_byte_like_oracle() -> Result<()> {
    let mut bytes = pqpk_fixture_bytes("mldsa-65.valid.json")?;
    bytes[6] = 0x21;
    refresh_pqpk_crc(&mut bytes);

    let error = unpack_pqpk(&bytes).expect_err("expected unsupported suite rejection");
    assert!(
        error
            .to_string()
            .contains("Unsupported detached PQ signature suiteId"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn qsig_wrong_suite_pqpk_optional_vs_authoritative() -> Result<()> {
    let (qsig, message) = qsig_fixture_bytes_and_message("mldsa-65.valid.json")?;
    let wrong_suite_pqpk = pqpk_fixture_bytes("mldsa-44.valid.json")?;

    let result = verify_qsig_against_bytes(&message, &qsig, None, Some(&wrong_suite_pqpk))?;
    assert!(
        result.ok,
        "embedded key should still verify cryptographically"
    );
    assert!(result.self_signed);
    assert!(!result.user_pinned);
    assert!(
        result
            .warnings
            .iter()
            .any(|warning| warning.contains("suite does not match this .qsig and was ignored")),
        "{:?}",
        result.warnings
    );

    let error = verify_qsig_against_bytes(&message, &qsig, Some(&wrong_suite_pqpk), None)
        .expect_err("authoritative bundled wrong-suite key must fail closed");
    assert!(
        error
            .to_string()
            .contains("Bundled PQ public key suite does not match this .qsig"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn pqpk_corpus_parses_or_rejects_like_oracle() -> Result<()> {
    let mut entries =
        fs::read_dir(data_dir().join("pqpk"))?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        let name = entry.file_name().to_string_lossy().to_string();
        let fixture = read_fixture(&entry.path())?;
        let bytes = fixture_bytes(&fixture)?;
        assert_fixture_digest(&name, &fixture, &bytes)?;

        if fixture["valid"].as_bool().unwrap_or(false) {
            let parsed = unpack_pqpk(&bytes).with_context(|| format!("{name}: unpack pqpk"))?;
            assert_eq!(
                parsed.suite_id,
                fixture["runtime"]["expectedSuiteId"]
                    .as_u64()
                    .context("expectedSuiteId")? as u8,
                "{name}: suiteId"
            );
            assert!(!parsed.key_bytes.is_empty(), "{name}: key bytes");
        } else {
            let error = unpack_pqpk(&bytes).expect_err(&format!("{name}: expected pqpk failure"));
            if let Some(reason) = fixture["rejectionReason"].as_str() {
                assert!(
                    error.to_string().contains(reason),
                    "{name}: expected error containing {reason:?}, got {error}"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn ots_corpus_links_only_to_exact_signature_digest() -> Result<()> {
    let mut entries = fs::read_dir(data_dir().join("ots"))?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        let name = entry.file_name().to_string_lossy().to_string();
        let fixture = read_fixture(&entry.path())?;
        let bytes = fixture_bytes(&fixture)?;
        assert_fixture_digest(&name, &fixture, &bytes)?;

        let parsed = parse_open_timestamp_proof(&bytes, Some(&name));
        if !fixture["valid"].as_bool().unwrap_or(false) && fixture["runtime"].is_null() {
            let error = parsed.expect_err(&format!("{name}: expected OTS parse failure"));
            if let Some(reason) = fixture["rejectionReason"].as_str() {
                assert!(
                    error.to_string().contains(reason),
                    "{name}: expected error containing {reason:?}, got {error}"
                );
            }
            continue;
        }

        let parsed = parsed.with_context(|| format!("{name}: parse OTS"))?;
        let signatures = fixture["runtime"]["signatures"]
            .as_array()
            .context("runtime.signatures")?
            .iter()
            .map(signature_artifact)
            .collect::<Result<Vec<_>>>()?;
        let linked = resolve_open_timestamp_target(&bytes, Some(&name), &signatures);
        if fixture["valid"].as_bool().unwrap_or(false) {
            let linked = linked.with_context(|| format!("{name}: resolve OTS"))?;
            assert_eq!(linked.stamped_digest_hex, parsed.stamped_digest_hex);
            assert!(linked.linked, "{name}: linked");
        } else {
            let error = linked.expect_err(&format!("{name}: expected OTS linkage failure"));
            if let Some(reason) = fixture["rejectionReason"].as_str() {
                assert!(
                    error.to_string().contains(reason),
                    "{name}: expected error containing {reason:?}, got {error}"
                );
            }
        }
    }
    Ok(())
}

fn signature_artifact(value: &Value) -> Result<SignatureArtifact> {
    let bytes = BASE64_STANDARD.decode(value["bytes"].as_str().context("signature bytes")?)?;
    Ok(SignatureArtifact {
        id: value["id"].as_str().unwrap_or("signature").to_string(),
        name: value["name"]
            .as_str()
            .unwrap_or("signature.qsig")
            .to_string(),
        source: "corpus".to_string(),
        family: "archive-approval".to_string(),
        format: "qsig".to_string(),
        target_type: None,
        target_ref: None,
        signature_content_digest_hex: value["signatureContentDigestHex"]
            .as_str()
            .map(str::to_string),
        ots_stamped_digest_hex: Some(sha256_hex(&bytes)),
        bytes,
        ok: true,
    })
}
