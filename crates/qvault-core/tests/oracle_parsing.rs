use anyhow::Result;
use serde_json::Value;

use qvault_core::manifest::{canonicalize_archive_manifest, ArchiveManifest};
use qvault_core::qcont::{parse_qcont_shard, parse_qcont_shard_non_strict};
use qvault_core::qenc::parse_qenc_header;
use qvault_core::test_support::deterministic::{
    mutate_qcont_manifest_byte, remove_qenc_key_commitment_bytes,
};
use qvault_core::test_support::fixtures::{fixture_path, read_fixture_bytes, read_fixture_json};

#[test]
fn parses_single_small_qenc_fixture() -> Result<()> {
    let fixture_dir = fixture_path("single-small");
    let qenc_bytes = read_fixture_bytes(fixture_dir.join("container.qenc"))?;
    let expectations: Value = read_fixture_json(fixture_dir.join("expectations.json"))?;

    let parsed = parse_qenc_header(&qenc_bytes)?;
    assert_eq!(
        parsed.offset as u64,
        expectations["qenc"]["headerLength"].as_u64().unwrap()
    );
    assert_eq!(
        parsed.encapsulated_key.len() as u64,
        expectations["qenc"]["encapsulatedKeyLength"]
            .as_u64()
            .unwrap()
    );
    assert_eq!(
        hex::encode(parsed.container_nonce),
        expectations["qenc"]["containerNonceHex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(parsed.kdf_salt),
        expectations["qenc"]["kdfSaltHex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(parsed.stored_key_commitment),
        expectations["qenc"]["keyCommitmentHex"].as_str().unwrap()
    );
    assert_eq!(
        serde_json::to_value(&parsed.metadata)?,
        expectations["qenc"]["metadata"].clone()
    );
    Ok(())
}

#[test]
fn parses_chunked_qenc_fixture() -> Result<()> {
    let fixture_dir = fixture_path("chunked-large");
    let qenc_bytes = read_fixture_bytes(fixture_dir.join("container.qenc"))?;
    let expectations: Value = read_fixture_json(fixture_dir.join("expectations.json"))?;

    let parsed = parse_qenc_header(&qenc_bytes)?;
    assert_eq!(parsed.metadata.aead_mode, "per-chunk-aead");
    assert_eq!(parsed.metadata.iv_strategy, "kmac-prefix64-ctr32-v3");
    assert_eq!(
        parsed.metadata.chunk_count.unwrap(),
        expectations["qenc"]["metadata"]["chunkCount"]
            .as_u64()
            .unwrap()
    );
    assert_eq!(
        parsed.metadata.payload_length.unwrap(),
        expectations["qenc"]["metadata"]["payloadLength"]
            .as_u64()
            .unwrap()
    );
    assert_eq!(parsed.metadata.max_chunk_count, 0xffff_ffff);
    Ok(())
}

#[test]
fn canonicalizes_manifest_exactly_like_js_oracle() -> Result<()> {
    let fixture_dir = fixture_path("split-5of3");
    let expectations: Value = read_fixture_json(fixture_dir.join("expectations.json"))?;
    let manifest_bytes = read_fixture_bytes(fixture_dir.join("manifest.qvmanifest.json"))?;
    let manifest: ArchiveManifest =
        serde_json::from_value(expectations["split"]["manifest"].clone())?;

    let canonicalized = canonicalize_archive_manifest(&manifest)?;
    assert_eq!(canonicalized.bytes, manifest_bytes);
    assert_eq!(
        canonicalized.digest_hex,
        expectations["split"]["manifestDigestHex"].as_str().unwrap()
    );
    Ok(())
}

#[test]
fn parses_qcont_shard_fixture() -> Result<()> {
    let fixture_dir = fixture_path("split-5of3");
    let expectations: Value = read_fixture_json(fixture_dir.join("expectations.json"))?;
    let shard_name = expectations["split"]["shards"][0]["fileName"]
        .as_str()
        .unwrap();
    let shard_bytes = read_fixture_bytes(fixture_dir.join(shard_name))?;

    let parsed = parse_qcont_shard(&shard_bytes)?;
    assert_eq!(
        parsed.manifest_digest_hex,
        expectations["split"]["manifestDigestHex"].as_str().unwrap()
    );
    assert_eq!(
        parsed.shard_index as u64,
        expectations["split"]["shards"][0]["shardIndex"]
            .as_u64()
            .unwrap()
    );
    assert_eq!(
        parsed.share.len() as u64,
        expectations["split"]["shards"][0]["shareLength"]
            .as_u64()
            .unwrap()
    );
    assert_eq!(
        hex::encode(parsed.key_commit),
        expectations["split"]["shards"][0]["keyCommitmentHex"]
            .as_str()
            .unwrap()
    );
    assert_eq!(parsed.meta_json.has_key_commitment, true);
    assert!(!parsed.fragments.is_empty());
    Ok(())
}

#[test]
fn rejects_invalid_qenc_magic() -> Result<()> {
    let fixture_dir = fixture_path("single-small");
    let mut qenc_bytes = read_fixture_bytes(fixture_dir.join("container.qenc"))?;
    qenc_bytes[0] ^= 0xff;
    assert!(parse_qenc_header(&qenc_bytes).is_err());
    Ok(())
}

#[test]
fn stripped_qenc_key_commitment_remains_structurally_parseable() -> Result<()> {
    let fixture_dir = fixture_path("single-small");
    let qenc_bytes = read_fixture_bytes(fixture_dir.join("container.qenc"))?;
    let malformed = remove_qenc_key_commitment_bytes(&qenc_bytes);
    let parsed = parse_qenc_header(&malformed)?;
    assert_eq!(parsed.offset, parse_qenc_header(&qenc_bytes)?.offset);
    Ok(())
}

#[test]
fn rejects_truncated_qenc_container() -> Result<()> {
    let fixture_dir = fixture_path("single-small");
    let qenc_bytes = read_fixture_bytes(fixture_dir.join("container.qenc"))?;
    let truncated = &qenc_bytes[..64];
    assert!(parse_qenc_header(truncated).is_err());
    Ok(())
}

#[test]
fn rejects_tampered_qcont_manifest() -> Result<()> {
    let fixture_dir = fixture_path("split-5of3");
    let expectations: Value = read_fixture_json(fixture_dir.join("expectations.json"))?;
    let shard_name = expectations["split"]["shards"][0]["fileName"]
        .as_str()
        .unwrap();
    let shard_bytes = read_fixture_bytes(fixture_dir.join(shard_name))?;
    let tampered = mutate_qcont_manifest_byte(&shard_bytes, 0x01);
    assert!(parse_qcont_shard(&tampered).is_err());
    Ok(())
}

#[test]
fn rejects_invalid_qcont_magic() -> Result<()> {
    let fixture_dir = fixture_path("split-5of3");
    let expectations: Value = read_fixture_json(fixture_dir.join("expectations.json"))?;
    let shard_name = expectations["split"]["shards"][0]["fileName"]
        .as_str()
        .unwrap();
    let mut shard_bytes = read_fixture_bytes(fixture_dir.join(shard_name))?;
    shard_bytes[0] ^= 0xff;
    assert!(parse_qcont_shard(&shard_bytes).is_err());
    Ok(())
}

#[test]
fn non_strict_qcont_parse_returns_diagnostics() {
    let garbage = vec![0x42; 512];
    let report = parse_qcont_shard_non_strict(&garbage);
    assert!(report.shard.is_none());
    assert!(!report.diagnostics.errors.is_empty());
}
