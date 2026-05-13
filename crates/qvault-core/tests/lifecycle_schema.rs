use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use qvault_core::lifecycle::{
    canonicalize_lifecycle_bundle, derive_cohort_id, parse_archive_state_descriptor_bytes,
    parse_cohort_binding_bytes, parse_lifecycle_bundle_bytes, parse_source_evidence_bytes,
    parse_transition_record_bytes,
};
use qvault_core::manifest::jcs::canonicalize_json_to_bytes;
use qvault_core::manifest::strict_json::parse_json_bytes_strict;
use serde_json::Value;

fn oracle_schema_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../qv-work/quantum-vault/docs/schema")
        .canonicalize()
        .expect("oracle schema dir")
}

fn read_fixture_json(relative: &str) -> Result<Value> {
    let bytes = fs::read(oracle_schema_dir().join(relative))?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn read_fixture_bytes(relative: &str) -> Result<Vec<u8>> {
    Ok(fs::read(oracle_schema_dir().join(relative))?)
}

fn runtime_fixture_bytes(relative: &str, use_raw_json_bytes: bool) -> Result<Vec<u8>> {
    let raw = read_fixture_bytes(relative)?;
    if use_raw_json_bytes {
        return Ok(raw);
    }
    let value = parse_json_bytes_strict(&raw)?;
    Ok(canonicalize_json_to_bytes(&value)?)
}

fn parse_artifact(artifact: &str, bytes: &[u8]) -> qvault_core::Result<Option<String>> {
    match artifact {
        "archive-state" => Ok(Some(
            parse_archive_state_descriptor_bytes(bytes)?.digest.value,
        )),
        "cohort-binding" => Ok(Some(parse_cohort_binding_bytes(bytes)?.digest.value)),
        "transition-record" => Ok(Some(parse_transition_record_bytes(bytes)?.digest.value)),
        "source-evidence" => Ok(Some(parse_source_evidence_bytes(bytes)?.digest.value)),
        "lifecycle-bundle" => Ok(Some(parse_lifecycle_bundle_bytes(bytes)?.digest.value)),
        other => Err(qvault_core::error::err(format!(
            "unsupported artifact {other}"
        ))),
    }
}

#[test]
fn lifecycle_schema_fixtures_parse_or_reject_like_oracle_index() -> Result<()> {
    let index = read_fixture_json("fixtures/index.json")?;
    let fixtures = index["fixtures"]
        .as_array()
        .context("fixtures index must contain array")?;

    for fixture in fixtures {
        let id = fixture["id"].as_str().context("missing fixture id")?;
        let runtime = &fixture["runtime"];
        if !runtime.is_object() {
            continue;
        }
        if runtime["contextualLifecycleBundleFile"].is_string() {
            continue;
        }
        let artifact = runtime["artifact"]
            .as_str()
            .with_context(|| format!("{id}: missing runtime artifact"))?;
        let relative = fixture["file"]
            .as_str()
            .with_context(|| format!("{id}: missing fixture file"))?;
        let use_raw = runtime["useRawJsonBytes"].as_bool().unwrap_or(false);
        let bytes = runtime_fixture_bytes(relative, use_raw)?;
        let parsed = parse_artifact(artifact, &bytes);
        let expect_success = runtime["expectParseSuccess"].as_bool().unwrap_or(false);

        if expect_success {
            let digest = parsed.with_context(|| format!("{id}: expected parse success"))?;
            if let Some(expected) = fixture["expectedDigestHex"].as_str() {
                assert_eq!(digest.as_deref(), Some(expected), "{id}");
            }
        } else {
            let error = parsed.expect_err(&format!("{id}: expected parse failure"));
            if let Some(expected) = runtime["expectErrorIncludes"].as_str() {
                assert!(
                    error.to_string().contains(expected),
                    "{id}: expected error containing {expected:?}, got {error}"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn lifecycle_transition_contextual_state_change_rejects_inside_bundle() -> Result<()> {
    let transition = read_fixture_json(
        "fixtures/qv-transition-record-v1.schema-valid.semantic-invalid.state-change.json",
    )?;
    let transition_bytes = canonicalize_json_to_bytes(&transition)?;
    parse_transition_record_bytes(&transition_bytes)
        .context("state-changing transition remains standalone structurally valid")?;

    let mut bundle = read_fixture_json("fixtures/qv-lifecycle-bundle-v1.valid.json")?;
    bundle["transitions"][0] = transition;
    let bundle_bytes = canonicalize_json_to_bytes(&bundle)?;
    let error = parse_lifecycle_bundle_bytes(&bundle_bytes).unwrap_err();
    assert!(
        error.to_string().contains("changes stateId"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn lifecycle_identity_derivation_matches_transition_fixture() -> Result<()> {
    let bundle = read_fixture_json("fixtures/qv-lifecycle-bundle-v1.valid.json")?;
    let canonical = canonicalize_lifecycle_bundle(&bundle)?;
    let bundle_object = canonical
        .lifecycle_bundle
        .value
        .as_object()
        .context("bundle object")?;
    let archive_id = bundle_object["archiveState"]["archiveId"]
        .as_str()
        .context("archiveId")?;
    let state_id = bundle_object["archiveStateDigest"]["value"]
        .as_str()
        .context("stateId")?;
    let current_digest: qvault_core::lifecycle::DigestObject =
        serde_json::from_value(bundle_object["currentCohortBindingDigest"].clone())?;
    let cohort_id = derive_cohort_id(archive_id, state_id, &current_digest)?;
    let transition_to_cohort_id = bundle_object["transitions"][0]["toCohortId"]
        .as_str()
        .context("transition toCohortId")?;
    assert_eq!(cohort_id, transition_to_cohort_id);
    Ok(())
}
