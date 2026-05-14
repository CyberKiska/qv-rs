use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use qvault_core::auth::{
    resolve_open_timestamp_target, verify_qsig_against_bytes, SignatureArtifact,
};
use qvault_core::hash::sha256_hex;
use qvault_core::lifecycle::{
    parse_archive_state_descriptor_bytes, parse_cohort_binding_bytes, parse_lifecycle_bundle_bytes,
};
use qvault_core::qcont::parse_qvqcont7_shard;

fn examples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/examples")
}

#[test]
fn js_successor_single_example_smoke_parses_and_verifies() -> Result<()> {
    let root = examples_dir().join("single");
    verify_example(
        &root,
        "file_500kb.archive-state.json",
        None,
        "file_500kb.lifecycle-bundle.json",
        "file_500kb.part1-of-5.qcont",
        "MLfile_500kb.archive-state.json.qsig",
        "ML-DSA-65-bdfe1322f762688a.pqpk",
        "MLfile_500kb.archive-state.json.qsig.ots",
    )
}

#[test]
fn js_successor_bundle_example_smoke_parses_and_verifies() -> Result<()> {
    let root = examples_dir().join("bundle");
    verify_example(
        &root,
        "bundle-2026-04-25T20-47-18.qvpack.archive-state.json",
        Some("bundle-2026-04-25T20-47-18.qvpack.cohort-binding.json"),
        "bundle-2026-04-25T20-47-18.qvpack.lifecycle-bundle.json",
        "bundle-2026-04-25T20-47-18.qvpack.part1-of-6.qcont",
        "MLbundle-2026-04-25T20-47-18.qvpack.archive-state.json.qsig",
        "ML-DSA-87-fbbb144c1d4072d0.pqpk",
        "MLbundle-2026-04-25T20-47-18.qvpack.archive-state.json.qsig.ots",
    )
}

fn verify_example(
    root: &Path,
    archive_state_file: &str,
    cohort_binding_file: Option<&str>,
    lifecycle_bundle_file: &str,
    shard_file: &str,
    qsig_file: &str,
    pqpk_file: &str,
    ots_file: &str,
) -> Result<()> {
    let archive_state_bytes = fs::read(root.join(archive_state_file))?;
    let archive_state = parse_archive_state_descriptor_bytes(&archive_state_bytes)
        .with_context(|| format!("{archive_state_file}: archive-state"))?;
    let lifecycle_bundle_bytes = fs::read(root.join(lifecycle_bundle_file))?;
    let lifecycle_bundle = parse_lifecycle_bundle_bytes(&lifecycle_bundle_bytes)
        .with_context(|| format!("{lifecycle_bundle_file}: lifecycle-bundle"))?;

    if let Some(cohort_binding_file) = cohort_binding_file {
        let cohort_binding_bytes = fs::read(root.join(cohort_binding_file))?;
        let cohort_binding = parse_cohort_binding_bytes(&cohort_binding_bytes)
            .with_context(|| format!("{cohort_binding_file}: cohort-binding"))?;
        assert_eq!(
            lifecycle_bundle.digest.value,
            parse_lifecycle_bundle_bytes(&lifecycle_bundle.bytes)?
                .digest
                .value
        );
        assert_eq!(
            cohort_binding.digest.value,
            lifecycle_bundle.lifecycle_bundle.value["currentCohortBindingDigest"]["value"]
        );
    }

    let shard_bytes = fs::read(root.join(shard_file))?;
    let shard =
        parse_qvqcont7_shard(&shard_bytes).with_context(|| format!("{shard_file}: qcont"))?;
    assert_eq!(
        shard.state_id, archive_state.state_id,
        "{shard_file}: stateId"
    );
    assert_eq!(
        shard.lifecycle_bundle_digest_hex, lifecycle_bundle.digest.value,
        "{shard_file}: lifecycle-bundle digest"
    );

    let qsig_bytes = fs::read(root.join(qsig_file))?;
    let pqpk_bytes = fs::read(root.join(pqpk_file))?;
    let signature =
        verify_qsig_against_bytes(&archive_state.bytes, &qsig_bytes, None, Some(&pqpk_bytes))
            .with_context(|| format!("{qsig_file}: qsig verification"))?;
    assert!(signature.ok, "{qsig_file}: signature verifies");
    assert!(
        signature.user_pinned,
        "{qsig_file}: signature is user-pinned"
    );

    let ots_bytes = fs::read(root.join(ots_file))?;
    let linked = resolve_open_timestamp_target(
        &ots_bytes,
        Some(ots_file),
        &[SignatureArtifact {
            id: qsig_file.to_string(),
            name: qsig_file.to_string(),
            source: "example".to_string(),
            family: "archive-approval".to_string(),
            format: "qsig".to_string(),
            target_type: None,
            target_ref: None,
            signature_content_digest_hex: Some(sha256_hex(&qsig_bytes)),
            ots_stamped_digest_hex: Some(sha256_hex(&qsig_bytes)),
            bytes: qsig_bytes,
            ok: true,
        }],
    )
    .with_context(|| format!("{ots_file}: OTS linkage"))?;
    assert!(linked.linked, "{ots_file}: linked");
    Ok(())
}
