use anyhow::{anyhow, Result};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use fips204::traits::{KeyGen, SerDes, Signer};
use qvault_core::auth::AuthPolicyLevel;
use qvault_core::error::QvCode;
use qvault_core::hash::{sha3_256, sha3_512};
use qvault_core::lifecycle::{
    canonicalize_lifecycle_bundle, canonicalize_source_evidence, canonicalize_transition_record,
    derive_cohort_id, DigestObject,
};
use qvault_core::qcont::{
    build_qvqcont7_shards, parse_qvqcont7_shard, restore_qvqcont7_from_shards,
    Qvqcont7BuildOptions, Qvqcont7BuildParams, RestoreQvqcont7Options, RestoreQvqcont7Selection,
};
use qvault_core::qenc::{parse_qenc_metadata_bytes, serialize_qenc_metadata};
use qvault_core::verify_successor_lifecycle_authenticity;
use serde_json::{json, Value};

const QENC_BYTES: &[u8] = include_bytes!("data/split_v7/single-small.qenc");
const SECRET_KEY_BYTES: &[u8] = include_bytes!("data/split_v7/single-small.secret.qkey");

#[test]
fn restore_v7_reconstructs_successor_qenc_and_private_key() -> Result<()> {
    let built = build_fixture_split()?;
    let shards = parse_built_shards(&built)?;
    let restored = restore_qvqcont7_from_shards(&shards, &RestoreQvqcont7Options::default())?;

    assert_eq!(restored.qenc_bytes, QENC_BYTES);
    assert_eq!(restored.priv_key, SECRET_KEY_BYTES);
    assert_eq!(restored.archive_id, built.archive_id);
    assert_eq!(restored.state_id, built.state_id);
    assert_eq!(restored.cohort_id, built.cohort_id);
    assert_eq!(restored.archive_state_bytes, built.archive_state_bytes);
    assert_eq!(restored.cohort_binding_bytes, built.cohort_binding_bytes);
    assert_eq!(
        restored.lifecycle_bundle_bytes,
        built.lifecycle_bundle_bytes
    );
    assert!(restored.qenc_ok);
    assert!(restored.qkey_ok);
    assert!(restored.authenticity.policy.satisfied);
    Ok(())
}

#[test]
fn restore_v7_fails_closed_on_ambiguous_same_state_cohorts() -> Result<()> {
    let first = build_fixture_split()?;
    let second = build_fixture_split_preserving(&first.archive_state_bytes)?;
    assert_eq!(first.archive_id, second.archive_id);
    assert_eq!(first.state_id, second.state_id);
    assert_ne!(first.cohort_id, second.cohort_id);

    let mut shards = parse_built_shards(&first)?;
    shards.extend(parse_built_shards(&second)?);

    let error = restore_qvqcont7_from_shards(&shards, &RestoreQvqcont7Options::default())
        .expect_err("ambiguous cohorts must fail closed");
    assert_eq!(error.qv_code(), Some(QvCode::AmbiguousInputs));

    let restored = restore_qvqcont7_from_shards(
        &shards,
        &RestoreQvqcont7Options {
            selection: RestoreQvqcont7Selection {
                selected_cohort_id: Some(second.cohort_id.clone()),
                ..RestoreQvqcont7Selection::default()
            },
            ..RestoreQvqcont7Options::default()
        },
    )?;
    assert_eq!(restored.cohort_id, second.cohort_id);
    assert!(restored.same_state_fork_detected);
    assert_eq!(restored.known_same_state_cohort_ids.len(), 2);
    assert!(restored
        .warnings
        .iter()
        .any(|warning| warning.contains("Multiple cohorts were supplied")));
    Ok(())
}

#[test]
fn restore_v7_enforces_archive_policy() -> Result<()> {
    let built = build_qvqcont7_shards(
        QENC_BYTES,
        SECRET_KEY_BYTES,
        Qvqcont7BuildParams { n: 5, k: 3 },
        &Qvqcont7BuildOptions {
            auth_policy_level: Some(AuthPolicyLevel::StrongPqSignature),
            min_valid_signatures: Some(1),
            ..Qvqcont7BuildOptions::default()
        },
    )?;
    let shards = parse_built_shards(&built)?;
    let error = restore_qvqcont7_from_shards(&shards, &RestoreQvqcont7Options::default())
        .expect_err("unsigned strong-PQ archive must fail policy");
    assert_eq!(error.qv_code(), Some(QvCode::PolicyNotSatisfied));
    Ok(())
}

#[test]
fn restore_and_verify_report_all_successor_signature_families() -> Result<()> {
    let built = build_fixture_split()?;
    let signed_bundle = build_signed_lifecycle_bundle_all_families(&built)?;

    // Without an externally supplied pin the approval stays cryptographically
    // verified but must not count toward policy (oracle: bundle-carried keys
    // are not trust anchors).
    let unpinned = verify_successor_lifecycle_authenticity(
        &built.archive_state_bytes,
        &signed_bundle,
        &Default::default(),
    )?;
    assert_eq!(unpinned.verification.counts.valid_archive_approval, 0);
    assert_eq!(unpinned.verification.counts.valid_maintenance, 0);
    assert_eq!(unpinned.verification.counts.valid_source_evidence, 0);
    assert_eq!(unpinned.verification.counts.valid_total, 3);
    assert!(!unpinned.status.archive_approval_signature_verified);
    assert!(!unpinned.status.maintenance_signature_verified);
    assert!(!unpinned.status.source_evidence_signature_verified);
    assert_eq!(
        unpinned
            .transition_report
            .records
            .first()
            .expect("transition report")
            .verified_maintenance_signature_count,
        0
    );
    assert_eq!(
        unpinned
            .source_evidence_report
            .records
            .first()
            .expect("source-evidence report")
            .verified_source_evidence_signature_count,
        0
    );
    assert_eq!(
        unpinned
            .warnings
            .iter()
            .filter(|warning| warning
                .contains("ignored for trusted lifecycle reporting and policy/state counting"))
            .count(),
        3
    );

    let signer_pin = signer_pin_pqpk()?;
    let pinned_inputs = qvault_core::auth::VerificationInputs {
        pinned_pq_public_key_file_bytes_list: vec![signer_pin],
        ..Default::default()
    };
    let verified = verify_successor_lifecycle_authenticity(
        &built.archive_state_bytes,
        &signed_bundle,
        &pinned_inputs,
    )?;
    assert_eq!(verified.verification.counts.valid_archive_approval, 1);
    assert_eq!(verified.verification.counts.valid_maintenance, 1);
    assert_eq!(verified.verification.counts.valid_source_evidence, 1);
    assert!(verified.status.archive_approval_signature_verified);
    assert!(verified.status.maintenance_signature_verified);
    assert!(verified.status.source_evidence_signature_verified);
    assert!(verified.status.transition_record_present);
    assert!(verified.status.transition_chain_valid);
    assert!(verified.status.source_evidence_present);
    assert_eq!(verified.transition_report.records.len(), 1);
    assert_eq!(verified.source_evidence_report.records.len(), 1);

    let shards = parse_built_shards(&built)?;
    let restored = restore_qvqcont7_from_shards(
        &shards,
        &RestoreQvqcont7Options {
            selection: RestoreQvqcont7Selection {
                lifecycle_bundle_bytes: Some(signed_bundle),
                ..RestoreQvqcont7Selection::default()
            },
            verification: pinned_inputs,
            ..RestoreQvqcont7Options::default()
        },
    )?;
    assert_eq!(
        restored
            .authenticity
            .verification
            .counts
            .valid_archive_approval,
        1
    );
    assert_eq!(
        restored.authenticity.verification.counts.valid_maintenance,
        1
    );
    assert_eq!(
        restored
            .authenticity
            .verification
            .counts
            .valid_source_evidence,
        1
    );
    assert!(restored.authenticity.status.maintenance_signature_verified);
    assert!(
        restored
            .authenticity
            .status
            .source_evidence_signature_verified
    );
    Ok(())
}

#[test]
fn restore_v7_tolerates_one_corrupted_shard_under_rs_policy() -> Result<()> {
    let built = build_fixture_split()?;
    let mut shards = parse_built_shards(&built)?;
    shards[0].share[0] ^= 0x80;

    let restored = restore_qvqcont7_from_shards(&shards, &RestoreQvqcont7Options::default())?;
    assert_eq!(restored.qenc_bytes, QENC_BYTES);
    assert_eq!(restored.priv_key, SECRET_KEY_BYTES);
    assert_eq!(restored.rejected_shard_indices, vec![0]);
    Ok(())
}

#[test]
fn restore_v7_rejects_mismatched_bundle_bytes_and_selected_digest() -> Result<()> {
    let built = build_fixture_split()?;
    let shards = parse_built_shards(&built)?;
    let error = restore_qvqcont7_from_shards(
        &shards,
        &RestoreQvqcont7Options {
            selection: RestoreQvqcont7Selection {
                lifecycle_bundle_bytes: Some(built.lifecycle_bundle_bytes.clone()),
                selected_lifecycle_bundle_digest_hex: Some("00".repeat(64)),
                ..RestoreQvqcont7Selection::default()
            },
            ..RestoreQvqcont7Options::default()
        },
    )
    .expect_err("bundle bytes must not override a conflicting selected digest");
    assert_eq!(error.qv_code(), Some(QvCode::InvalidSelection));
    Ok(())
}

#[test]
fn restore_v7_ignores_uncommitted_allocation_geometry() -> Result<()> {
    let built = build_fixture_split()?;
    let mut shards = parse_built_shards(&built)?;
    let metadata = shards[0]
        .meta_json
        .as_object_mut()
        .expect("shard metadata object");
    metadata.insert("chunkCount".to_string(), Value::from(u64::MAX));
    metadata.insert("chunkSize".to_string(), Value::from(u64::MAX));
    metadata.insert("payloadLength".to_string(), Value::from(u64::MAX));
    metadata.insert("ciphertextLength".to_string(), Value::from(u64::MAX));
    metadata.insert("rsEncodeBase".to_string(), Value::from(u64::MAX));

    let outcome = std::panic::catch_unwind(|| {
        restore_qvqcont7_from_shards(&shards, &RestoreQvqcont7Options::default())
    });
    let restored = outcome
        .expect("uncommitted geometry must not panic or abort")
        .expect("committed geometry and valid shard bodies remain sufficient");
    assert_eq!(restored.qenc_bytes, QENC_BYTES);
    assert!(restored
        .warnings
        .iter()
        .any(|warning| warning.contains("unauthenticated redundant metadata")));
    Ok(())
}

#[test]
fn restore_v7_treats_private_key_hash_metadata_as_diagnostic() -> Result<()> {
    let built = build_fixture_split()?;
    let mut shards = parse_built_shards(&built)?;
    shards[0]
        .meta_json
        .as_object_mut()
        .expect("shard metadata object")
        .insert("privateKeyHash".to_string(), Value::String("00".repeat(64)));

    let restored = restore_qvqcont7_from_shards(&shards, &RestoreQvqcont7Options::default())?;
    assert_eq!(restored.priv_key, SECRET_KEY_BYTES);
    assert!(restored.qkey_ok, "the QENC key commitment is authoritative");
    assert!(!restored.private_key_hash_matches_metadata);
    assert!(restored
        .warnings
        .iter()
        .any(|warning| warning.contains("unauthenticated shard metadata")));
    Ok(())
}

#[test]
fn restore_v7_validates_shares_and_fragments_independently() -> Result<()> {
    let built = build_qvqcont7_shards(
        QENC_BYTES,
        SECRET_KEY_BYTES,
        Qvqcont7BuildParams { n: 6, k: 2 },
        &Qvqcont7BuildOptions {
            auth_policy_level: Some(AuthPolicyLevel::IntegrityOnly),
            min_valid_signatures: Some(1),
            ..Qvqcont7BuildOptions::default()
        },
    )?;
    let mut shards = parse_built_shards(&built)?;
    shards[0].share[0] ^= 0x80;
    shards[1].share[0] ^= 0x80;
    shards[2].fragments[4] ^= 0x80;
    shards[3].fragments[4] ^= 0x80;

    let restored = restore_qvqcont7_from_shards(&shards, &RestoreQvqcont7Options::default())?;
    assert_eq!(restored.qenc_bytes, QENC_BYTES);
    assert_eq!(restored.priv_key, SECRET_KEY_BYTES);
    assert_eq!(restored.invalid_share_indices, vec![0, 1]);
    assert_eq!(restored.corrupted_shard_indices, vec![2, 3]);
    assert!(restored.missing_shard_indices.is_empty());
    Ok(())
}

#[test]
fn restore_v7_rejects_unregistered_qenc_domain_strings() -> Result<()> {
    let built = build_fixture_split()?;
    let mut shards = parse_built_shards(&built)?;
    let mut metadata = parse_qenc_metadata_bytes(&shards[0].qenc_meta_bytes)?;
    metadata.domain_strings.kdf = "quantum-vault:kdf:unregistered".to_string();
    let mutated_metadata = serialize_qenc_metadata(&metadata)?;
    for shard in &mut shards {
        shard.qenc_meta_bytes.clone_from(&mutated_metadata);
    }

    let error = restore_qvqcont7_from_shards(&shards, &RestoreQvqcont7Options::default())
        .expect_err("restore must enforce the registered crypto profile domains");
    assert_eq!(error.qv_code(), Some(QvCode::InvalidFormat));
    assert!(error.to_string().contains("domainStrings"), "{error}");
    Ok(())
}

#[test]
fn split_v7_rejects_rs_codewords_above_255_before_secret_work() {
    let error = build_qvqcont7_shards(
        QENC_BYTES,
        SECRET_KEY_BYTES,
        Qvqcont7BuildParams { n: 256, k: 2 },
        &Qvqcont7BuildOptions::default(),
    )
    .expect_err("QV-RS-ErasureCodes-v1 has an n <= 255 bound");
    assert!(error.to_string().contains("must not exceed 255"), "{error}");
}

fn build_signed_lifecycle_bundle_all_families(
    built: &qvault_core::qcont::BuiltQvqcont7Shards,
) -> Result<Vec<u8>> {
    let mut bundle = built.lifecycle_bundle.value.clone();
    let predecessor_digest = DigestObject {
        alg: "SHA3-512".to_string(),
        value: "23".repeat(64),
    };
    let predecessor_cohort_id =
        derive_cohort_id(&built.archive_id, &built.state_id, &predecessor_digest)?;
    let transition = json!({
        "schema": "quantum-vault-transition-record/v1",
        "version": 1,
        "canonicalization": "QV-JSON-RFC8785-v1",
        "transitionType": "same-state-resharing",
        "archiveId": built.archive_id,
        "fromStateId": built.state_id,
        "toStateId": built.state_id,
        "fromCohortId": predecessor_cohort_id,
        "toCohortId": built.cohort_id,
        "fromCohortBindingDigest": predecessor_digest,
        "toCohortBindingDigest": {
            "alg": "SHA3-512",
            "value": built.cohort_binding_digest_hex,
        },
        "reasonCode": "cohort-rotation",
        "performedAt": "2026-03-25T12:34:56.000Z",
        "operatorRole": "operator",
        "actorHints": {
            "maintenanceSignaturePurpose": "operator-attestation"
        },
        "notes": null,
    });
    let source_evidence = json!({
        "schema": "quantum-vault-source-evidence/v1",
        "version": 1,
        "sourceEvidenceType": "source-evidence",
        "canonicalization": "QV-JSON-RFC8785-v1",
        "relationType": "reviewed-source",
        "sourceObjectType": "archive-state-descriptor",
        "sourceDigests": [
            { "alg": "SHA3-512", "value": "45".repeat(64) },
            { "alg": "SHA-256", "value": "67".repeat(32) }
        ],
        "externalSourceSignatureRefs": ["sig:external-restore-phase3"]
    });
    let canonical_transition = canonicalize_transition_record(&transition)?;
    let canonical_source_evidence = canonicalize_source_evidence(&source_evidence)?;

    let archive_sig = build_qsig_fixture(&built.archive_state_bytes)?;
    let maintenance_sig = build_qsig_fixture(&canonical_transition.bytes)?;
    let source_sig = build_qsig_fixture(&canonical_source_evidence.bytes)?;
    set_object_field(
        &mut bundle,
        "sourceEvidence",
        Value::Array(vec![canonical_source_evidence.source_evidence.value]),
    );
    set_object_field(
        &mut bundle,
        "transitions",
        Value::Array(vec![canonical_transition.transition_record.value]),
    );
    set_object_field(
        &mut bundle,
        "attachments",
        json!({
            "publicKeys": [
                public_key_entry("pk-archive", &archive_sig.public_key),
                public_key_entry("pk-maintenance", &maintenance_sig.public_key),
                public_key_entry("pk-source-evidence", &source_sig.public_key)
            ],
            "archiveApprovalSignatures": [
                qsig_entry(
                    "archive-approval-sig-1",
                    "archive-approval",
                    "archive-state",
                    &format!("state:{}", built.state_id),
                    &built.state_id,
                    &archive_sig.qsig,
                    "pk-archive"
                )
            ],
            "maintenanceSignatures": [
                qsig_entry(
                    "maintenance-sig-1",
                    "maintenance",
                    "transition-record",
                    &format!("transition:sha3-512:{}", canonical_transition.digest.value),
                    &canonical_transition.digest.value,
                    &maintenance_sig.qsig,
                    "pk-maintenance"
                )
            ],
            "sourceEvidenceSignatures": [
                qsig_entry(
                    "source-evidence-sig-1",
                    "source-evidence",
                    "source-evidence",
                    &format!("source-evidence:sha3-512:{}", canonical_source_evidence.digest.value),
                    &canonical_source_evidence.digest.value,
                    &source_sig.qsig,
                    "pk-source-evidence"
                )
            ],
            "timestamps": []
        }),
    );
    Ok(canonicalize_lifecycle_bundle(&bundle)?.bytes)
}

struct QsigFixture {
    qsig: Vec<u8>,
    public_key: Vec<u8>,
}

fn signer_pin_pqpk() -> Result<Vec<u8>> {
    let (public_key, _) = fips204::ml_dsa_87::KG::keygen_from_seed(&[0x87; 32]);
    qvault_core::auth::pack_public_key_file(
        qvault_core::auth::PqSignatureSuite::MlDsa87,
        &public_key.into_bytes(),
    )
    .map_err(|error| anyhow!(error))
}

fn build_qsig_fixture(message: &[u8]) -> Result<QsigFixture> {
    let (public_key, private_key) = fips204::ml_dsa_87::KG::keygen_from_seed(&[0x87; 32]);
    let public_key = public_key.into_bytes().to_vec();
    let file_hash = sha3_512(message);
    let fingerprint = sha3_256(&public_key);
    let mut auth_meta = Vec::new();
    auth_meta.push(0x10);
    auth_meta.extend_from_slice(&(public_key.len() as u16).to_le_bytes());
    auth_meta.extend_from_slice(&public_key);
    auth_meta.push(0x11);
    auth_meta.extend_from_slice(&33u16.to_le_bytes());
    auth_meta.push(0x01);
    auth_meta.extend_from_slice(&fingerprint);
    let auth_meta_digest = sha3_256(&auth_meta);
    let display_name = b"archive.qvmanifest.json";
    let mut display_meta = Vec::new();
    display_meta.push(0x01);
    display_meta.extend_from_slice(&(display_name.len() as u16).to_le_bytes());
    display_meta.extend_from_slice(display_name);
    display_meta.push(0x02);
    display_meta.extend_from_slice(&8u16.to_le_bytes());
    display_meta.extend_from_slice(&(message.len() as u32).to_le_bytes());
    display_meta.extend_from_slice(&0u32.to_le_bytes());

    let mut tbs = Vec::new();
    tbs.extend_from_slice(b"QSTB");
    tbs.extend_from_slice(&[0x02, 0x00, 0x02, 0x00, 0x03, 0x01, 0x01, 0x01]);
    tbs.extend_from_slice(&file_hash);
    tbs.extend_from_slice(&auth_meta_digest);
    let signature = private_key
        .try_sign_with_seed(&[0x5a; 32], &tbs, b"quantum-signer/v2")
        .map_err(|error| anyhow!(error))?;

    let mut qsig = Vec::new();
    qsig.extend_from_slice(b"PQSG");
    qsig.extend_from_slice(&[0x02, 0x00, 0x03, 0x01, 0x01, 0x01]);
    qsig.extend_from_slice(&0x0007u16.to_le_bytes());
    qsig.extend_from_slice(&file_hash);
    qsig.extend_from_slice(&auth_meta_digest);
    qsig.push(b"quantum-signer/v2".len() as u8);
    qsig.push(0);
    qsig.extend_from_slice(&(auth_meta.len() as u16).to_le_bytes());
    qsig.extend_from_slice(&(display_meta.len() as u16).to_le_bytes());
    qsig.extend_from_slice(&(signature.len() as u32).to_le_bytes());
    qsig.extend_from_slice(b"quantum-signer/v2");
    qsig.extend_from_slice(&auth_meta);
    qsig.extend_from_slice(&display_meta);
    qsig.extend_from_slice(&signature);
    Ok(QsigFixture { qsig, public_key })
}

fn public_key_entry(id: &str, public_key: &[u8]) -> Value {
    json!({
        "id": id,
        "kty": "ml-dsa-public-key",
        "suite": "mldsa-87",
        "encoding": "base64",
        "value": BASE64_STANDARD.encode(public_key),
    })
}

fn qsig_entry(
    id: &str,
    family: &str,
    target_type: &str,
    target_ref: &str,
    target_digest: &str,
    qsig: &[u8],
    public_key_ref: &str,
) -> Value {
    json!({
        "id": id,
        "signatureFamily": family,
        "format": "qsig",
        "suite": "mldsa-87",
        "targetType": target_type,
        "targetRef": target_ref,
        "targetDigest": { "alg": "SHA3-512", "value": target_digest },
        "signatureEncoding": "base64",
        "signature": BASE64_STANDARD.encode(qsig),
        "publicKeyRef": public_key_ref,
    })
}

fn set_object_field(value: &mut Value, key: &str, replacement: Value) {
    value
        .as_object_mut()
        .expect("test lifecycle bundle object")
        .insert(key.to_string(), replacement);
}

fn build_fixture_split() -> Result<qvault_core::qcont::BuiltQvqcont7Shards> {
    build_qvqcont7_shards(
        QENC_BYTES,
        SECRET_KEY_BYTES,
        Qvqcont7BuildParams { n: 5, k: 3 },
        &Qvqcont7BuildOptions {
            auth_policy_level: Some(AuthPolicyLevel::IntegrityOnly),
            min_valid_signatures: Some(1),
            ..Qvqcont7BuildOptions::default()
        },
    )
    .map_err(Into::into)
}

fn build_fixture_split_preserving(
    archive_state_bytes: &[u8],
) -> Result<qvault_core::qcont::BuiltQvqcont7Shards> {
    #[cfg(feature = "deterministic-test-vectors")]
    let options = Qvqcont7BuildOptions {
        preserved_archive_state_bytes: Some(archive_state_bytes.to_vec()),
        auth_policy_level: Some(AuthPolicyLevel::IntegrityOnly),
        min_valid_signatures: Some(1),
        ..Qvqcont7BuildOptions::default()
    };
    #[cfg(not(feature = "deterministic-test-vectors"))]
    let options = Qvqcont7BuildOptions {
        preserved_archive_state_bytes: Some(archive_state_bytes.to_vec()),
        auth_policy_level: Some(AuthPolicyLevel::IntegrityOnly),
        min_valid_signatures: Some(1),
    };
    build_qvqcont7_shards(
        QENC_BYTES,
        SECRET_KEY_BYTES,
        Qvqcont7BuildParams { n: 5, k: 3 },
        &options,
    )
    .map_err(Into::into)
}

fn parse_built_shards(
    built: &qvault_core::qcont::BuiltQvqcont7Shards,
) -> Result<Vec<qvault_core::qcont::Qvqcont7Shard>> {
    built
        .shards
        .iter()
        .map(|shard| parse_qvqcont7_shard(&shard.bytes).map_err(Into::into))
        .collect()
}
