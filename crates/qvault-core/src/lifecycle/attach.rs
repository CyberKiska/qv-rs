use std::collections::{BTreeMap, HashMap, HashSet};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use serde_json::Value;

use crate::auth::{
    classify_detached_archive_approval_bytes, resolve_open_timestamp_target, unpack_pqpk,
    verify_qsig_against_bytes, verify_stellar_sig_against_bytes, DetachedArchiveApprovalKind,
    NamedBinaryArtifact, ParsedPqpk, SignatureArtifact,
};
use crate::error::{coded, err, QvCode, Result};
use crate::hash::{sha256_hex, sha3_512_hex};
use crate::lifecycle::{
    canonicalize_archive_state_descriptor, canonicalize_cohort_binding,
    canonicalize_lifecycle_bundle, canonicalize_source_evidence, canonicalize_transition_record,
    parse_archive_state_descriptor_bytes, parse_lifecycle_bundle_bytes,
    parse_source_evidence_bytes, CanonicalLifecycleBundle, CanonicalTransitionRecord,
};
use crate::manifest::jcs::canonicalize_json;
use crate::manifest::strict_json::parse_json_bytes_strict;
use crate::qcont::shard_v7::Qvqcont7Shard;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleSignatureFamily {
    ArchiveApproval,
    Maintenance,
    SourceEvidence,
}

impl LifecycleSignatureFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ArchiveApproval => "archive-approval",
            Self::Maintenance => "maintenance",
            Self::SourceEvidence => "source-evidence",
        }
    }

    pub fn attachment_field(self) -> &'static str {
        match self {
            Self::ArchiveApproval => "archiveApprovalSignatures",
            Self::Maintenance => "maintenanceSignatures",
            Self::SourceEvidence => "sourceEvidenceSignatures",
        }
    }

    pub fn target_type(self) -> &'static str {
        match self {
            Self::ArchiveApproval => "archive-state",
            Self::Maintenance => "transition-record",
            Self::SourceEvidence => "source-evidence",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleSignatureImport {
    pub name: String,
    pub bytes: Vec<u8>,
    pub signature_family: LifecycleSignatureFamily,
    pub target_type: Option<String>,
    pub target_ref: Option<String>,
    pub target_digest_hex: Option<String>,
    pub source_evidence_bytes: Option<Vec<u8>>,
    pub source_evidence_value: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleSourceEvidenceImport {
    pub bytes: Option<Vec<u8>>,
    pub value: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachLifecycleOptions {
    pub archive_state_bytes: Option<Vec<u8>>,
    pub lifecycle_bundle_bytes: Option<Vec<u8>>,
    pub signatures: Vec<NamedBinaryArtifact>,
    pub signature_imports: Vec<LifecycleSignatureImport>,
    pub source_evidence: Vec<LifecycleSourceEvidenceImport>,
    pub pq_public_key_file_bytes_list: Vec<Vec<u8>>,
    pub timestamps: Vec<NamedBinaryArtifact>,
    pub expected_ed25519_signer: Option<String>,
    pub embed_into_shards: bool,
}

impl Default for AttachLifecycleOptions {
    fn default() -> Self {
        Self {
            archive_state_bytes: None,
            lifecycle_bundle_bytes: None,
            signatures: Vec::new(),
            signature_imports: Vec::new(),
            source_evidence: Vec::new(),
            pq_public_key_file_bytes_list: Vec::new(),
            timestamps: Vec::new(),
            expected_ed25519_signer: None,
            embed_into_shards: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachedLifecycleShard {
    pub index: u16,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachedLifecycleBundle {
    pub shards: Vec<AttachedLifecycleShard>,
    pub archive_state: Value,
    pub archive_state_bytes: Vec<u8>,
    pub archive_state_digest_hex: String,
    pub state_id: String,
    pub cohort_binding: Value,
    pub cohort_binding_bytes: Vec<u8>,
    pub cohort_binding_digest_hex: String,
    pub lifecycle_bundle: Value,
    pub lifecycle_bundle_bytes: Vec<u8>,
    pub lifecycle_bundle_digest_hex: String,
    pub embedded_lifecycle_bundle_digests: Vec<String>,
    pub mixed_embedded_lifecycle_bundle_digests: bool,
}

fn signature_import_failed(message: impl Into<String>) -> crate::error::QvError {
    coded(QvCode::SignatureImportFailed, message)
}

struct AttachContext<'a> {
    shards: Vec<&'a Qvqcont7Shard>,
    archive_state_bytes: Vec<u8>,
    archive_state_digest_hex: String,
    state_id: String,
    cohort_binding_bytes: Vec<u8>,
    lifecycle_bundle: Value,
    embedded_lifecycle_bundle_digests: Vec<String>,
}

struct PqPin {
    bytes: Vec<u8>,
    parsed: ParsedPqpk,
}

struct ResolvedSourceEvidence {
    value: Value,
    bytes: Vec<u8>,
    digest_hex: String,
    target_ref: String,
}

struct ResolvedTarget {
    target_type: String,
    target_ref: String,
    digest_hex: String,
    bytes: Vec<u8>,
}

struct ImportedSignature {
    public_keys: Vec<Value>,
    signature: Value,
}

pub fn attach_lifecycle_bundle(
    shards: &[Qvqcont7Shard],
    options: &AttachLifecycleOptions,
) -> Result<AttachedLifecycleBundle> {
    let context = resolve_attach_context(shards, options)?;
    let pins = normalize_pq_pins(&options.pq_public_key_file_bytes_list)?;
    let expected_ed25519 = options
        .expected_ed25519_signer
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    let mut imported_public_keys = Vec::new();
    let mut imported_signatures = BTreeMap::<&'static str, Vec<Value>>::from([
        ("archiveApprovalSignatures", Vec::new()),
        ("maintenanceSignatures", Vec::new()),
        ("sourceEvidenceSignatures", Vec::new()),
    ]);
    let mut imported_source_evidence = Vec::<Value>::new();
    for (index, source_evidence) in options.source_evidence.iter().enumerate() {
        let source = resolve_source_evidence_import(
            source_evidence.bytes.as_deref(),
            source_evidence.value.as_ref(),
            &format!("source-evidence import {}", index + 1),
        )?;
        imported_source_evidence =
            merge_source_evidence_entries(&imported_source_evidence, &[source.value])?;
    }

    let mut imports = options
        .signatures
        .iter()
        .map(|signature| LifecycleSignatureImport {
            name: import_label(&signature.name, "signature import"),
            bytes: signature.bytes.clone(),
            signature_family: LifecycleSignatureFamily::ArchiveApproval,
            target_type: None,
            target_ref: None,
            target_digest_hex: None,
            source_evidence_bytes: None,
            source_evidence_value: None,
        })
        .collect::<Vec<_>>();
    imports.extend(options.signature_imports.iter().cloned());

    for import in &imports {
        if import.bytes.is_empty() {
            return Err(signature_import_failed(format!(
                "Invalid signature file: {}",
                import_label(&import.name, "signature import")
            )));
        }
        let label = import_label(&import.name, "signature import");
        let target = resolve_import_target(&context, import, &imported_source_evidence, &label)
            .map_err(|error| signature_import_failed(error.to_string()))?;
        if import.signature_family == LifecycleSignatureFamily::SourceEvidence {
            let source = resolve_source_evidence(import, &label)
                .map_err(|error| signature_import_failed(error.to_string()))?;
            imported_source_evidence =
                merge_source_evidence_entries(&imported_source_evidence, &[source.value])?;
        }
        let imported = import_external_lifecycle_signature(
            import.signature_family,
            &target,
            &label,
            &import.bytes,
            &pins,
            expected_ed25519,
        )
        .map_err(|error| signature_import_failed(error.to_string()))?;
        imported_public_keys.extend(imported.public_keys);
        imported_signatures
            .get_mut(import.signature_family.attachment_field())
            .ok_or_else(|| err("Internal lifecycle signature family map is missing"))?
            .push(imported.signature);
    }

    let mut merged_bundle = context.lifecycle_bundle.clone();
    let source_evidence = merge_source_evidence_entries(
        array_field(
            &merged_bundle,
            "sourceEvidence",
            "lifecycleBundle.sourceEvidence",
        )?,
        &imported_source_evidence,
    )?;
    let mut attachments =
        object_field(&merged_bundle, "attachments", "lifecycleBundle.attachments")?.clone();
    let public_keys = merge_entries_by_id(
        array_field(
            &attachments,
            "publicKeys",
            "lifecycleBundle.attachments.publicKeys",
        )?,
        &imported_public_keys,
    )?;
    set_object_field(&mut attachments, "publicKeys", Value::Array(public_keys))?;
    for family in [
        LifecycleSignatureFamily::ArchiveApproval,
        LifecycleSignatureFamily::Maintenance,
        LifecycleSignatureFamily::SourceEvidence,
    ] {
        let field = family.attachment_field();
        let merged = merge_entries_by_id(
            array_field(
                &attachments,
                field,
                &format!("lifecycleBundle.attachments.{field}"),
            )?,
            imported_signatures
                .get(field)
                .ok_or_else(|| err("Internal lifecycle signature field map is missing"))?,
        )?;
        set_object_field(&mut attachments, field, Value::Array(merged))?;
    }
    set_object_field(
        &mut merged_bundle,
        "sourceEvidence",
        Value::Array(source_evidence),
    )?;
    set_object_field(&mut merged_bundle, "attachments", attachments)?;

    if !options.timestamps.is_empty() {
        let signatures = build_signature_artifacts(&merged_bundle)?;
        let mut timestamps = Vec::new();
        for timestamp in &options.timestamps {
            if timestamp.bytes.is_empty() {
                return Err(err(format!(
                    "Invalid timestamp file: {}",
                    import_label(&timestamp.name, "timestamp")
                )));
            }
            let name = import_label(&timestamp.name, "timestamp");
            let resolved =
                resolve_open_timestamp_target(&timestamp.bytes, Some(&name), &signatures)?;
            timestamps.push(serde_json::json!({
                "id": attachment_id("ots", &timestamp.bytes),
                "type": "opentimestamps",
                "targetRef": resolved.target_ref,
                "targetDigest": {
                    "alg": "SHA-256",
                    "value": resolved.stamped_digest_hex,
                },
                "proofEncoding": "base64",
                "proof": BASE64_STANDARD.encode(&timestamp.bytes),
            }));
        }
        let mut attachments =
            object_field(&merged_bundle, "attachments", "lifecycleBundle.attachments")?.clone();
        let merged_timestamps = merge_entries_by_id(
            array_field(
                &attachments,
                "timestamps",
                "lifecycleBundle.attachments.timestamps",
            )?,
            &timestamps,
        )?;
        set_object_field(
            &mut attachments,
            "timestamps",
            Value::Array(merged_timestamps),
        )?;
        set_object_field(&mut merged_bundle, "attachments", attachments)?;
    }

    let canonical_bundle = canonicalize_lifecycle_bundle(&merged_bundle)?;
    ensure_attach_preserved_identity(&context, &canonical_bundle)?;

    let shards_out = if options.embed_into_shards {
        context
            .shards
            .iter()
            .map(|shard| rewrite_lifecycle_bundle_in_shard(shard, &canonical_bundle.bytes))
            .collect::<Result<Vec<_>>>()?
    } else {
        Vec::new()
    };
    let canonical_cohort = canonicalize_cohort_binding(
        &canonical_bundle.lifecycle_bundle.value["currentCohortBinding"],
    )?;

    Ok(AttachedLifecycleBundle {
        shards: shards_out,
        archive_state: canonical_bundle.lifecycle_bundle.value["archiveState"].clone(),
        archive_state_bytes: context.archive_state_bytes,
        archive_state_digest_hex: context.archive_state_digest_hex,
        state_id: context.state_id,
        cohort_binding: canonical_bundle.lifecycle_bundle.value["currentCohortBinding"].clone(),
        cohort_binding_bytes: context.cohort_binding_bytes,
        cohort_binding_digest_hex: canonical_cohort.digest.value,
        lifecycle_bundle: canonical_bundle.lifecycle_bundle.value,
        lifecycle_bundle_bytes: canonical_bundle.bytes,
        lifecycle_bundle_digest_hex: canonical_bundle.digest.value,
        mixed_embedded_lifecycle_bundle_digests: context.embedded_lifecycle_bundle_digests.len()
            > 1,
        embedded_lifecycle_bundle_digests: context.embedded_lifecycle_bundle_digests,
    })
}

fn resolve_attach_context<'a>(
    shards: &'a [Qvqcont7Shard],
    options: &AttachLifecycleOptions,
) -> Result<AttachContext<'a>> {
    if !shards.is_empty() {
        let cohort = ensure_single_lifecycle_cohort(shards)?;
        let embedded_archive_state =
            parse_archive_state_descriptor_bytes(&cohort.archive_state_bytes)?;
        if let Some(bytes) = options.archive_state_bytes.as_deref() {
            let explicit = parse_archive_state_descriptor_bytes(bytes)?;
            if explicit.bytes != embedded_archive_state.bytes {
                return Err(err(
                    "Provided archive-state descriptor does not match the selected successor shard set",
                ));
            }
        }

        let canonical_cohort =
            canonicalize_cohort_binding(&cohort.shards[0].cohort_binding.cohort_binding.value)?;
        let selected_bundle = if let Some(bundle_bytes) = options.lifecycle_bundle_bytes.as_deref()
        {
            let parsed = parse_lifecycle_bundle_bytes(bundle_bytes)?;
            assert_bundle_matches_context(
                &parsed,
                &embedded_archive_state.bytes,
                &canonical_cohort.bytes,
                &embedded_archive_state.digest.value,
                &canonical_cohort.digest.value,
            )?;
            parsed
        } else if cohort.lifecycle_bundle_variants.len() == 1 {
            let bytes = cohort
                .lifecycle_bundle_variants
                .values()
                .next()
                .ok_or_else(|| {
                    err("Selected successor shards contain no lifecycle-bundle bytes")
                })?;
            parse_lifecycle_bundle_bytes(bytes)?
        } else {
            return Err(err(
                "Selected successor shards contain multiple embedded lifecycle-bundle digests. Provide explicit lifecycle-bundle bytes to choose one fail closed.",
            ));
        };

        return Ok(AttachContext {
            shards: cohort.shards,
            archive_state_bytes: embedded_archive_state.bytes,
            archive_state_digest_hex: embedded_archive_state.digest.value,
            state_id: embedded_archive_state.state_id,
            cohort_binding_bytes: canonical_cohort.bytes,
            lifecycle_bundle: selected_bundle.lifecycle_bundle.value,
            embedded_lifecycle_bundle_digests: cohort
                .lifecycle_bundle_variants
                .keys()
                .cloned()
                .collect(),
        });
    }

    if let Some(bundle_bytes) = options.lifecycle_bundle_bytes.as_deref() {
        let parsed = parse_lifecycle_bundle_bytes(bundle_bytes)?;
        let archive_state =
            canonicalize_archive_state_descriptor(&parsed.lifecycle_bundle.value["archiveState"])?;
        if let Some(bytes) = options.archive_state_bytes.as_deref() {
            let explicit = parse_archive_state_descriptor_bytes(bytes)?;
            if explicit.bytes != archive_state.bytes {
                return Err(err(
                    "Provided archive-state descriptor does not match the provided lifecycle bundle",
                ));
            }
        }
        let cohort_binding =
            canonicalize_cohort_binding(&parsed.lifecycle_bundle.value["currentCohortBinding"])?;
        return Ok(AttachContext {
            shards: Vec::new(),
            archive_state_bytes: archive_state.bytes,
            archive_state_digest_hex: archive_state.digest.value,
            state_id: archive_state.state_id,
            cohort_binding_bytes: cohort_binding.bytes,
            lifecycle_bundle: parsed.lifecycle_bundle.value,
            embedded_lifecycle_bundle_digests: vec![parsed.digest.value],
        });
    }

    Err(err(
        "No successor lifecycle shards or lifecycle bundle were provided for attach.",
    ))
}

struct CohortSelection<'a> {
    archive_state_bytes: Vec<u8>,
    lifecycle_bundle_variants: BTreeMap<String, Vec<u8>>,
    shards: Vec<&'a Qvqcont7Shard>,
}

fn ensure_single_lifecycle_cohort(shards: &[Qvqcont7Shard]) -> Result<CohortSelection<'_>> {
    let mut key: Option<String> = None;
    let mut archive_state_bytes: Option<Vec<u8>> = None;
    let mut cohort_binding_bytes: Option<Vec<u8>> = None;
    let mut variants = BTreeMap::new();
    let mut selected = Vec::new();
    for shard in shards {
        let shard_key = format!(
            "{}:{}:{}",
            shard.meta_json["archiveId"].as_str().unwrap_or_default(),
            shard.meta_json["stateId"].as_str().unwrap_or_default(),
            shard.meta_json["cohortId"].as_str().unwrap_or_default()
        );
        if let Some(existing) = &key {
            if existing != &shard_key {
                return Err(err(
                    "Attach requires successor shards from exactly one archive/state/cohort set.",
                ));
            }
        } else {
            key = Some(shard_key);
            archive_state_bytes = Some(shard.archive_state_bytes.clone());
            cohort_binding_bytes = Some(shard.cohort_binding_bytes.clone());
        }
        if archive_state_bytes.as_deref() != Some(shard.archive_state_bytes.as_slice()) {
            return Err(err(
                "Selected successor shards do not agree on embedded archive-state bytes",
            ));
        }
        if cohort_binding_bytes.as_deref() != Some(shard.cohort_binding_bytes.as_slice()) {
            return Err(err(
                "Selected successor shards do not agree on embedded cohort-binding bytes",
            ));
        }
        match variants.get(&shard.lifecycle_bundle_digest_hex) {
            Some(bytes) if bytes != &shard.lifecycle_bundle_bytes => {
                return Err(err(
                    "Selected successor shards do not agree on lifecycle-bundle bytes for one embedded digest",
                ))
            }
            Some(_) => {}
            None => {
                variants.insert(
                    shard.lifecycle_bundle_digest_hex.clone(),
                    shard.lifecycle_bundle_bytes.clone(),
                );
            }
        }
        selected.push(shard);
    }
    Ok(CohortSelection {
        archive_state_bytes: archive_state_bytes.unwrap_or_default(),
        lifecycle_bundle_variants: variants,
        shards: selected,
    })
}

fn assert_bundle_matches_context(
    bundle: &CanonicalLifecycleBundle,
    archive_state_bytes: &[u8],
    cohort_binding_bytes: &[u8],
    archive_state_digest_hex: &str,
    cohort_binding_digest_hex: &str,
) -> Result<()> {
    let archive_digest = bundle.lifecycle_bundle.value["archiveStateDigest"]["value"]
        .as_str()
        .unwrap_or_default();
    if archive_digest != archive_state_digest_hex {
        return Err(err(
            "Provided lifecycle bundle does not match the selected archive-state digest",
        ));
    }
    let cohort_digest = bundle.lifecycle_bundle.value["currentCohortBindingDigest"]["value"]
        .as_str()
        .unwrap_or_default();
    if cohort_digest != cohort_binding_digest_hex {
        return Err(err(
            "Provided lifecycle bundle does not match the selected cohort-binding digest",
        ));
    }
    let bundle_archive =
        canonicalize_archive_state_descriptor(&bundle.lifecycle_bundle.value["archiveState"])?;
    if bundle_archive.bytes != archive_state_bytes {
        return Err(err(
            "Provided lifecycle bundle does not match the selected archive-state bytes",
        ));
    }
    let bundle_cohort =
        canonicalize_cohort_binding(&bundle.lifecycle_bundle.value["currentCohortBinding"])?;
    if bundle_cohort.bytes != cohort_binding_bytes {
        return Err(err(
            "Provided lifecycle bundle does not match the selected cohort-binding bytes",
        ));
    }
    Ok(())
}

fn normalize_pq_pins(bytes_list: &[Vec<u8>]) -> Result<Vec<PqPin>> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for bytes in bytes_list {
        let parsed = unpack_pqpk(bytes)?;
        let key = format!("{}:{}", parsed.suite_id, hex::encode(&parsed.key_bytes));
        if seen.insert(key) {
            out.push(PqPin {
                bytes: bytes.clone(),
                parsed,
            });
        }
    }
    Ok(out)
}

fn resolve_import_target(
    context: &AttachContext<'_>,
    import: &LifecycleSignatureImport,
    imported_source_evidence: &[Value],
    label: &str,
) -> Result<ResolvedTarget> {
    let default = match import.signature_family {
        LifecycleSignatureFamily::ArchiveApproval => Some(ResolvedTarget {
            target_type: "archive-state".to_string(),
            target_ref: format!("state:{}", context.state_id),
            digest_hex: context.archive_state_digest_hex.clone(),
            bytes: context.archive_state_bytes.clone(),
        }),
        LifecycleSignatureFamily::Maintenance => None,
        LifecycleSignatureFamily::SourceEvidence => {
            let source = resolve_source_evidence(import, label)?;
            Some(ResolvedTarget {
                target_type: "source-evidence".to_string(),
                target_ref: source.target_ref,
                digest_hex: source.digest_hex,
                bytes: source.bytes,
            })
        }
    };
    let target_type = import
        .target_type
        .as_deref()
        .unwrap_or(import.signature_family.target_type());
    if target_type != import.signature_family.target_type() {
        return Err(err(format!(
            "{label}: wrong targetType for {} import; expected {}, got {target_type}",
            import.signature_family.as_str(),
            import.signature_family.target_type()
        )));
    }
    if import.signature_family == LifecycleSignatureFamily::Maintenance
        && import.target_ref.as_deref().unwrap_or_default().is_empty()
    {
        return Err(err(format!(
            "{label}: maintenance imports require explicit targetRef; refusing to route by guess"
        )));
    }
    let target_ref = import
        .target_ref
        .clone()
        .or_else(|| default.as_ref().map(|target| target.target_ref.clone()))
        .ok_or_else(|| err(format!("{label}: missing targetRef")))?;
    let ref_digest = digest_from_target_ref(import.signature_family, &target_ref, label)?;
    if let Some(declared) = &import.target_digest_hex {
        if declared != &ref_digest {
            return Err(err(format!(
                "{label}: targetDigest does not match targetRef"
            )));
        }
    }
    if let Some(default) = &default {
        if default.digest_hex != ref_digest {
            return Err(err(format!(
                "{label}: targetRef does not match the selected {} target",
                import.signature_family.as_str()
            )));
        }
        return Ok(default.clone_with_ref(target_ref, ref_digest));
    }
    resolve_existing_target(
        context,
        imported_source_evidence,
        import.signature_family,
        &target_ref,
        &ref_digest,
    )
    .map_err(|error| err(format!("{label}: {error}")))
}

impl ResolvedTarget {
    fn clone_with_ref(&self, target_ref: String, digest_hex: String) -> Self {
        Self {
            target_type: self.target_type.clone(),
            target_ref,
            digest_hex,
            bytes: self.bytes.clone(),
        }
    }
}

fn resolve_existing_target(
    context: &AttachContext<'_>,
    imported_source_evidence: &[Value],
    family: LifecycleSignatureFamily,
    target_ref: &str,
    digest_hex: &str,
) -> Result<ResolvedTarget> {
    match family {
        LifecycleSignatureFamily::Maintenance => {
            let transitions = array_field(
                &context.lifecycle_bundle,
                "transitions",
                "lifecycleBundle.transitions",
            )?;
            for transition in transitions {
                let canonical = canonicalize_transition_record(transition)?;
                if canonical.digest.value == digest_hex {
                    return Ok(ResolvedTarget {
                        target_type: "transition-record".to_string(),
                        target_ref: target_ref.to_string(),
                        digest_hex: digest_hex.to_string(),
                        bytes: canonical.bytes,
                    });
                }
            }
            Err(err("maintenance targetDigest mismatch"))
        }
        LifecycleSignatureFamily::SourceEvidence => {
            let mut values = array_field(
                &context.lifecycle_bundle,
                "sourceEvidence",
                "lifecycleBundle.sourceEvidence",
            )?
            .clone();
            values.extend(imported_source_evidence.iter().cloned());
            for evidence in values {
                let canonical = canonicalize_source_evidence(&evidence)?;
                if canonical.digest.value == digest_hex {
                    return Ok(ResolvedTarget {
                        target_type: "source-evidence".to_string(),
                        target_ref: target_ref.to_string(),
                        digest_hex: digest_hex.to_string(),
                        bytes: canonical.bytes,
                    });
                }
            }
            Err(err("source-evidence targetDigest mismatch"))
        }
        LifecycleSignatureFamily::ArchiveApproval => unreachable!(),
    }
}

fn resolve_source_evidence(
    import: &LifecycleSignatureImport,
    label: &str,
) -> Result<ResolvedSourceEvidence> {
    match (
        import.source_evidence_bytes.as_deref(),
        import.source_evidence_value.as_ref(),
    ) {
        (Some(_), Some(_)) => Err(err(format!(
            "{label}: provide either sourceEvidenceBytes or sourceEvidence, not both"
        ))),
        (Some(bytes), None) => resolve_source_evidence_import(Some(bytes), None, label),
        (None, Some(value)) => resolve_source_evidence_import(None, Some(value), label),
        (None, None) => Err(err(format!(
            "{label}: source-evidence import requires sourceEvidenceBytes or sourceEvidence"
        ))),
    }
}

fn resolve_source_evidence_import(
    bytes: Option<&[u8]>,
    value: Option<&Value>,
    label: &str,
) -> Result<ResolvedSourceEvidence> {
    match (bytes, value) {
        (Some(_), Some(_)) => Err(err(format!(
            "{label}: provide either sourceEvidenceBytes or sourceEvidence, not both"
        ))),
        (Some(bytes), None) => {
            let canonical = match parse_source_evidence_bytes(bytes) {
                Ok(value) => value,
                Err(_) => {
                    let parsed = parse_json_bytes_strict(bytes)?;
                    canonicalize_source_evidence(&parsed)?
                }
            };
            Ok(ResolvedSourceEvidence {
                value: canonical.source_evidence.value,
                bytes: canonical.bytes,
                digest_hex: canonical.digest.value.clone(),
                target_ref: format!("source-evidence:sha3-512:{}", canonical.digest.value),
            })
        }
        (None, Some(value)) => {
            let canonical = canonicalize_source_evidence(value)?;
            Ok(ResolvedSourceEvidence {
                value: canonical.source_evidence.value,
                bytes: canonical.bytes,
                digest_hex: canonical.digest.value.clone(),
                target_ref: format!("source-evidence:sha3-512:{}", canonical.digest.value),
            })
        }
        (None, None) => Err(err(format!(
            "{label}: source-evidence import requires sourceEvidenceBytes or sourceEvidence"
        ))),
    }
}

fn import_external_lifecycle_signature(
    family: LifecycleSignatureFamily,
    target: &ResolvedTarget,
    name: &str,
    signature_bytes: &[u8],
    pins: &[PqPin],
    expected_ed25519: Option<&str>,
) -> Result<ImportedSignature> {
    match classify_detached_archive_approval_bytes(signature_bytes) {
        Ok(DetachedArchiveApprovalKind::Qsig) => {
            import_external_qsig(family, target, name, signature_bytes, pins)
        }
        Ok(DetachedArchiveApprovalKind::StellarJson) => {
            import_external_stellar_sig(family, target, name, signature_bytes, expected_ed25519)
        }
        Err(error) => Err(err(format!(
            "{name}: unsupported detached signature format ({error})"
        ))),
    }
}

fn import_external_qsig(
    family: LifecycleSignatureFamily,
    target: &ResolvedTarget,
    name: &str,
    signature_bytes: &[u8],
    pins: &[PqPin],
) -> Result<ImportedSignature> {
    let mut successful = Vec::new();
    for pin in pins {
        let result = verify_qsig_against_bytes(
            &target.bytes,
            signature_bytes,
            Some(&pin.bytes),
            Some(&pin.bytes),
        )?;
        if result.ok && result.signer_pinned {
            successful.push((result, pin));
        }
    }
    let (verified, matched_pin) = match successful.len() {
        1 => {
            let (result, pin) = successful.remove(0);
            (result, Some(pin))
        }
        count if count > 1 => {
            return Err(err(format!(
                "Multiple .pqpk files verify {name}. Keep only the intended signer key."
            )))
        }
        _ if !pins.is_empty() => {
            return Err(err(format!(
                "{name}: no provided .pqpk file matches this detached PQ signature."
            )))
        }
        _ => {
            let result = verify_qsig_against_bytes(&target.bytes, signature_bytes, None, None)?;
            if !result.ok {
                return Err(err(format!(
                    "{name}: {}",
                    result
                        .error
                        .unwrap_or_else(|| "PQ signature verification failed".to_string())
                )));
            }
            (result, None)
        }
    };
    let public_key = matched_pin.map(build_public_key_attachment).transpose()?;
    let suite = verified
        .suite
        .ok_or_else(|| err(format!("{name}: verified .qsig did not report a suite")))?;
    Ok(ImportedSignature {
        public_keys: public_key.clone().into_iter().collect(),
        signature: signature_entry(
            family,
            "qsig",
            &suite,
            target,
            signature_bytes,
            public_key
                .as_ref()
                .and_then(|value| value["id"].as_str())
                .map(str::to_string),
        ),
    })
}

fn import_external_stellar_sig(
    family: LifecycleSignatureFamily,
    target: &ResolvedTarget,
    name: &str,
    signature_bytes: &[u8],
    expected_ed25519: Option<&str>,
) -> Result<ImportedSignature> {
    let verified =
        verify_stellar_sig_against_bytes(&target.bytes, signature_bytes, None, expected_ed25519)?;
    if !verified.ok {
        return Err(err(format!(
            "{name}: {}",
            verified
                .error
                .unwrap_or_else(|| "Ed25519 signature verification failed".to_string())
        )));
    }
    let public_key = verified
        .signer
        .as_deref()
        .and_then(build_stellar_signer_attachment);
    Ok(ImportedSignature {
        public_keys: public_key.clone().into_iter().collect(),
        signature: signature_entry(
            family,
            "stellar-sig",
            "ed25519",
            target,
            signature_bytes,
            public_key
                .as_ref()
                .and_then(|value| value["id"].as_str())
                .map(str::to_string),
        ),
    })
}

fn build_public_key_attachment(pin: &PqPin) -> Result<Value> {
    let suite = suite_from_id(pin.parsed.suite_id)?;
    let kty = crate::auth::get_signature_suite_info(suite)?.public_key_type;
    let identity = format!(
        "{}:{}",
        pin.parsed.suite_id,
        hex::encode(&pin.parsed.key_bytes)
    );
    Ok(serde_json::json!({
        "id": attachment_id("key", identity.as_bytes()),
        "kty": kty,
        "suite": suite,
        "encoding": "base64",
        "value": BASE64_STANDARD.encode(&pin.parsed.key_bytes),
    }))
}

fn build_stellar_signer_attachment(signer: &str) -> Option<Value> {
    let signer = signer.trim();
    if signer.is_empty() {
        return None;
    }
    Some(serde_json::json!({
        "id": attachment_id("key", signer.as_bytes()),
        "kty": "ed25519-public-key",
        "suite": "ed25519",
        "encoding": "stellar-address",
        "value": signer,
    }))
}

fn signature_entry(
    family: LifecycleSignatureFamily,
    format: &str,
    suite: &str,
    target: &ResolvedTarget,
    signature_bytes: &[u8],
    public_key_ref: Option<String>,
) -> Value {
    let mut object = serde_json::Map::new();
    object.insert(
        "id".to_string(),
        Value::String(signature_attachment_id(format, signature_bytes)),
    );
    object.insert(
        "signatureFamily".to_string(),
        Value::String(family.as_str().to_string()),
    );
    object.insert("format".to_string(), Value::String(format.to_string()));
    object.insert("suite".to_string(), Value::String(suite.to_string()));
    object.insert(
        "targetType".to_string(),
        Value::String(target.target_type.clone()),
    );
    object.insert(
        "targetRef".to_string(),
        Value::String(target.target_ref.clone()),
    );
    object.insert(
        "targetDigest".to_string(),
        serde_json::json!({"alg": "SHA3-512", "value": target.digest_hex}),
    );
    object.insert(
        "signatureEncoding".to_string(),
        Value::String("base64".to_string()),
    );
    object.insert(
        "signature".to_string(),
        Value::String(BASE64_STANDARD.encode(signature_bytes)),
    );
    // Always emit the member; JS canonical bundles carry `"publicKeyRef":null`
    // when no `.pqpk` pin matched the imported signature.
    object.insert(
        "publicKeyRef".to_string(),
        public_key_ref.map(Value::String).unwrap_or(Value::Null),
    );
    Value::Object(object)
}

fn build_signature_artifacts(bundle: &Value) -> Result<Vec<SignatureArtifact>> {
    let attachments = object_field(bundle, "attachments", "lifecycleBundle.attachments")?;
    let mut out = Vec::new();
    for (field, family) in [
        ("archiveApprovalSignatures", "archive-approval"),
        ("maintenanceSignatures", "maintenance"),
        ("sourceEvidenceSignatures", "source-evidence"),
    ] {
        for signature in array_field(attachments, field, field)? {
            let id = string_field(signature, "id", "detachedSignature.id")?;
            let format = string_field(signature, "format", "detachedSignature.format")?;
            let target_type =
                string_field(signature, "targetType", "detachedSignature.targetType")?;
            let target_ref = string_field(signature, "targetRef", "detachedSignature.targetRef")?;
            let bytes = BASE64_STANDARD
                .decode(string_field(
                    signature,
                    "signature",
                    "detachedSignature.signature",
                )?)
                .map_err(|error| err(format!("Invalid detached signature base64: {error}")))?;
            out.push(SignatureArtifact {
                id: id.clone(),
                name: id,
                source: "lifecycle-bundle".to_string(),
                family: family.to_string(),
                format,
                target_type: Some(target_type),
                target_ref: Some(target_ref),
                signature_content_digest_hex: Some(sha3_512_hex(&bytes)),
                ots_stamped_digest_hex: Some(sha256_hex(&bytes)),
                bytes,
                ok: true,
            });
        }
    }
    Ok(out)
}

/// Public keys, maintenance signature attachment entries, and timestamp attachment entries produced
/// when importing same-run maintenance evidence over a newly emitted transition record (oracle:
/// `quantum-vault` `reshare.js` attach phase).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MaintenanceEvidenceAttachments {
    pub public_keys: Vec<Value>,
    pub maintenance_signatures: Vec<Value>,
    pub timestamps: Vec<Value>,
}

fn maintenance_signature_artifacts(entries: &[Value]) -> Result<Vec<SignatureArtifact>> {
    let mut out = Vec::new();
    for signature in entries {
        let id = string_field(signature, "id", "maintenanceSignature.id")?;
        let format = string_field(signature, "format", "maintenanceSignature.format")?;
        let bytes = BASE64_STANDARD
            .decode(string_field(
                signature,
                "signature",
                "maintenanceSignature.signature",
            )?)
            .map_err(|error| err(format!("Invalid detached signature base64: {error}")))?;
        out.push(SignatureArtifact {
            id: id.clone(),
            name: id,
            source: "reshare-maintenance".to_string(),
            family: "maintenance".to_string(),
            format,
            target_type: Some("transition-record".to_string()),
            target_ref: Some(string_field(
                signature,
                "targetRef",
                "maintenanceSignature.targetRef",
            )?),
            signature_content_digest_hex: Some(sha3_512_hex(&bytes)),
            ots_stamped_digest_hex: Some(sha256_hex(&bytes)),
            bytes,
            ok: true,
        });
    }
    Ok(out)
}

/// Import detached maintenance signatures (and optional `.pqpk` pins plus `.ots` proofs) over the
/// **new** same-state transition record bytes produced by resharing.
///
/// When each [`LifecycleSignatureImport`] omits `targetRef` / `targetDigestHex`, they default to
/// this transition. If present, they must match exactly (fail closed).
pub fn import_maintenance_evidence_for_new_transition(
    transition: &CanonicalTransitionRecord,
    imports: &[LifecycleSignatureImport],
    pq_public_key_file_bytes_list: &[Vec<u8>],
    timestamps: &[NamedBinaryArtifact],
    expected_ed25519_signer: Option<&str>,
) -> Result<MaintenanceEvidenceAttachments> {
    if !pq_public_key_file_bytes_list.is_empty() && imports.is_empty() {
        return Err(err(
            "maintenance signer keys require at least one maintenance signature import",
        ));
    }
    if !timestamps.is_empty() && imports.is_empty() {
        return Err(err(
            "maintenance OpenTimestamps proofs require at least one maintenance signature import",
        ));
    }
    if imports.is_empty() {
        return Ok(MaintenanceEvidenceAttachments::default());
    }

    let expected_ref = format!("transition:sha3-512:{}", transition.digest.value);
    let pins = normalize_pq_pins(pq_public_key_file_bytes_list)?;
    let target = ResolvedTarget {
        target_type: "transition-record".to_string(),
        target_ref: expected_ref.clone(),
        digest_hex: transition.digest.value.clone(),
        bytes: transition.bytes.clone(),
    };

    let mut public_keys_out = Vec::<Value>::new();
    let mut signatures_out = Vec::<Value>::new();

    for (index, import) in imports.iter().enumerate() {
        if import.signature_family != LifecycleSignatureFamily::Maintenance {
            return Err(err(format!(
                "reshare maintenance import {} must use signature family maintenance",
                index + 1
            )));
        }
        let target_type = import
            .target_type
            .as_deref()
            .unwrap_or(LifecycleSignatureFamily::Maintenance.target_type());
        if target_type != LifecycleSignatureFamily::Maintenance.target_type() {
            return Err(err(format!(
                "reshare maintenance import {}: wrong targetType (expected transition-record)",
                index + 1
            )));
        }
        if let Some(declared_ref) = import.target_ref.as_deref() {
            if declared_ref != expected_ref.as_str() {
                return Err(err(format!(
                    "reshare maintenance import {}: targetRef must match the newly emitted transition (expected {expected_ref})",
                    index + 1
                )));
            }
        }
        if let Some(declared_digest) = import.target_digest_hex.as_deref() {
            if declared_digest != transition.digest.value {
                return Err(err(format!(
                    "reshare maintenance import {}: targetDigest must equal the newly emitted transition-record digest",
                    index + 1
                )));
            }
        }

        let label = import_label(&import.name, &format!("maintenance-sig-{}", index + 1));
        let imported = import_external_lifecycle_signature(
            LifecycleSignatureFamily::Maintenance,
            &target,
            &label,
            &import.bytes,
            &pins,
            expected_ed25519_signer
                .map(str::trim)
                .filter(|s| !s.is_empty()),
        )?;
        public_keys_out.extend(imported.public_keys);
        signatures_out.push(imported.signature);
    }

    let signature_artifacts = maintenance_signature_artifacts(&signatures_out)?;
    let mut timestamps_out = Vec::<Value>::new();
    for timestamp in timestamps {
        if timestamp.bytes.is_empty() {
            return Err(err(format!(
                "Invalid maintenance timestamp file: {}",
                import_label(&timestamp.name, "timestamp")
            )));
        }
        let name = import_label(&timestamp.name, "maintenance-ots");
        let resolved =
            resolve_open_timestamp_target(&timestamp.bytes, Some(&name), &signature_artifacts)?;
        timestamps_out.push(serde_json::json!({
            "id": attachment_id("ots", &timestamp.bytes),
            "type": "opentimestamps",
            "targetRef": resolved.target_ref,
            "targetDigest": {
                "alg": "SHA-256",
                "value": resolved.stamped_digest_hex,
            },
            "proofEncoding": "base64",
            "proof": BASE64_STANDARD.encode(&timestamp.bytes),
        }));
    }

    Ok(MaintenanceEvidenceAttachments {
        public_keys: public_keys_out,
        maintenance_signatures: signatures_out,
        timestamps: timestamps_out,
    })
}

fn merge_entries_by_id(existing: &[Value], next: &[Value]) -> Result<Vec<Value>> {
    let mut out = existing.to_vec();
    let mut by_id = HashMap::new();
    for (index, item) in out.iter().enumerate() {
        by_id.insert(string_field(item, "id", "attachment.id")?, index);
    }
    for value in next {
        let id = string_field(value, "id", "attachment.id")?;
        if let Some(index) = by_id.get(&id) {
            if canonicalize_json(&out[*index])? != canonicalize_json(value)? {
                return Err(err(format!(
                    "Lifecycle attachment merge conflict: duplicate id \"{id}\" with differing content"
                )));
            }
            continue;
        }
        by_id.insert(id, out.len());
        out.push(value.clone());
    }
    Ok(out)
}

fn merge_source_evidence_entries(existing: &[Value], next: &[Value]) -> Result<Vec<Value>> {
    let mut out = existing.to_vec();
    let mut by_digest = HashMap::new();
    for (index, value) in out.iter().enumerate() {
        let canonical = canonicalize_source_evidence(value)?;
        by_digest.insert(canonical.digest.value, (index, canonical.bytes));
    }
    for value in next {
        let canonical = canonicalize_source_evidence(value)?;
        if let Some((_, previous_bytes)) = by_digest.get(&canonical.digest.value) {
            if previous_bytes != &canonical.bytes {
                return Err(err(format!(
                    "Lifecycle source-evidence merge conflict: duplicate digest \"{}\" with differing content",
                    canonical.digest.value
                )));
            }
            continue;
        }
        by_digest.insert(canonical.digest.value, (out.len(), canonical.bytes));
        out.push(canonical.source_evidence.value);
    }
    Ok(out)
}

fn ensure_attach_preserved_identity(
    context: &AttachContext<'_>,
    bundle: &CanonicalLifecycleBundle,
) -> Result<()> {
    let archive_state =
        canonicalize_archive_state_descriptor(&bundle.lifecycle_bundle.value["archiveState"])?;
    if archive_state.bytes != context.archive_state_bytes {
        return Err(err(
            "Attach changed the archive-state descriptor bytes, which is forbidden",
        ));
    }
    let cohort_binding =
        canonicalize_cohort_binding(&bundle.lifecycle_bundle.value["currentCohortBinding"])?;
    if cohort_binding.bytes != context.cohort_binding_bytes {
        return Err(err(
            "Attach changed the cohort-binding bytes, which is forbidden",
        ));
    }
    Ok(())
}

fn rewrite_lifecycle_bundle_in_shard(
    shard: &Qvqcont7Shard,
    lifecycle_bundle_bytes: &[u8],
) -> Result<AttachedLifecycleShard> {
    let lifecycle_bundle = parse_lifecycle_bundle_bytes(lifecycle_bundle_bytes)?;
    let mut updated = shard.clone();
    updated.lifecycle_bundle_bytes = lifecycle_bundle.bytes.clone();
    updated.lifecycle_bundle_digest_hex = lifecycle_bundle.digest.value.clone();
    updated.lifecycle_bundle = lifecycle_bundle;
    Ok(AttachedLifecycleShard {
        index: shard.shard_index,
        bytes: crate::qcont::build_qvqcont7_shard(&updated)?,
    })
}

fn digest_from_target_ref(
    family: LifecycleSignatureFamily,
    target_ref: &str,
    label: &str,
) -> Result<String> {
    let prefix = match family {
        LifecycleSignatureFamily::ArchiveApproval => "state:",
        LifecycleSignatureFamily::Maintenance => "transition:sha3-512:",
        LifecycleSignatureFamily::SourceEvidence => "source-evidence:sha3-512:",
    };
    let Some(digest) = target_ref.strip_prefix(prefix) else {
        return Err(err(format!(
            "{label}: invalid targetRef for {}",
            family.as_str()
        )));
    };
    if digest.len() != 128
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(err(format!(
            "{label}: invalid targetRef for {}",
            family.as_str()
        )));
    }
    Ok(digest.to_string())
}

fn attachment_id(prefix: &str, bytes: &[u8]) -> String {
    format!("{prefix}-{}", &sha3_512_hex(bytes)[..16])
}

fn signature_attachment_id(_format: &str, bytes: &[u8]) -> String {
    let digest = sha3_512_hex(bytes);
    format!("sig-{}", &digest[..16])
}

fn suite_from_id(suite_id: u8) -> Result<&'static str> {
    Ok(match suite_id {
        crate::auth::qsig::SUITE_ID_ML_DSA_44 => "mldsa-44",
        crate::auth::qsig::SUITE_ID_ML_DSA_65 => "mldsa-65",
        crate::auth::qsig::SUITE_ID_ML_DSA_87 => "mldsa-87",
        crate::auth::qsig::SUITE_ID_SLH_DSA_SHAKE_128S => "slhdsa-shake-128s",
        crate::auth::qsig::SUITE_ID_SLH_DSA_SHAKE_192S => "slhdsa-shake-192s",
        crate::auth::qsig::SUITE_ID_SLH_DSA_SHAKE_256S => "slhdsa-shake-256s",
        crate::auth::qsig::SUITE_ID_SLH_DSA_SHAKE_256F => "slhdsa-shake-256f",
        _ => return Err(err(format!("Unsupported .pqpk suite id: {suite_id}"))),
    })
}

fn import_label(value: &str, fallback: &str) -> String {
    let value = value.trim();
    if value.is_empty() {
        fallback.to_string()
    } else {
        value.to_string()
    }
}

fn object_field<'a>(value: &'a Value, key: &str, field: &str) -> Result<&'a Value> {
    let child = value
        .get(key)
        .ok_or_else(|| err(format!("Invalid {field}")))?;
    if !child.is_object() {
        return Err(err(format!("Invalid {field}")));
    }
    Ok(child)
}

fn array_field<'a>(value: &'a Value, key: &str, field: &str) -> Result<&'a Vec<Value>> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| err(format!("Invalid {field}")))
}

fn string_field(value: &Value, key: &str, field: &str) -> Result<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| err(format!("Invalid {field}")))
}

fn set_object_field(value: &mut Value, key: &str, next: Value) -> Result<()> {
    let Some(object) = value.as_object_mut() else {
        return Err(err("Expected JSON object"));
    };
    object.insert(key.to_string(), next);
    Ok(())
}
