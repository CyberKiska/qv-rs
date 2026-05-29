use anyhow::{bail, Context, Result};
use qvault_core::auth::{DisplayMetadata, NamedBinaryArtifact, SignatureCheckResult};
use qvault_core::error::{coded, QvCode};
use qvault_core::lifecycle::{
    parse_archive_state_descriptor_bytes, parse_source_evidence_bytes,
    parse_transition_record_bytes,
};
use qvault_core::qcont::{LifecycleSignatureFamily, LifecycleSignatureImport};
use serde_json::Value;
use std::path::PathBuf;
use time::{format_description::well_known::Rfc3339, OffsetDateTime, UtcOffset};

use super::files::{read_file_checked, validate_optional_filename};
use super::{AttachArgs, CliContext, SignArgs, SignTargetArg};

pub(crate) fn load_named_artifacts(
    paths: &[PathBuf],
    ctx: CliContext,
) -> Result<Vec<NamedBinaryArtifact>> {
    paths
        .iter()
        .map(|path| {
            let bytes = read_file_checked(path, ctx)
                .with_context(|| format!("failed to read {}", path.display()))?;
            Ok(NamedBinaryArtifact {
                name: path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("artifact")
                    .to_string(),
                bytes,
            })
        })
        .collect()
}

pub(crate) fn build_attach_signature_imports(
    args: &AttachArgs,
    ctx: CliContext,
) -> Result<Vec<LifecycleSignatureImport>> {
    let mut imports = Vec::new();
    for artifact in load_named_artifacts(&args.archive_approval_signatures, ctx)
        .map_err(|error| signature_import_error(error.to_string()))?
    {
        imports.push(signature_import(
            artifact,
            LifecycleSignatureFamily::ArchiveApproval,
            None,
            None,
        ));
    }
    for artifact in load_named_artifacts(&args.maintenance_signatures, ctx)
        .map_err(|error| signature_import_error(error.to_string()))?
    {
        imports.push(signature_import(
            artifact,
            LifecycleSignatureFamily::Maintenance,
            args.maintenance_target_ref.clone(),
            None,
        ));
    }
    let source_evidence_bytes = match args.source_evidence.as_slice() {
        [single] => Some(
            read_file_checked(single, ctx)
                .with_context(|| format!("failed to read source-evidence {}", single.display()))
                .map_err(|error| signature_import_error(error.to_string()))?,
        ),
        [] => None,
        _ if args.source_evidence_signatures.is_empty() => None,
        _ => {
            return Err(signature_import_error(
                "--source-evidence-sig requires exactly one --source-evidence when no explicit per-signature target is available",
            ))
        }
    };
    for artifact in load_named_artifacts(&args.source_evidence_signatures, ctx)
        .map_err(|error| signature_import_error(error.to_string()))?
    {
        let import = signature_import(
            artifact,
            LifecycleSignatureFamily::SourceEvidence,
            args.source_evidence_target_ref.clone(),
            source_evidence_bytes.clone(),
        );
        if import.source_evidence_bytes.is_none() && import.target_ref.is_none() {
            return Err(signature_import_error(
                "--source-evidence-sig requires --source-evidence or --source-evidence-target-ref",
            ));
        }
        imports.push(import);
    }
    for spec in &args.sig_imports {
        imports.push(parse_sig_import_spec(spec, ctx)?);
    }
    Ok(imports)
}

pub(crate) fn signature_import(
    artifact: NamedBinaryArtifact,
    family: LifecycleSignatureFamily,
    target_ref: Option<String>,
    source_evidence_bytes: Option<Vec<u8>>,
) -> LifecycleSignatureImport {
    LifecycleSignatureImport {
        name: artifact.name,
        bytes: artifact.bytes,
        signature_family: family,
        target_type: Some(family.target_type().to_string()),
        target_ref,
        target_digest_hex: None,
        source_evidence_bytes,
        source_evidence_value: None,
    }
}

fn signature_import_error(message: impl Into<String>) -> anyhow::Error {
    coded(QvCode::SignatureImportFailed, message).into()
}

fn parse_sig_import_spec(spec: &str, ctx: CliContext) -> Result<LifecycleSignatureImport> {
    let value: Value = serde_json::from_str(spec).map_err(|error| {
        signature_import_error(format!("--sig-import must be a JSON object: {error}"))
    })?;
    let object = value
        .as_object()
        .ok_or_else(|| signature_import_error("--sig-import must be a JSON object"))?;
    let file = object
        .get("file")
        .and_then(Value::as_str)
        .ok_or_else(|| signature_import_error("--sig-import.file is required"))?;
    let family = match object
        .get("signatureFamily")
        .and_then(Value::as_str)
        .ok_or_else(|| signature_import_error("--sig-import.signatureFamily is required"))?
    {
        "archive-approval" => LifecycleSignatureFamily::ArchiveApproval,
        "maintenance" => LifecycleSignatureFamily::Maintenance,
        "source-evidence" => LifecycleSignatureFamily::SourceEvidence,
        other => {
            return Err(signature_import_error(format!(
                "unsupported --sig-import.signatureFamily: {other}"
            )))
        }
    };
    let path = PathBuf::from(file);
    let bytes = read_file_checked(&path, ctx)
        .with_context(|| format!("failed to read --sig-import file {}", path.display()))
        .map_err(|error| signature_import_error(error.to_string()))?;
    let source_evidence_bytes = object
        .get("sourceEvidence")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .map(|path| read_file_checked(&path, ctx))
        .transpose()
        .map_err(|error| signature_import_error(error.to_string()))?;
    let target_digest_hex = match object.get("targetDigest") {
        Some(Value::String(value)) => Some(value.clone()),
        Some(Value::Object(map)) => map.get("value").and_then(Value::as_str).map(str::to_string),
        Some(_) => {
            return Err(signature_import_error(
                "--sig-import.targetDigest must be a hex string or digest object",
            ))
        }
        None => None,
    };
    Ok(LifecycleSignatureImport {
        name: path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("signature")
            .to_string(),
        bytes,
        signature_family: family,
        target_type: object
            .get("targetType")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| Some(family.target_type().to_string())),
        target_ref: object
            .get("targetRef")
            .and_then(Value::as_str)
            .map(str::to_string),
        target_digest_hex,
        source_evidence_bytes,
        source_evidence_value: None,
    })
}

pub(crate) fn select_single_pinned_pqpk(
    public_keys: &[NamedBinaryArtifact],
) -> Result<Option<Vec<u8>>> {
    let Some(first) = public_keys.first() else {
        return Ok(None);
    };
    for key in public_keys.iter().skip(1) {
        if key.bytes != first.bytes {
            bail!("restore accepts at most one distinct --pqpk pinned PQ signer key");
        }
    }
    Ok(Some(first.bytes.clone()))
}

pub(crate) fn normalize_optional_string(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

pub(crate) fn validate_sign_target_bytes(bytes: &[u8], target: SignTargetArg) -> Result<()> {
    let result = match target {
        SignTargetArg::Bytes => return Ok(()),
        SignTargetArg::ArchiveState => parse_archive_state_descriptor_bytes(bytes).map(|_| ()),
        SignTargetArg::TransitionRecord => parse_transition_record_bytes(bytes).map(|_| ()),
        SignTargetArg::SourceEvidence => parse_source_evidence_bytes(bytes).map(|_| ()),
    };
    result.map_err(|error| {
        coded(
            QvCode::InvalidFormat,
            format!(
                "{} signing target must be canonical and valid: {error}",
                target.as_str()
            ),
        )
        .into()
    })
}

pub(crate) fn build_sign_display_metadata(
    args: &SignArgs,
    target_len: usize,
) -> Result<DisplayMetadata> {
    let filename = args.filename.clone().or_else(|| {
        (args.target == SignTargetArg::Bytes)
            .then(|| {
                args.input_file
                    .file_name()
                    .and_then(|value| value.to_str())
                    .map(str::to_string)
            })
            .flatten()
    });
    validate_optional_filename(filename.as_deref())?;
    let filesize = if args.target == SignTargetArg::Bytes {
        Some(u64::try_from(target_len).map_err(|_| {
            coded(
                QvCode::UnsupportedFormat,
                "sign target length does not fit in display metadata filesize",
            )
        })?)
    } else {
        None
    };
    let created_at = args
        .created_at
        .as_deref()
        .map(normalize_created_at)
        .transpose()?;
    Ok(DisplayMetadata {
        filename,
        filesize,
        created_at,
    })
}

fn normalize_created_at(value: &str) -> Result<String> {
    let parsed = OffsetDateTime::parse(value, &Rfc3339).map_err(|error| {
        coded(
            QvCode::InvalidFormat,
            format!("--created-at must be valid RFC3339/ISO-8601: {error}"),
        )
    })?;
    let utc = parsed.to_offset(UtcOffset::UTC);
    if !(0..=9999).contains(&utc.year()) {
        return Err(coded(
            QvCode::InvalidFormat,
            "--created-at year must fit canonical four-digit UTC form",
        )
        .into());
    }
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        utc.year(),
        u8::from(utc.month()),
        utc.day(),
        utc.hour(),
        utc.minute(),
        utc.second(),
        utc.millisecond()
    ))
}

pub(crate) fn sig_verify_reason_code(
    verification: &SignatureCheckResult,
    pqpk_provided: bool,
) -> &'static str {
    if verification.ok {
        if pqpk_provided && (verification.bundle_pinned || verification.user_pinned) {
            return "VERIFIED_WITH_PQPK";
        }
        if verification.self_signed {
            return "VERIFIED_EMBEDDED_KEY_UNPINNED";
        }
        return "VERIFIED";
    }

    let error = verification.error.as_deref().unwrap_or_default();
    if error.contains("Signed SHA3-512 hash does not match") {
        return "TARGET_DIGEST_MISMATCH";
    }
    if error.contains("No verification key available") {
        return "NO_VERIFICATION_KEY";
    }
    if pqpk_provided {
        return "PQPK_VERIFICATION_FAILED";
    }
    "SIGNATURE_VERIFICATION_FAILED"
}

pub(crate) fn normalize_sig_verify_result_for_cli(
    verification: &mut SignatureCheckResult,
    pqpk_provided: bool,
) {
    if !pqpk_provided {
        return;
    }
    if verification.ok {
        verification.bundle_pinned = false;
        verification.user_pinned = true;
        verification.signer_pinned = true;
        verification.key_source = Some("user-pqpk".to_string());
        return;
    }
    if let Some(error) = verification.error.as_mut() {
        *error = error
            .replace("Bundled PQ public key", "Supplied .pqpk")
            .replace("bundled public key", "supplied .pqpk");
    }
}

pub(crate) fn sig_verify_trust_source(
    verification: &SignatureCheckResult,
    pqpk_provided: bool,
) -> String {
    if verification.ok && pqpk_provided && (verification.bundle_pinned || verification.user_pinned)
    {
        return "loaded-pqpk".to_string();
    }
    if verification.ok && verification.self_signed {
        return "embedded-only".to_string();
    }
    if !verification.ok && pqpk_provided {
        return "loaded-pqpk-failed".to_string();
    }
    if !verification.ok {
        return "none".to_string();
    }
    verification
        .key_source
        .clone()
        .unwrap_or_else(|| "unknown".to_string())
}
