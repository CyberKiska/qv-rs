use super::super::*;

pub(super) fn run_verify(args: VerifyArgs, ctx: CliContext) -> Result<()> {
    let archive_state_bytes =
        read_small_artifact_checked(&args.archive_state, ctx, "Archive-state descriptor")?;
    let archive_state = parse_archive_state_descriptor_bytes(&archive_state_bytes)
        .map_err(|error| coded(QvCode::InvalidFormat, error.to_string()))?;
    let lifecycle_bundle_bytes = match &args.bundle {
        Some(path) => read_small_artifact_checked(path, ctx, "Lifecycle bundle")?,
        None => bail!("verify requires --bundle with canonical lifecycle bundle bytes"),
    };
    let signatures = load_named_artifacts(&args.signatures, ctx)?;
    let pq_public_keys = load_named_artifacts(&args.pq_public_keys, ctx)?;
    let timestamps = load_named_artifacts(&args.timestamps, ctx)?;
    let pinned_pq_public_key_file_bytes_list = select_distinct_pinned_pqpks(&pq_public_keys);
    let pq_public_key_file_bytes_list = pinned_pq_public_key_file_bytes_list.clone();
    let attached = attach_lifecycle_bundle_to_shards(
        &[],
        &AttachLifecycleOptions {
            archive_state_bytes: Some(archive_state.bytes.clone()),
            lifecycle_bundle_bytes: Some(lifecycle_bundle_bytes.clone()),
            signature_imports: signatures
                .into_iter()
                .map(|artifact| {
                    signature_import(
                        artifact,
                        LifecycleSignatureFamily::ArchiveApproval,
                        None,
                        None,
                    )
                })
                .collect(),
            pq_public_key_file_bytes_list,
            timestamps,
            expected_ed25519_signer: normalize_optional_string(
                args.expected_ed25519_signer.as_deref(),
            ),
            embed_into_shards: false,
            ..AttachLifecycleOptions::default()
        },
    )?;

    let authenticity = verify_successor_lifecycle_authenticity(
        &archive_state.bytes,
        &attached.lifecycle_bundle_bytes,
        &VerificationInputs {
            signatures: vec![],
            pinned_pq_public_key_file_bytes: None,
            pinned_pq_public_key_file_bytes_list,
            timestamps: vec![],
            expected_ed25519_signer: normalize_optional_string(
                args.expected_ed25519_signer.as_deref(),
            ),
        },
    )?;

    let required_policy = build_required_policy_report(&authenticity, args.required_policy_level);
    let verify_ok = verify_cli_report_satisfied(&authenticity, required_policy.as_ref());

    let detached_summary = if args.include_detached_summary {
        let rows: Vec<Value> = authenticity
            .verification
            .results
            .iter()
            .map(|row| {
                serde_json::json!({
                    "artifactId": row.artifact_id,
                    "name": row.name,
                    "source": row.source,
                    "format": row.format,
                    "ok": row.ok,
                    "proofIdentityDigestAlg": row.proof_identity_digest_alg,
                    "proofIdentityDigestHex": row.proof_identity_digest_hex,
                })
            })
            .collect();
        Value::Array(rows)
    } else {
        Value::Null
    };

    if ctx.json {
        let mut report = serde_json::json!({
            "command": "verify",
            "ok": verify_ok,
            "cliSchemaVersion": 1,
            "verification": serde_json::to_value(&authenticity.verification)?,
            "policy": serde_json::to_value(&authenticity.policy)?,
            "timestampEvidence": serde_json::to_value(&authenticity.timestamp_evidence)?,
            "transitionReport": serde_json::to_value(&authenticity.transition_report)?,
            "sourceEvidenceReport": serde_json::to_value(&authenticity.source_evidence_report)?,
            "warnings": authenticity.warnings,
            "status": serde_json::to_value(&authenticity.status)?,
            "detachedSummary": detached_summary,
        });
        if let Some(ref req) = required_policy {
            report["requiredPolicy"] = req.clone();
        }
        println!("{}", serde_json::to_string_pretty(&report)?);
        if !verify_ok {
            return Err(reported_exit(map_qv_code_to_exit(
                QvCode::PolicyNotSatisfied,
            )));
        }
        return Ok(());
    }

    if !verify_ok {
        let reason = required_policy
            .as_ref()
            .and_then(|value| value.get("reason").and_then(Value::as_str))
            .map(str::to_string)
            .unwrap_or_else(|| authenticity.policy.reason.clone());
        return Err(coded(QvCode::PolicyNotSatisfied, reason).into());
    }

    if !ctx.quiet {
        println!("Lifecycle verification succeeded.");
        println!("State ID: {}", archive_state.state_id);
    }
    Ok(())
}
