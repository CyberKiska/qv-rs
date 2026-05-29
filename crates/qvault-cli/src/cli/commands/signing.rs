use super::super::*;

pub(super) fn run_sign(args: SignArgs, ctx: CliContext) -> Result<()> {
    validate_optional_filename(args.filename.as_deref())?;
    prepare_output_parent_dirs(std::slice::from_ref(&args.out), ctx)?;
    preflight_outputs(std::slice::from_ref(&args.out), args.force, ctx)?;

    let target_bytes = read_bounded_file_checked(
        &args.input_file,
        ctx,
        MAX_SIGNED_TARGET_BYTES,
        "sign target",
    )?;
    validate_sign_target_bytes(&target_bytes, args.target)?;

    let secret_key_file_bytes = Zeroizing::new(read_file_checked(&args.secret_key, ctx)?);
    let secret_key_file =
        unpack_secret_key_file(secret_key_file_bytes.as_slice()).map_err(|error| {
            coded(
                QvCode::InvalidFormat,
                format!("invalid PQ signing secret key file: {error}"),
            )
        })?;
    let suite = secret_key_file.suite;
    let suite_info = get_signature_suite_info(suite.canonical_name())?;
    let public_key = public_from_secret(suite, secret_key_file.key_bytes())?;
    let display_metadata = build_sign_display_metadata(&args, target_bytes.len())?;
    let display_metadata_json = serde_json::json!({
        "filename": display_metadata.filename.as_deref(),
        "filesize": display_metadata.filesize,
        "createdAt": display_metadata.created_at.as_deref()
    });
    let artifact = create_detached_qsig(
        DetachedSignOptions::new(suite, secret_key_file.key_bytes(), &target_bytes)
            .with_display_metadata(display_metadata),
    )?;
    if artifact.public_key != public_key {
        return Err(coded(
            QvCode::VerificationFailed,
            "generated detached PQ signature public key did not match derived signer key",
        )
        .into());
    }

    write_file_checked(&args.out, &artifact.qsig_bytes, ctx)?;

    let signer_fingerprint_hex = to_hex(&artifact.signer_fingerprint_record[1..]);
    let target_digest_hex = sha3_512_hex(&target_bytes);
    let signature_digest_hex = sha3_512_hex(&artifact.qsig_bytes);
    let public_key_digest_hex = sha3_512_hex(&artifact.public_key);

    if ctx.json {
        let report = serde_json::json!({
            "command": "sign",
            "ok": true,
            "cliSchemaVersion": 1,
            "signaturePath": args.out,
            "signatureDigestAlg": "SHA3-512",
            "signatureDigestHex": signature_digest_hex,
            "signatureLength": artifact.qsig_bytes.len(),
            "target": {
                "type": args.target.as_str(),
                "path": args.input_file,
                "digestAlg": "SHA3-512",
                "digestHex": target_digest_hex,
                "length": target_bytes.len(),
                "canonicalLifecycleArtifact": args.target != SignTargetArg::Bytes
            },
            "suite": suite_info.canonical,
            "suiteDisplayName": suite_info.display_name,
            "signatureFamily": suite_info.family,
            "strongPq": suite_info.strong_pq,
            "signerFingerprintAlg": "SHA3-256",
            "signerFingerprintHex": signer_fingerprint_hex,
            "publicKeyDigestAlg": "SHA3-512",
            "publicKeyDigestHex": public_key_digest_hex,
            "displayMetadata": display_metadata_json
        });
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else if !ctx.quiet {
        println!("Created detached PQ signature: {}", args.out.display());
        println!("Target type: {}", args.target.as_str());
        println!("Suite: {}", suite_info.display_name);
        println!("Signer fingerprint (SHA3-256): {signer_fingerprint_hex}");
    }
    Ok(())
}

pub(super) fn run_sig_verify(args: SigVerifyArgs, ctx: CliContext) -> Result<()> {
    let document_bytes = read_bounded_file_checked(
        &args.input_file,
        ctx,
        MAX_SIGNED_TARGET_BYTES,
        "verification target",
    )?;
    let qsig_bytes = read_file_checked(&args.sig, ctx)?;
    let pqpk_bytes = args
        .pqpk
        .as_ref()
        .map(|path| read_file_checked(path, ctx))
        .transpose()?;
    let pqpk_provided = pqpk_bytes.is_some();

    let mut verification =
        verify_qsig_against_bytes(&document_bytes, &qsig_bytes, pqpk_bytes.as_deref(), None)
            .map_err(|error| {
                coded(
                    QvCode::InvalidFormat,
                    format!("detached QSIG verification input rejected: {error}"),
                )
            })?;
    normalize_sig_verify_result_for_cli(&mut verification, pqpk_provided);

    let reason_code = sig_verify_reason_code(&verification, pqpk_provided);
    let trust_source = sig_verify_trust_source(&verification, pqpk_provided);
    let trusted = verification.ok && (verification.bundle_pinned || verification.user_pinned);
    let document_digest_hex = sha3_512_hex(&document_bytes);
    let signature_digest_hex = sha3_512_hex(&qsig_bytes);

    if ctx.json {
        let report = serde_json::json!({
            "command": "sig-verify",
            "ok": verification.ok,
            "cliSchemaVersion": 1,
            "cryptographicOk": verification.ok,
            "trusted": trusted,
            "trustSource": trust_source,
            "reasonCode": reason_code,
            "lifecyclePolicyEvaluated": false,
            "countedForLifecyclePolicy": false,
            "documentPath": args.input_file,
            "signaturePath": args.sig,
            "publicKeyPath": args.pqpk,
            "documentDigestAlg": "SHA3-512",
            "documentDigestHex": document_digest_hex,
            "signatureDigestAlg": "SHA3-512",
            "signatureDigestHex": signature_digest_hex,
            "verification": serde_json::to_value(&verification)?,
            "warnings": verification.warnings
        });
        println!("{}", serde_json::to_string_pretty(&report)?);
        if !verification.ok {
            std::process::exit(map_qv_code_to_exit(QvCode::VerificationFailed));
        }
        return Ok(());
    }

    if !verification.ok {
        let reason = verification
            .error
            .clone()
            .unwrap_or_else(|| "detached PQ signature verification failed".to_string());
        return Err(coded(QvCode::VerificationFailed, reason).into());
    }

    if !ctx.quiet {
        println!("Detached PQ signature is cryptographically valid.");
        println!("Trust source: {trust_source}");
        if !trusted {
            println!("Signer identity is not pinned by a supplied .pqpk.");
        }
    }
    Ok(())
}
