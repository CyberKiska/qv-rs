use super::super::*;

pub(super) fn run_encrypt(args: EncryptArgs, ctx: CliContext) -> Result<()> {
    validate_optional_filename(args.filename.as_deref())?;
    let source_evidence_paths = encrypt_source_evidence_paths(&args)?;
    if source_evidence_paths.is_some() {
        let output_paths = encrypt_output_paths(&args, source_evidence_paths.as_ref());
        ensure_distinct_output_paths(&output_paths)?;
        prepare_output_parent_dirs(&output_paths, ctx)?;
        preflight_outputs(&output_paths, args.force, ctx)?;
    }

    let plaintext = Zeroizing::new(
        read_file_checked(&args.input_file, ctx)
            .with_context(|| format!("failed to read {}", args.input_file.display()))?,
    );
    let public_key = read_file_checked(&args.public_key, ctx)
        .with_context(|| format!("failed to read {}", args.public_key.display()))?;
    validate_public_key(&public_key)?;
    if source_evidence_paths.is_none() {
        preflight_outputs(std::slice::from_ref(&args.out), args.force, ctx)?;
    }

    let original_filename = match args.filename.clone() {
        Some(filename) => Some(filename),
        None => args
            .input_file
            .file_name()
            .and_then(|value| value.to_str())
            .map(str::to_string),
    };
    let source_evidence = source_evidence_paths
        .map(|paths| {
            create_encrypt_source_evidence(
                paths,
                args.source_evidence_key
                    .as_deref()
                    .expect("source-evidence paths require a key"),
                plaintext.as_slice(),
                ctx,
            )
        })
        .transpose()?;
    let qenc_bytes = encrypt_qenc(
        &plaintext,
        &public_key,
        &EncryptQencOptions {
            original_filename: original_filename.clone(),
            ..EncryptQencOptions::default()
        },
    )?;
    let header = parse_qenc_header(&qenc_bytes)?;
    if let Some(source_evidence) = source_evidence.as_ref() {
        write_encrypt_outputs(&args.out, &qenc_bytes, source_evidence, args.force, ctx)?;
    } else {
        write_file_checked(&args.out, &qenc_bytes, ctx)?;
    }

    if ctx.json {
        let mut report = serde_json::json!({
            "command": "encrypt",
            "ok": true,
            "cliSchemaVersion": 1,
            "alg": { "KEM": "ML-KEM-1024", "KDF": "KMAC256", "AEAD": "AES-256-GCM" },
            "inputPath": args.input_file,
            "inputPaths": [args.input_file],
            "outputPath": args.out,
            "publicKeyPath": args.public_key,
            "fmt": "QVv1-5-0",
            "aeadMode": header.metadata.aead_mode,
            "chunkSize": header.metadata.chunk_size,
            "chunkCount": header.metadata.chunk_count,
            "payloadLength": header.metadata.payload_length,
            "plaintextLength": plaintext.len(),
            "inputLength": plaintext.len(),
            "containerHashAlg": "SHA3-512",
            "containerHashHex": sha3_512_hex(&qenc_bytes),
            "containerId": Value::Null,
            "fileHashHex": sha3_512_hex(&plaintext),
            "originalFilename": original_filename,
            "payloadKind": "file",
            "fileCount": 1
        });
        if let Some(source_evidence) = source_evidence.as_ref() {
            let report_object = report
                .as_object_mut()
                .ok_or_else(|| anyhow::anyhow!("encrypt JSON report must be an object"))?;
            report_object.insert(
                "sourceEvidence".to_string(),
                encrypt_source_evidence_json(source_evidence)?,
            );
        }
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else if !ctx.quiet {
        println!("Encrypted file: {}", args.out.display());
        if let Some(source_evidence) = source_evidence.as_ref() {
            println!(
                "Source evidence: {}",
                source_evidence.paths.source_evidence.display()
            );
            println!(
                "Source evidence signature: {}",
                source_evidence.paths.signature.display()
            );
            println!(
                "Source evidence signer public key: {}",
                source_evidence.paths.public_key.display()
            );
            println!(
                "Signer fingerprint (SHA3-256): {}",
                source_evidence.signer_fingerprint_hex
            );
        }
    }
    Ok(())
}

fn encrypt_source_evidence_paths(args: &EncryptArgs) -> Result<Option<EncryptSourceEvidencePaths>> {
    let output_flag_present = args.source_evidence_out.is_some()
        || args.source_evidence_sig_out.is_some()
        || args.source_evidence_pqpk_out.is_some();
    if args.source_evidence_key.is_none() {
        if output_flag_present {
            bail!(
                    "--source-evidence-out requires --source-evidence-key; --source-evidence-sig-out and --source-evidence-pqpk-out also require --source-evidence-key"
                );
        }
        return Ok(None);
    }

    Ok(Some(EncryptSourceEvidencePaths {
        source_evidence: args
            .source_evidence_out
            .clone()
            .unwrap_or_else(|| append_file_name_suffix(&args.out, ".source-evidence.json")),
        signature: args
            .source_evidence_sig_out
            .clone()
            .unwrap_or_else(|| append_file_name_suffix(&args.out, ".source-evidence.json.qsig")),
        public_key: args
            .source_evidence_pqpk_out
            .clone()
            .unwrap_or_else(|| append_file_name_suffix(&args.out, ".source-evidence.pqpk")),
    }))
}

fn encrypt_output_paths(
    args: &EncryptArgs,
    source_evidence_paths: Option<&EncryptSourceEvidencePaths>,
) -> Vec<PathBuf> {
    let mut paths = vec![args.out.clone()];
    if let Some(paths_for_source_evidence) = source_evidence_paths {
        paths.push(paths_for_source_evidence.source_evidence.clone());
        paths.push(paths_for_source_evidence.signature.clone());
        paths.push(paths_for_source_evidence.public_key.clone());
    }
    paths
}

fn ensure_distinct_output_paths(paths: &[PathBuf]) -> Result<()> {
    for (index, path) in paths.iter().enumerate() {
        if paths[..index].iter().any(|existing| existing == path) {
            bail!("encrypt output paths must be distinct: {}", path.display());
        }
    }
    Ok(())
}

fn create_encrypt_source_evidence(
    paths: EncryptSourceEvidencePaths,
    secret_key_path: &Path,
    plaintext: &[u8],
    ctx: CliContext,
) -> Result<EncryptSourceEvidenceArtifact> {
    let canonical = build_source_file_evidence(plaintext, SourceFileEvidenceOptions::default())?;
    let source_digests = canonical
        .source_evidence
        .value
        .get("sourceDigests")
        .cloned()
        .ok_or_else(|| {
            coded(
                QvCode::InvalidFormat,
                "source evidence missing sourceDigests",
            )
        })?;
    let source_evidence_bytes = canonical.bytes;

    let secret_key_file_bytes = Zeroizing::new(read_file_checked(secret_key_path, ctx)?);
    let secret_key_file =
        unpack_secret_key_file(secret_key_file_bytes.as_slice()).map_err(|error| {
            coded(
                QvCode::InvalidFormat,
                format!("invalid source-evidence PQ signing key file: {error}"),
            )
        })?;
    let suite = secret_key_file.suite;
    let derived_public_key = public_from_secret(suite, secret_key_file.key_bytes())?;
    let artifact = create_detached_qsig(DetachedSignOptions::new(
        suite,
        secret_key_file.key_bytes(),
        &source_evidence_bytes,
    ))?;
    if artifact.public_key != derived_public_key {
        return Err(coded(
            QvCode::VerificationFailed,
            "generated source-evidence signature public key did not match derived signer key",
        )
        .into());
    }
    let public_key_file_bytes = pack_public_key_file(suite, &artifact.public_key)?;
    let verification = verify_qsig_against_bytes(
        &source_evidence_bytes,
        &artifact.qsig_bytes,
        Some(&public_key_file_bytes),
        None,
    )
    .map_err(|error| {
        coded(
            QvCode::InvalidFormat,
            format!("generated source-evidence QSIG failed verifier parsing: {error}"),
        )
    })?;
    if !verification.ok {
        return Err(coded(
            QvCode::VerificationFailed,
            "generated source-evidence QSIG failed self-verification",
        )
        .into());
    }

    Ok(EncryptSourceEvidenceArtifact {
        paths,
        source_evidence_bytes,
        suite,
        signer_fingerprint_hex: to_hex(&artifact.signer_fingerprint_record[1..]),
        source_digests,
        public_key_digest_hex: sha3_512_hex(&artifact.public_key),
        public_key_file_digest_hex: sha3_512_hex(&public_key_file_bytes),
        signature_digest_hex: sha3_512_hex(&artifact.qsig_bytes),
        signature_bytes: artifact.qsig_bytes,
        public_key_file_bytes,
    })
}

fn write_encrypt_outputs(
    qenc_path: &Path,
    qenc_bytes: &[u8],
    source_evidence: &EncryptSourceEvidenceArtifact,
    force: bool,
    ctx: CliContext,
) -> Result<()> {
    let outputs: [(&Path, &[u8]); 4] = [
        (qenc_path, qenc_bytes),
        (
            source_evidence.paths.source_evidence.as_path(),
            source_evidence.source_evidence_bytes.as_slice(),
        ),
        (
            source_evidence.paths.signature.as_path(),
            source_evidence.signature_bytes.as_slice(),
        ),
        (
            source_evidence.paths.public_key.as_path(),
            source_evidence.public_key_file_bytes.as_slice(),
        ),
    ];
    let mut written = Vec::new();
    for (path, bytes) in outputs {
        match write_file_checked(path, bytes, ctx) {
            Ok(()) => written.push(path.to_path_buf()),
            Err(error) => {
                let mut may_have_written = written;
                may_have_written.push(path.to_path_buf());
                if !force {
                    for created in &may_have_written {
                        let _ = fs::remove_file(created);
                    }
                }
                let may_have_written_text = may_have_written
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(error.context(format!(
                        "failed while writing coordinated encrypt source-evidence outputs; files that may have been written: {may_have_written_text}; best-effort cleanup {}",
                        if force {
                            "was not attempted because --force was used"
                        } else {
                            "was attempted for these paths"
                        }
                    )));
            }
        }
    }
    Ok(())
}

fn encrypt_source_evidence_json(source_evidence: &EncryptSourceEvidenceArtifact) -> Result<Value> {
    let suite_info = get_signature_suite_info(source_evidence.suite.canonical_name())?;
    Ok(serde_json::json!({
        "enabled": true,
        "sourceEvidencePath": source_evidence.paths.source_evidence,
        "signaturePath": source_evidence.paths.signature,
        "publicKeyPath": source_evidence.paths.public_key,
        "relationType": SOURCE_EVIDENCE_RELATION_ENCRYPTED_SOURCE,
        "sourceObjectType": SOURCE_EVIDENCE_OBJECT_TYPE_FILE,
        "canonicalization": SOURCE_EVIDENCE_CANONICALIZATION,
        "sourceDigests": source_evidence.source_digests,
        "signatureFormat": "qsig",
        "signatureDigestAlg": "SHA3-512",
        "signatureDigestHex": source_evidence.signature_digest_hex,
        "signatureLength": source_evidence.signature_bytes.len(),
        "suite": suite_info.canonical,
        "suiteDisplayName": suite_info.display_name,
        "signatureFamily": suite_info.family,
        "strongPq": suite_info.strong_pq,
        "signerFingerprintAlg": "SHA3-256",
        "signerFingerprintHex": source_evidence.signer_fingerprint_hex,
        "publicKeyDigestAlg": "SHA3-512",
        "publicKeyDigestHex": source_evidence.public_key_digest_hex,
        "publicKeyFileDigestAlg": "SHA3-512",
        "publicKeyFileDigestHex": source_evidence.public_key_file_digest_hex,
        "publicKeyFileLength": source_evidence.public_key_file_bytes.len()
    }))
}

pub(super) fn run_decrypt(args: DecryptArgs, ctx: CliContext) -> Result<()> {
    if args.out.is_some() && (args.out_dir.is_some() || args.use_original_filename) {
        bail!("decrypt accepts --out or --out-dir/--use-original-filename, not both");
    }
    let qenc_bytes = read_file_checked(&args.input_qenc, ctx)
        .with_context(|| format!("failed to read {}", args.input_qenc.display()))?;
    let private_key = Zeroizing::new(
        read_file_checked(&args.private_key, ctx)
            .with_context(|| format!("failed to read {}", args.private_key.display()))?,
    );
    validate_secret_key(&private_key)?;
    let header = parse_qenc_header(&qenc_bytes)?;
    let mut decrypted = decrypt_qenc(&qenc_bytes, &private_key)?;
    let file_bytes = Zeroizing::new(std::mem::take(&mut decrypted.file_bytes));
    let output_path = decrypt_output_path(&args, &decrypted.private_metadata.original_filename)?;
    preflight_outputs(std::slice::from_ref(&output_path), args.force, ctx)?;
    write_file_checked(&output_path, &file_bytes, ctx)?;

    if ctx.json {
        let report = serde_json::json!({
            "command": "decrypt",
            "ok": true,
            "cliSchemaVersion": 1,
            "inputPath": args.input_qenc,
            "outputPath": output_path,
            "outputPaths": [output_path],
            "alg": { "KEM": "ML-KEM-1024", "KDF": "KMAC256", "AEAD": "AES-256-GCM" },
            "fmt": "QVv1-5-0",
            "aeadMode": header.metadata.aead_mode,
            "chunkSize": header.metadata.chunk_size,
            "chunkCount": header.metadata.chunk_count,
            "payloadLength": header.metadata.payload_length,
            "plaintextLength": file_bytes.len(),
            "originalFilename": decrypted.private_metadata.original_filename,
            "fileHashHex": decrypted.private_metadata.file_hash,
            "containerHashAlg": "SHA3-512",
            "containerHashHex": sha3_512_hex(&qenc_bytes),
            "containerId": Value::Null,
            "payloadKind": if file_bytes.starts_with(b"QVB1") { "qvpack" } else { "file" },
            "fileCount": 1,
            "qvpackExtracted": false,
            "qvpackEntries": []
        });
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else if !ctx.quiet {
        println!("Decrypted file: {}", output_path.display());
    }
    Ok(())
}
