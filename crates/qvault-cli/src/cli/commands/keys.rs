use super::super::*;

pub(super) fn run_keygen(args: KeygenArgs, ctx: CliContext) -> Result<()> {
    if let Some(prefix) = args.name.as_deref() {
        validate_safe_name_prefix(prefix)?;
    }
    reject_symlink_components(&args.out, ctx.allow_symlink)?;
    fs::create_dir_all(&args.out)
        .with_context(|| format!("failed to create {}", args.out.display()))?;
    let prefix = args.name.as_deref().unwrap_or("");
    let public_key_path = args.out.join(format!("{prefix}publicKey.qkey"));
    let private_key_path = args.out.join(format!("{prefix}privateKey.qkey"));
    preflight_outputs(
        &[public_key_path.clone(), private_key_path.clone()],
        args.force,
        ctx,
    )?;

    let (public_key, private_key) = generate_key_pair()?;
    let private_key = Zeroizing::new(private_key);
    write_file_checked(&public_key_path, &public_key, args.force, ctx)?;
    write_secret_file_checked(&private_key_path, &private_key, args.force, ctx)?;

    if ctx.json {
        let mut report = serde_json::json!({
            "command": "keygen",
            "ok": true,
            "cliSchemaVersion": 1,
            "alg": { "KEM": "ML-KEM-1024" },
            "publicKeyPath": public_key_path,
            "privateKeyPath": private_key_path,
            "publicKeyDigestHex": sha3_512_hex(&public_key),
            "privateKeyDigestHex": sha3_512_hex(&private_key),
            "publicKeyLength": ML_KEM_1024_PUBLIC_KEY_SIZE,
            "privateKeyLength": ML_KEM_1024_SECRET_KEY_SIZE,
            "seed": { "source": "secure-random" }
        });
        if args.print_public {
            report["publicKeyBase64"] = Value::String(BASE64_STANDARD.encode(&public_key));
        }
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else if !ctx.quiet {
        println!("Generated ML-KEM-1024 keypair.");
        println!("Public key: {}", public_key_path.display());
        println!("Private key: {}", private_key_path.display());
        if args.print_public {
            println!("{}", BASE64_STANDARD.encode(&public_key));
        }
    }
    Ok(())
}

pub(super) fn run_signer_keygen(args: SignerKeygenArgs, ctx: CliContext) -> Result<()> {
    let suite = PqSignatureSuite::from(args.suite);
    let suite_info = get_signature_suite_info(suite.canonical_name())?;
    let (public_key_path, secret_key_path) = signer_key_output_paths(&args.out)?;
    let output_paths = [public_key_path.clone(), secret_key_path.clone()];

    prepare_output_parent_dirs(&output_paths, ctx)?;
    preflight_outputs(&output_paths, args.force, ctx)?;

    let keypair = generate_signing_keypair(suite)?;
    let (_, public_key, secret_key) = keypair.into_parts();
    let public_key_file = pack_public_key_file(suite, &public_key)?;
    let secret_key_file = Zeroizing::new(pack_secret_key_file(suite, secret_key.as_slice())?);
    let signer_fingerprint_hex = to_hex(&sha3_256(&public_key));
    let public_key_digest_hex = sha3_512_hex(&public_key);

    write_file_checked(&public_key_path, &public_key_file, args.force, ctx).with_context(|| {
        format!(
            "failed to write public signing key {}; secret signing key was not written",
            public_key_path.display()
        )
    })?;
    write_secret_file_checked(
        &secret_key_path,
        secret_key_file.as_slice(),
        args.force,
        ctx,
    )
    .with_context(|| {
        format!(
            "public signing key was written to {}; failed to write secret signing key {}",
            public_key_path.display(),
            secret_key_path.display()
        )
    })?;

    if ctx.json {
        let report = serde_json::json!({
            "command": "signer-keygen",
            "ok": true,
            "cliSchemaVersion": 1,
            "suite": suite_info.canonical,
            "suiteDisplayName": suite_info.display_name,
            "signatureFamily": suite_info.family,
            "strongPq": suite_info.strong_pq,
            "publicKeyType": suite_info.public_key_type,
            "publicKeyPath": public_key_path,
            "secretKeyPath": secret_key_path,
            "signerFingerprintAlg": "SHA3-256",
            "signerFingerprintHex": signer_fingerprint_hex,
            "publicKeyDigestAlg": "SHA3-512",
            "publicKeyDigestHex": public_key_digest_hex,
            "publicKeyLength": suite.public_key_len(),
            "publicKeyFileLength": public_key_file.len()
        });
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else if !ctx.quiet {
        println!("Generated PQ signing keypair.");
        println!("Suite: {}", suite_info.display_name);
        println!(
            "Strong PQ: {}",
            if suite_info.strong_pq { "yes" } else { "no" }
        );
        println!("Signer fingerprint (SHA3-256): {signer_fingerprint_hex}");
        println!("Public key: {}", public_key_path.display());
        println!("Secret key: {}", secret_key_path.display());
    }
    Ok(())
}
