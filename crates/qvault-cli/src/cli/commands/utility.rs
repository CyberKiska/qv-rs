use super::super::*;

fn selftest_selected(filter: &str, name: &str) -> bool {
    filter.is_empty() || filter == "crypto" || name.contains(filter)
}

pub(super) fn run_selftest(args: SelftestArgs, ctx: CliContext) -> Result<()> {
    let filter = args.filter.unwrap_or_default().trim().to_ascii_lowercase();
    let mut checks = Vec::new();

    let sha3_name = "sha3-256-kat";
    if selftest_selected(&filter, sha3_name) {
        let actual = to_hex(&sha3_256(b"abc"));
        let expected = "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532";
        if actual != expected {
            bail!("{sha3_name} failed");
        }
        checks.push(serde_json::json!({ "name": sha3_name, "ok": true }));
    }

    let kmac_name = "kmac256-kat";
    if selftest_selected(&filter, kmac_name) {
        let key = (0x40u8..=0x5f).collect::<Vec<_>>();
        let output = qvault_core::kdf::kmac256(
            &key,
            &[0x00, 0x01, 0x02, 0x03],
            64,
            "My Tagged Application",
        )?;
        let expected = concat!(
            "20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7",
            "f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd"
        );
        if to_hex(&output) != expected {
            bail!("{kmac_name} failed");
        }
        checks.push(serde_json::json!({ "name": kmac_name, "ok": true }));
    }

    let aes_name = "aes-256-gcm-kat";
    if selftest_selected(&filter, aes_name) {
        let key = [0u8; 32];
        let iv = [0u8; 12];
        let plaintext = [0u8; 16];
        let ciphertext = qvault_core::aead::encrypt_chunk(&key, &plaintext, &iv, &[])?;
        let expected = concat!(
            "cea7403d4d606b6e074ec5d3baf39d18",
            "d0d1c8a799996bf0265b98b5d48ab919"
        );
        if to_hex(&ciphertext) != expected
            || qvault_core::aead::decrypt_chunk(&key, &ciphertext, &iv, &[])? != plaintext
        {
            bail!("{aes_name} failed");
        }
        checks.push(serde_json::json!({ "name": aes_name, "ok": true }));
    }

    let ml_kem_name = "ml-kem-keygen-encaps-decaps";
    if selftest_selected(&filter, ml_kem_name) {
        let (public_key, private_key) = generate_key_pair(Some([0x11; 64]))?;
        let private_key = Zeroizing::new(private_key);
        validate_public_key(&public_key)?;
        validate_secret_key(&private_key)?;
        let (ciphertext, encapsulated_secret) =
            qvault_core::mlkem::encapsulate(&public_key, Some([0x22; 32]))?;
        let encapsulated_secret = Zeroizing::new(encapsulated_secret);
        let decapsulated_secret =
            Zeroizing::new(qvault_core::mlkem::decapsulate(&ciphertext, &private_key)?);
        if encapsulated_secret.as_slice() != decapsulated_secret.as_slice() {
            bail!("{ml_kem_name} failed");
        }
        checks.push(serde_json::json!({ "name": ml_kem_name, "ok": true }));
    }

    let ml_dsa_name = "ml-dsa-44-sign-verify";
    if selftest_selected(&filter, ml_dsa_name) {
        let message = b"qvault-cli runtime selftest";
        let keypair = generate_signing_keypair(PqSignatureSuite::MlDsa44)?;
        let signature = create_detached_qsig(DetachedSignOptions::new(
            PqSignatureSuite::MlDsa44,
            keypair.secret_key_bytes(),
            message,
        ))?;
        let public_key_file =
            pack_public_key_file(PqSignatureSuite::MlDsa44, keypair.public_key_bytes())?;
        let verified = verify_qsig_against_bytes(
            message,
            &signature.qsig_bytes,
            None,
            Some(&public_key_file),
        )?;
        if !verified.ok || !verified.user_pinned || verified.self_signed {
            bail!("{ml_dsa_name} failed");
        }
        checks.push(serde_json::json!({ "name": ml_dsa_name, "ok": true }));
    }
    if checks.is_empty() {
        bail!("selftest --filter must match at least one check: {filter}");
    }
    if ctx.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "command": "selftest",
                "ok": true,
                "cliSchemaVersion": 1,
                "checks": checks
            }))?
        );
    } else if !ctx.quiet {
        println!("Selftest passed.");
    }
    Ok(())
}

pub(super) fn run_version(_args: VersionArgs, ctx: CliContext) -> Result<()> {
    if ctx.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "command": "version",
                "ok": true,
                "cliSchemaVersion": 1,
                "name": "qvault-cli",
                "version": env!("CARGO_PKG_VERSION"),
                "format": { "qcont": "QVqcont-7", "lifecycleBundle": "QV-Lifecycle-Bundle/v1" }
            }))?
        );
    } else if !ctx.quiet {
        println!("qvault-cli {}", env!("CARGO_PKG_VERSION"));
    }
    Ok(())
}
