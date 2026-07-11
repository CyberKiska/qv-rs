use super::super::*;

pub(super) fn run_selftest(args: SelftestArgs, ctx: CliContext) -> Result<()> {
    let filter = args.filter.unwrap_or_default().trim().to_ascii_lowercase();
    let include_crypto =
        filter.is_empty() || filter == "crypto" || "ml-kem-keygen".contains(&filter);
    let mut checks = Vec::new();
    if include_crypto {
        let (public_key, private_key) = generate_key_pair(None)?;
        let private_key = Zeroizing::new(private_key);
        validate_public_key(&public_key)?;
        validate_secret_key(&private_key)?;
        checks.push(serde_json::json!({ "name": "ml-kem-keygen", "ok": true }));
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
