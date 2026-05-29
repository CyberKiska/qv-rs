use super::super::*;

pub(super) fn run_inspect(args: InspectArgs, ctx: CliContext) -> Result<()> {
    let bytes = read_file_checked(&args.artifact_file, ctx)?;
    let inspected = inspect_artifact(&args.artifact_file, &bytes)?;
    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&inspected)?);
    } else if !ctx.quiet {
        println!("Artifact: {}", args.artifact_file.display());
        println!(
            "Type: {}",
            inspected["artifactType"].as_str().unwrap_or("unknown")
        );
        println!("Digest: {}", inspected["digestHex"].as_str().unwrap_or(""));
        if let Some(text) = inspected.get("canonicalJsonText").and_then(Value::as_str) {
            println!("{text}");
        }
    }
    Ok(())
}

pub(super) fn run_canonicalize(args: CanonicalizeArgs, ctx: CliContext) -> Result<()> {
    let bytes = read_file_checked(&args.artifact_file, ctx)?;
    let canonical = canonicalize_artifact(&bytes)?;
    if ctx.json {
        let report = serde_json::json!({
            "command": "canonicalize",
            "ok": true,
            "cliSchemaVersion": 1,
            "file": args.artifact_file,
            "artifactType": canonical.artifact_type,
            "artifactVersion": canonical.artifact_version,
            "digestAlg": "SHA3-512",
            "digestHex": sha3_512_hex(&canonical.bytes),
            "canonicalJson": canonical.value,
            "canonicalJsonText": canonical.text
        });
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        io::stdout().write_all(&canonical.bytes)?;
    }
    Ok(())
}
