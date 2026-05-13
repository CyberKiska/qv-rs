#[cfg(feature = "legacy-mvp")]
mod legacy_main;

#[cfg(feature = "legacy-mvp")]
fn main() -> anyhow::Result<()> {
    legacy_main::main()
}

#[cfg(not(feature = "legacy-mvp"))]
fn main() {
    eprintln!(
        "qvault-cli successor migration build: predecessor manifest-v2 / QVqcont-6 CLI commands are disabled. Rebuild with --features legacy-mvp for migration-only compatibility."
    );
    std::process::exit(2);
}
