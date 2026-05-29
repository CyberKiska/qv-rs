use anyhow::Result;

use super::{CliContext, Command};

mod artifacts;
mod attach;
mod encryption;
mod keys;
mod reshare;
mod restore;
mod signing;
mod split;
mod utility;
mod verify;

pub(super) fn run(command: Command, ctx: CliContext) -> Result<()> {
    match command {
        Command::Keygen(args) => keys::run_keygen(args, ctx),
        Command::SignerKeygen(args) => keys::run_signer_keygen(args, ctx),
        Command::Sign(args) => signing::run_sign(args, ctx),
        Command::SigVerify(args) => signing::run_sig_verify(args, ctx),
        Command::Encrypt(args) => encryption::run_encrypt(args, ctx),
        Command::Decrypt(args) => encryption::run_decrypt(args, ctx),
        Command::Split(args) => split::run_split(args, ctx),
        Command::Attach(args) => attach::run_attach(args, ctx),
        Command::Reshare(args) => reshare::run_reshare(args, ctx),
        Command::Inspect(args) => artifacts::run_inspect(args, ctx),
        Command::Canonicalize(args) => artifacts::run_canonicalize(args, ctx),
        Command::Verify(args) => verify::run_verify(args, ctx),
        Command::Restore(args) => restore::run_restore(args, ctx),
        Command::Selftest(args) => utility::run_selftest(args, ctx),
        Command::Version(args) => utility::run_version(args, ctx),
    }
}
