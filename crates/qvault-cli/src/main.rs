mod cli;

fn main() {
    if let Err(error) = cli::main() {
        cli::emit_error(&error);
        std::process::exit(cli::exit_code(&error));
    }
}
