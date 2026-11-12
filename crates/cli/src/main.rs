//! Command-line entry point.
use std::io::Write;
fn main() {
    let output = sigis_cli::run(&std::env::args().skip(1).collect::<Vec<_>>());
    let _ = std::io::stdout().write_all(output.stdout.as_bytes());
    let _ = std::io::stderr().write_all(output.stderr.as_bytes());
    std::process::exit(output.code);
}
